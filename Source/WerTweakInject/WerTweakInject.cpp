/****************************************************************************
 *
 *            WerTweak
 *
 *            Copyright (c) 2020 Tim De Baets
 *
 ****************************************************************************
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * This Source Code Form is "Incompatible With Secondary Licenses", as
 * defined by the Mozilla Public License, v. 2.0.
 *
 ****************************************************************************
 *
 * Main implementation of the WerTweak injector application
 *
 ****************************************************************************/

#include "framework.h"

#include <Processes.h>
#include <Wow64Utils.h>

#include "..\WerTweak\ProjectUtils.h"

// TODO: add memleak checks
 
#define OPCODE_INT3         ((BYTE)0xCC)
#define OPCODE_REXW_PREFIX  ((BYTE)0x48)
#define OPCODE_SUB_ESP      ((WORD)0xEC83) // reverse byte order due to endianness
#define OPCODE_MOV_ECX      ((BYTE)0xB9)
#define OPCODE_MOV_EAX      ((BYTE)0xB8)
#define OPCODE_CALL_EAX     ((WORD)0xD0FF) // reverse byte order due to endianness
#define OPCODE_PUSH         ((BYTE)0x68)

// Use this to be able to attach a 'real' debugger to the child process
//#define SUSPEND_CHILD_PROCESS

#if defined(_WIN64)

#define CONTEXT_IP(pContext) (pContext)->Rip

// Native debugging when not a Wow64 process
#define IS_NATIVE_DEBUGGEE_PROCESS(bIsWow64Process) \
    (!bIsWow64Process)

#elif defined(_WIN32)

#define CONTEXT_IP(pContext) (pContext)->Eip

// Native debugging when on 32-bit Windows *or* a Wow64 process
#define IS_NATIVE_DEBUGGEE_PROCESS(bIsWow64Process) \
    (!g_bIs64BitWindows || bIsWow64Process)

#else
#error "Unsupported architecture"
#endif

typedef struct tProcInfo
{
    bool                        bIs32Bit;
    bool                        bIsNative; // false when we're 64-bit and debugging a WOW64 process
    bool                        bInjected;
    bool                        bFirstBPHit;
    CREATE_PROCESS_DEBUG_INFO   createInfo;
    BYTE                        byOriginalEntryPointOpcode;
    CONTEXT                     origThreadContext;      // used when bIsNative == true
    WOW64_CONTEXT               origThreadWow64Context; // used when bIsNative == false
    PVOID                       pStubInTarget;
    PVOID                       pStubInTargetBP;
} tProcInfo;

tProcInfo   g_procInfo              = {};
FARPROC     g_pNativeLoadLibraryW   = NULL;
FARPROC     g_pWow64LoadLibraryW    = NULL;
bool        g_bIs64BitWindows       = false;

#pragma pack(push, 1)
typedef struct tLoadLibraryStub32
{
    BYTE    instr_PUSH;
    DWORD   operand_PUSH_value;

    BYTE    instr_MOV_EAX;
    DWORD   operand_MOV_EAX;

    WORD    instr_CALL_EAX;

    BYTE    instr_INT_3;

    WCHAR   data_DllName[512];
} tLoadLibraryStub32;

typedef struct tLoadLibraryStub64
{
    BYTE    prefix_SUB_RSP;
    WORD    instr_SUB_RSP;
    BYTE    operand_SUB_RSP;

    BYTE    prefix_MOV_RCX;
    BYTE    instr_MOV_RCX;
    PVOID64 operand_MOV_RCX;

    BYTE    prefix_MOV_RAX;
    BYTE    instr_MOV_RAX;
    PVOID64 operand_MOV_RAX;
    
    WORD    instr_CALL_RAX;

    BYTE    instr_INT_3;

    WCHAR   data_DllName[512];
} tLoadLibraryStub64;
#pragma pack(pop)

bool InitLoadLibraryStub32(tLoadLibraryStub32  *pStub,              /* OUT */
                           PVOID                pStubInTarget,
                           const WCHAR         *dllName,
                           FARPROC              pLoadLibraryAddr,
                           PVOID               *ppStubInTargetBP    /* OUT */)
{
    if (!pStub || !pStubInTarget || !dllName || !pLoadLibraryAddr || !ppStubInTargetBP)
        return false;

    if (HIDWORD((DWORD64)pStubInTarget) != 0)
    {
        DbgOut("Upper 32 bits of stub address in target process are nonzero (0x%p)", pStubInTarget);
        return false;
    }

    if (HIDWORD((DWORD64)pLoadLibraryAddr) != 0)
    {
        DbgOut("Upper 32 bits of LoadLibraryW address are nonzero (0x%p)", pLoadLibraryAddr);
        return false;
    }

    pStub->instr_PUSH           = OPCODE_PUSH;
    pStub->operand_PUSH_value   = LODWORD((DWORD64)pStubInTarget) +
        offsetof(tLoadLibraryStub32, data_DllName);
    pStub->instr_MOV_EAX        = OPCODE_MOV_EAX;
    pStub->operand_MOV_EAX      = LODWORD((DWORD64)pLoadLibraryAddr);
    pStub->instr_CALL_EAX       = OPCODE_CALL_EAX;
    pStub->instr_INT_3          = OPCODE_INT3;

    if (!SUCCEEDED(StringCchCopyW(pStub->data_DllName, ARRAYSIZE(pStub->data_DllName),
                                  dllName)))
    {
        return false;
    }

    *ppStubInTargetBP = (PBYTE)pStubInTarget + offsetof(tLoadLibraryStub32, instr_INT_3);

    return true;
}

bool InitLoadLibraryStub64(tLoadLibraryStub64  *pStub,              /* OUT */
                           PVOID                pStubInTarget,
                           const WCHAR         *dllName,
                           FARPROC              pLoadLibraryAddr,
                           PVOID               *ppStubInTargetBP    /* OUT */)
{
    if (!pStub || !pStubInTarget || !dllName || !pLoadLibraryAddr || !ppStubInTargetBP)
        return false;

    pStub->prefix_SUB_RSP   = OPCODE_REXW_PREFIX;
    pStub->instr_SUB_RSP    = OPCODE_SUB_ESP;
    pStub->operand_SUB_RSP  = 0x8; // TODO: allocate more than 8 for home space?
    pStub->prefix_MOV_RCX   = OPCODE_REXW_PREFIX;
    pStub->instr_MOV_RCX    = OPCODE_MOV_ECX;
    pStub->operand_MOV_RCX  = (PBYTE)pStubInTarget +
        offsetof(tLoadLibraryStub64, data_DllName);
    pStub->prefix_MOV_RAX   = OPCODE_REXW_PREFIX;
    pStub->instr_MOV_RAX    = OPCODE_MOV_EAX;
    pStub->operand_MOV_RAX  = pLoadLibraryAddr;
    pStub->instr_CALL_RAX   = OPCODE_CALL_EAX;
    pStub->instr_INT_3      = OPCODE_INT3;

    if (!SUCCEEDED(StringCchCopyW(pStub->data_DllName, ARRAYSIZE(pStub->data_DllName),
                                  dllName)))
    {
        return false;
    }

    *ppStubInTargetBP = (PBYTE)pStubInTarget + offsetof(tLoadLibraryStub64, instr_INT_3);

    return true;
}

static const LPCWSTR g_pszWerTweakDllName32 = L"WerTweak.dll";
static const LPCWSTR g_pszWerTweakDllName64 = L"WerTweak64.dll";

wstring g_strDllNameToInject32;
wstring g_strDllNameToInject64;

bool GetDllPathToInject(LPCWSTR pszDllName, wstring &refDllPath)
{
    wstring         exeFileName = GetModuleName(NULL);
    wostringstream  oss;

    PathRemoveFileSpec(&exeFileName[0]);
    exeFileName.resize(lstrlenW(exeFileName.c_str()));

    oss << exeFileName << L"\\" << pszDllName;

    refDllPath = oss.str();

    // TODO: remove
    DbgOut("DLL filename: %s", refDllPath.c_str());

    return PathFileExists(refDllPath.c_str());
}

bool GetNativeLoadLibraryAddress()
{
    HMODULE hKernel32 = GetModuleHandleA(g_szKernel32);

    if (!hKernel32)
        return false;

    /*
     * Get the address of the native LoadLibraryW function in kernel32.dll. This address can only
     * be used when our architecture matches the architecture of the debuggee. In the other case
     * (64-bit debugger debugging a Wow64 process), we need another way to get the correct
     * LoadLibraryW address, see the Wow64GetKnownDllProcAddress() call in InjectCode().
     */
    g_pNativeLoadLibraryW = GetProcAddress(hKernel32, "LoadLibraryW");

    return (g_pNativeLoadLibraryW != NULL);
}

bool ReadTargetMemory(HANDLE hProc, PVOID pAddress, PVOID pBuf, SIZE_T bufSize)
{
    SIZE_T cbRead = 0;

    return ReadProcessMemory(hProc, pAddress, pBuf, bufSize, &cbRead) && (cbRead == bufSize);
}

bool ReadProcessString(HANDLE   hProc,
                       bool     bUnicode,
                       PVOID    pAddress,
                       DWORD    dwLength,
                       wstring &refString)
{
    string  ansiString;
    PVOID   pBuf    = NULL;
    SIZE_T  bufSize = 0;

    refString.clear();

    if (!pAddress || dwLength == 0)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return false;
    }

    if (bUnicode)
    {
        refString.resize(dwLength);
        pBuf    = &refString[0];
        bufSize = refString.size() * sizeof(refString[0]);
    }
    else
    {
        ansiString.resize(dwLength);
        pBuf    = &ansiString[0];
        bufSize = ansiString.size() * sizeof(ansiString[0]);
    }

    if (!ReadTargetMemory(hProc, pAddress, pBuf, bufSize))
        return false;

    if (!bUnicode)
    {
        CA2W ca2w(ansiString.c_str());
        refString = ca2w;
    }

    return true;
}

bool WriteTargetMemory(HANDLE hProc, PVOID pAddress, PVOID pBuf, SIZE_T bufSize)
{
    SIZE_T cbWritten = 0;

    return WriteProcessMemory(hProc, pAddress, pBuf, bufSize, &cbWritten) && (cbWritten == bufSize);
}

bool WriteTargetByte(HANDLE hProc, PVOID pAddress, BYTE byte)
{
    return WriteTargetMemory(hProc, pAddress, &byte, sizeof(byte));
}

bool SetEntryPointBP(tProcInfo *pProcInfo)
{
    if (!ReadTargetMemory(pProcInfo->createInfo.hProcess,
                          pProcInfo->createInfo.lpStartAddress,
                          &pProcInfo->byOriginalEntryPointOpcode,
                          sizeof(pProcInfo->byOriginalEntryPointOpcode)))
    {
        DbgOut("Failed to read original entry-point opcode from target process (%u)", GetLastError());
        return false;
    }

    if (!WriteTargetByte(pProcInfo->createInfo.hProcess,
                         pProcInfo->createInfo.lpStartAddress,
                         OPCODE_INT3))
    {
        DbgOut("Failed to write INT3 entry-point opcode to target process (%u)", GetLastError());
        return false;
    }

    return true;
}

bool RemoveEntryPointBP(tProcInfo *pProcInfo)
{
    return WriteTargetMemory(pProcInfo->createInfo.hProcess,
                             pProcInfo->createInfo.lpStartAddress,
                             &pProcInfo->byOriginalEntryPointOpcode,
                             sizeof(pProcInfo->byOriginalEntryPointOpcode));
}

bool SaveEntryPointContext(tProcInfo *pProcInfo)
{
    if (pProcInfo->bIsNative)
    {
        CONTEXT *pContext = &pProcInfo->origThreadContext;

        pContext->ContextFlags = CONTEXT_FULL;

        if (!GetThreadContext(pProcInfo->createInfo.hThread, pContext))
        {
            DbgOut("GetThreadContext failed (%u)", GetLastError());
            return false;
        }

        // The EIP/RIP in the context structure points past the BP, so decrement EIP/RIP to point
        // at the original instruction.
        CONTEXT_IP(pContext) -= sizeof(OPCODE_INT3);
    }
    else
    {
        WOW64_CONTEXT *pContext = &pProcInfo->origThreadWow64Context;

        pContext->ContextFlags = CONTEXT_FULL;

        if (!Wow64GetThreadContext(pProcInfo->createInfo.hThread, pContext))
        {
            DbgOut("Wow64GetThreadContext failed (%u)", GetLastError());
            return false;
        }

        // Same comment as above
        pContext->Eip -= sizeof(OPCODE_INT3);
    }

    return true;
}

bool RestoreEntryPointContext(tProcInfo *pProcInfo)
{
    // Set the registers back to what they were before we redirected them to the LoadLibrary stub

    if (pProcInfo->bIsNative)
    {
        if (!SetThreadContext(pProcInfo->createInfo.hThread,
                              &pProcInfo->origThreadContext))
        {
            DbgOut("SetThreadContext failed (%u)", GetLastError());
            return false;
        }
    }
    else
    {
        if (!Wow64SetThreadContext(pProcInfo->createInfo.hThread,
                                   &pProcInfo->origThreadWow64Context))
        {
            DbgOut("Wow64SetThreadContext failed (%u)", GetLastError());
            return false;
        }
    }

    return true;
}

bool InjectCode(tProcInfo *pProcInfo)
{
    tLoadLibraryStub32  stub32              = {};
    tLoadLibraryStub64  stub64              = {};
    size_t              stubSize            = 0;
    PVOID               pStub               = NULL;
    PVOID               pStubInTarget       = NULL;
    PVOID               pStubInTargetBP     = NULL;
    CONTEXT             stubContext         = pProcInfo->origThreadContext;
    WOW64_CONTEXT       stubWow64Context    = pProcInfo->origThreadWow64Context;
    bool                bResult             = false;

    if (pProcInfo->bIs32Bit)
    {
        pStub       = &stub32;
        stubSize    = sizeof(stub32);
    }
    else
    {
        pStub       = &stub64;
        stubSize    = sizeof(stub64);
    }

    // Locate where the stub will be in the target process
    pStubInTarget = VirtualAllocEx(pProcInfo->createInfo.hProcess,
                                   NULL,
                                   stubSize,
                                   MEM_COMMIT,
                                   PAGE_EXECUTE_READWRITE);
    if (!pStubInTarget)
    {
        DbgOut("VirtualAllocEx failed (%u)", GetLastError());
        goto exit;
    }

    // Initialize the stub
    if (pProcInfo->bIs32Bit)
    {
        if (!InitLoadLibraryStub32(&stub32,
                                   pStubInTarget,
                                   g_strDllNameToInject32.c_str(),
                                   pProcInfo->bIsNative ? g_pNativeLoadLibraryW :
                                                          g_pWow64LoadLibraryW,
                                   &pStubInTargetBP))
        {
            DbgOut("Failed to initialize 32-bit inject code");
            goto exit;
        }
    }
    else
    {
        if (!InitLoadLibraryStub64(&stub64,
                                   pStubInTarget,
                                   g_strDllNameToInject64.c_str(),
                                   g_pNativeLoadLibraryW,
                                   &pStubInTargetBP))
        {
            DbgOut("Failed to initialize 64-bit inject code");
            goto exit;
        }
    }

    // Copy the stub into the target process
    if (!WriteTargetMemory(pProcInfo->createInfo.hProcess, pStubInTarget, pStub, stubSize))
    {
        DbgOut("Failed to write inject code to target process (%u)", GetLastError());
        goto exit;
    }

    // Change the EIP/RIP register in the target thread to point at the stub we just copied in
    if (pProcInfo->bIsNative)
    {
        CONTEXT_IP(&stubContext) = (DWORD64)pStubInTarget;

        if (!SetThreadContext(pProcInfo->createInfo.hThread, &stubContext))
        {
            DbgOut("Failed to modify thread context to point to injected code (%u)",
                   GetLastError());
            goto exit;
        }
    }
    else
    {
        if (HIDWORD((DWORD64)pStubInTarget) != 0)
        {
            DbgOut("Upper 32 bits of stub address in target process are nonzero (0x%p)",
                   pStubInTarget);
            goto exit;
        }

        stubWow64Context.Eip = LODWORD((DWORD64)pStubInTarget);

        if (!Wow64SetThreadContext(pProcInfo->createInfo.hThread, &stubWow64Context))
        {
            DbgOut("Failed to modify Wow64 thread context to point to injected code (%u)",
                   GetLastError());
            goto exit;
        }
    }

    pProcInfo->pStubInTarget    = pStubInTarget;
    pProcInfo->pStubInTargetBP  = pStubInTargetBP;
    pStubInTarget = NULL; // will be freed later TODO

    bResult = true;

exit:

    if (pStubInTarget)
    {
        VirtualFreeEx(pProcInfo->createInfo.hProcess, pStubInTarget, 0, MEM_RELEASE);
        pStubInTarget = NULL;
    }

    return bResult;
}

bool OnProcessCreate(tProcInfo *pProcInfo, DEBUG_EVENT *pEvt)
{
    pProcInfo->createInfo = pEvt->u.CreateProcessInfo;

    if (g_bIs64BitWindows)
    {
        BOOL bIsWow64 = FALSE;

        IsWow64Process(pEvt->u.CreateProcessInfo.hProcess, &bIsWow64);

        pProcInfo->bIs32Bit     = bIsWow64;
        pProcInfo->bIsNative    = IS_NATIVE_DEBUGGEE_PROCESS(bIsWow64);

        /* 
         * Prevent debugging a 64-bit process by a 32-bit debugger. This should be already blocked
         * by CreateProcess (ERROR_NOT_SUPPORTED), but checking here anyway just to be sure.
         */
#if !defined(_WIN64)
        if (!pProcInfo->bIs32Bit)
        {
            DbgOut("Cannot debug a 64-bit process with a 32-bit debugger");
            return false;
        }
#endif

        if (!pProcInfo->bIsNative && !g_pWow64LoadLibraryW)
        {
            g_pWow64LoadLibraryW = Wow64GetKnownDllProcAddress(g_szKernel32, "LoadLibraryW");
            DbgOut("g_pWow64LoadLibraryW: 0x%p", g_pWow64LoadLibraryW); // TODO: remove
            if (!g_pWow64LoadLibraryW)
            {
                DbgOut("Failed to get Wow64 LoadLibraryW address");
                return false;
            }
        }
    }
    else
    {
        // 32-bit Windows, no other possibility than 32-bit process/native debugging
        pProcInfo->bIs32Bit     = true;
        pProcInfo->bIsNative    = true;
    }

    DbgOut("Debugging process with ID %u (%hs, %hs bitness)",
           pEvt->dwProcessId,
           pProcInfo->bIs32Bit ? "32-bit" : "64-bit",
           pProcInfo->bIsNative ? "native" : "non-native");

    return true;
}

void OnProcessExit(DEBUG_EVENT* pEvt)
{
    DbgOut("Process with ID %u exited with code 0x%x",
           pEvt->dwProcessId,
           pEvt->u.ExitProcess.dwExitCode);
}

void OnProcessException(tProcInfo *pProcInfo, DEBUG_EVENT *pEvt)
{
    // We're only interested in breakpoint exceptions, but need to be careful which type to handle
    // depending on native/non-native bitness
    if (pProcInfo->bIsNative)
    {
        if (pEvt->u.Exception.ExceptionRecord.ExceptionCode != EXCEPTION_BREAKPOINT)
            return;
    }
    else
    {
        if (pEvt->u.Exception.ExceptionRecord.ExceptionCode != STATUS_WX86_BREAKPOINT)
            return;
    }

    // TODO: bInjected is currently never set to true, fix this
    if (pProcInfo->bInjected)
        return;

    if (!pProcInfo->bFirstBPHit)
    {
        pProcInfo->bFirstBPHit = true;

        if (!SetEntryPointBP(pProcInfo))
        {
            DbgOut("Failed to initialize hook");
        }
    }
    else if (pEvt->u.Exception.ExceptionRecord.ExceptionAddress ==
                pProcInfo->createInfo.lpStartAddress)
    {
        DbgOut("Process entry point hit");

        if (!RemoveEntryPointBP(pProcInfo))
        {
            DbgOut("Failed to remove entry point breakpoint");
            return;
        }

        if (!SaveEntryPointContext(pProcInfo))
        {
            DbgOut("Failed to save entry point context");
            return;
        }

        if (!InjectCode(pProcInfo))
        {
            DbgOut("Failed to inject code");
            return;
        }

#if defined(SUSPEND_CHILD_PROCESS)
        SuspendThread(pProcInfo->createInfo.hThread);
#endif
    }
    else if (pEvt->u.Exception.ExceptionRecord.ExceptionAddress ==
                pProcInfo->pStubInTargetBP)
    {
        DbgOut("Stub breakpoint hit");

        // TODO: log handle of the loaded DLL (EAX/RAX)?

        if (!RestoreEntryPointContext(pProcInfo))
        {
            DbgOut("Failed to restore entry point context");
        }

        // TODO: free stub
    }
}

// TODO: remove?
void OnLoadDll(tProcInfo *pProcInfo, DEBUG_EVENT *pEvt)
{
    PVOID   pImageNameAddr = NULL;
    wstring strImageName;

    // TODO: test unicode
    if (pEvt->u.LoadDll.lpImageName)
    {
        if (!ReadTargetMemory(pProcInfo->createInfo.hProcess,
                              pEvt->u.LoadDll.lpImageName,
                              &pImageNameAddr, sizeof(pImageNameAddr)))
        {
            DbgOut("Failed to read DLL filename from target process (1) (%u)", GetLastError());
        }
        else if (!pImageNameAddr)
        {
            DbgOut("Failed to read DLL filename from target process (2)");
        }
        else if (!ReadProcessString(pProcInfo->createInfo.hProcess,
                                    pEvt->u.LoadDll.fUnicode,
                                    pImageNameAddr,
                                    MAX_PATH,
                                    strImageName))
        {
            DbgOut("Failed to read DLL filename from target process (3) (%u)", GetLastError());
        }
    }

    DbgOut("Load DLL: %ws @ 0x%p", strImageName.c_str(), pEvt->u.LoadDll.lpBaseOfDll);
}

void OnDebugString(tProcInfo *pProcInfo, DEBUG_EVENT *pEvt)
{
    wstring dbgString;

    // TODO: test unicode
    if (!ReadProcessString(pProcInfo->createInfo.hProcess,
                           pEvt->u.DebugString.fUnicode,
                           pEvt->u.DebugString.lpDebugStringData,
                           pEvt->u.DebugString.nDebugStringLength,
                           dbgString))
    {
        DbgOut("Failed to read debug string from target process (%u)", GetLastError());
        return;
    }

    DbgOut("Debug string: %ws", dbgString.c_str());
}

void MakeAllOurObjectHandlesInheritable()
{
    PPROCESS_HANDLE_SNAPSHOT_INFORMATION    pHandles = NULL;
    NTSTATUS                                status;

    status = PhEnumHandlesEx2(GetCurrentProcess(), &pHandles);
    if (!NT_SUCCESS(status))
    {
        DbgOut("PhEnumHandlesEx2 failed (%x)", status);
        return;
    }

    for (int i = 0; i < pHandles->NumberOfHandles; i++)
    {
        PROCESS_HANDLE_TABLE_ENTRY_INFO *pInfo = &pHandles->Handles[i];

        // TODO: only for specific object types? (check ObjectTypeIndex)
        // TODO: add generic macro for checking flag in bitmask
        if ((pInfo->HandleAttributes & OBJ_INHERIT) == 0)
        {
            if (!SetHandleInformation(pInfo->HandleValue, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT))
            {
                DbgOut("SetHandleInformation(0x%x) failed (%u)", pInfo->HandleValue, GetLastError());
            }
        }
    }

    delete[] pHandles;
}

int APIENTRY wWinMain(_In_ HINSTANCE        hInstance,
                      _In_opt_ HINSTANCE    hPrevInstance,
                      _In_ LPWSTR           lpCmdLine,
                      _In_ int              nCmdShow)
{
    UNREFERENCED_PARAMETER(hPrevInstance);

    STARTUPINFO         startupInfo = {};
    PROCESS_INFORMATION procInfo    = {};
    DEBUG_EVENT         dbgEvent    = {};
    SidWrapper          procSid;
    bool                bRunning    = true;

    startupInfo.cb = sizeof(startupInfo);

    ZeroMemory(&g_procInfo, sizeof(g_procInfo));
    g_procInfo.createInfo.hFile     = INVALID_HANDLE_VALUE;
    g_procInfo.createInfo.hProcess  = INVALID_HANDLE_VALUE;
    g_procInfo.createInfo.hThread   = INVALID_HANDLE_VALUE;

    g_bIs64BitWindows = Is64BitWindows();
    
    // TODO: remove
    DbgOut("%s", lpCmdLine);

    if (lpCmdLine[0] == '\0')
    {
        // TODO: print usage?
        return 1;
    }

    if (!GetProcessSid(GetCurrentProcessId(), GetCurrentProcess(), procSid))
    {
        DbgOut("Failed to get our process SID, exiting");
        return 2;
    }

    if (!GetNativeLoadLibraryAddress())
    {
        DbgOut("Failed to get native LoadLibrary address");
        return 3;
    }

    if (!GetDllPathToInject(g_pszWerTweakDllName32, g_strDllNameToInject32))
    {
        DbgOut("Failed to find 32-bit DLL file to inject");
        return 4;
    }

#if defined(_WIN64)
    if (!GetDllPathToInject(g_pszWerTweakDllName64, g_strDllNameToInject64))
    {
        DbgOut("Failed to find 64-bit DLL file to inject");
        return 5;
    }
#endif

    /*
     * When WerSvc launches WerFault.exe for a hung process, the service duplicates a few object
     * handles into the context of WerFault (in my testing, 2 file mapping handles and 5 event
     * handles). The duplicated handle values are then passed to WerFault via a named file mapping,
     * of which the name is passed to WerFault via the command line (example:
     * "/shared Global\8928ad8824614ac9aadef800e0ddd09f"). However, for duplicating these handles,
     * WerSvc uses DuplicateHandle() calls with the bInheritHandle parameter set to FALSE, so when
     * WerSvc actually launches WerTweak instead of WerFault, the duplicated handle values are only
     * valid in the context of the WerTweak child process and not in the WerFault grandchild process.
     * This causes WerFault to fail to properly handle the hung process and exit prematurely with an
     * exit code of 0x80070006 ("Invalid handle").
     * To fix this, we enumerate all object handles in the current process, check if they have the
     * 'inheritable' flag set, and if not, set the flag after all. This might seem like overkill, but
     * it's probably the only way to ensure that the duplicated handle values stay valid in
     * WerFault's context.
     */
    MakeAllOurObjectHandlesInheritable();

    // NOTE: bInheritHandles=TRUE is required for WerFault to function correctly! (and even more so
    // in the case of a hung process, see comment above)
    // TODO: disable debug heap (by setting _NO_DEBUG_HEAP environment variable)
    // TODO: use NtCreateUserProcess with IFEOSkipDebugger flag if WerFault.exe process runs as SYSTEM?
    if (!CreateProcess(NULL,
                       lpCmdLine,
                       NULL, NULL,
                       TRUE, /* bInheritHandles */
                       DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS,
                       NULL, NULL,
                       &startupInfo,
                       &procInfo))
    {
        DbgOut("CreateProcess failed (%u)", GetLastError());
        return 6;
    }

    CloseHandleSafe(&procInfo.hProcess);
    CloseHandleSafe(&procInfo.hThread);

    if (!DebugSetProcessKillOnExit(FALSE))
    {
        DbgOut("DebugSetProcessKillOnExit failed! (%u)", GetLastError());
    }

    /*
     * When a process crashes, Windows 10 starts two instances of WerFault.exe: one instance as a
     * SYSTEM process, and one instance as a regular user process. We're only interested in hooking
     * the user process, so exit if we're running as SYSTEM.
     */
    if (IsSystemSid((PSID)&procSid[0]))
    {
        DbgOut("Running as a SYSTEM process, exiting");
        return 0;
    }

    // For the regular process, using a debugger loop is required for WerFault to function correctly!
    while (bRunning)
    {
        bool bContinue = true; // TODO: just use 'continue' instead

        if (!WaitForDebugEvent(&dbgEvent, INFINITE))
            break;

        switch (dbgEvent.dwDebugEventCode)
        {
        case CREATE_PROCESS_DEBUG_EVENT:
            if (!OnProcessCreate(&g_procInfo, &dbgEvent))
                goto exit;
            break;
        case EXIT_PROCESS_DEBUG_EVENT:
            OnProcessExit(&dbgEvent);
            bRunning = false;
            break;
        case EXCEPTION_DEBUG_EVENT:
            OnProcessException(&g_procInfo, &dbgEvent);
            switch (dbgEvent.u.Exception.ExceptionRecord.ExceptionCode)
            {
            // A 64-bit debugger debugging a Wow64 process will see both types of breakpoint exceptions
            case EXCEPTION_BREAKPOINT:
#if defined(_WIN64)
            case STATUS_WX86_BREAKPOINT:
#endif
                DbgOut("Breakpoint");
                break;
            default:
                ContinueDebugEvent(dbgEvent.dwProcessId, dbgEvent.dwThreadId, DBG_EXCEPTION_NOT_HANDLED);
                bContinue = false;
                break;
            }
            break;
        case CREATE_THREAD_DEBUG_EVENT:
            CloseHandleSafe(&dbgEvent.u.CreateThread.hThread);
            break;
        case LOAD_DLL_DEBUG_EVENT:
            //OnLoadDll(&g_procInfo, &dbgEvent);
            CloseHandleSafe(&dbgEvent.u.LoadDll.hFile);
            break;
        case OUTPUT_DEBUG_STRING_EVENT:
            OnDebugString(&g_procInfo, &dbgEvent);
            break;
        }

        if (bContinue)
        {
            // Must use DBG_CONTINUE here, otherwise exceptions with OUTPUT_DEBUG_STRING_EVENT on NT!!!!
            if (!ContinueDebugEvent(dbgEvent.dwProcessId, dbgEvent.dwThreadId, DBG_CONTINUE))
                break;
        }
    }

exit:

    CloseHandleSafe(&g_procInfo.createInfo.hFile);
    CloseHandleSafe(&g_procInfo.createInfo.hProcess);
    CloseHandleSafe(&g_procInfo.createInfo.hThread);

    DbgOut("Done");

    // TODO: exit with same code as WerFault did?
    return 0;
}
