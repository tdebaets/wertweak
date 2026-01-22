/****************************************************************************
 *
 *            WerTweak
 *
 *            Copyright (c) 2025 Tim De Baets
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
 * Class for injecting the WerTweak DLL into the WerFault.exe process
 *
 ****************************************************************************/

#include "DLLInject.h"
#include "WerTweakInject.h"

bool GetDLLPathToInject(LPCWSTR pszDLLName, wstring &refDLLPath)
{
    wstring         exeFileName = GetModuleName(NULL);
    wostringstream  oss;

    PathRemoveFileSpec(&exeFileName[0]);
    exeFileName.resize(lstrlenW(exeFileName.c_str()));

    oss << exeFileName << L"\\" << pszDLLName;

    refDLLPath = oss.str();

    // TODO: remove
    DbgOut("DLL filename: %s", refDLLPath.c_str());

    return PathFileExists(refDLLPath.c_str());
}

CWERFaultDLLInjectInfo::CWERFaultDLLInjectInfo(WORD wImageFileMachine /* IMAGE_FILE_MACHINE_* */) :
    m_dwTranslateHpssSectionRVA(0),
    m_dwTranslateHpssSectionSize(0)
{
    switch (wImageFileMachine)
    {
    case IMAGE_FILE_MACHINE_I386:
        if (!RetrieveInfo(g_pszWerTweakDllName32))
        {
            throw CWERFaultDLLInjectError("Failed to retrieve 32-bit inject DLL file info");
        }
        break;

    case IMAGE_FILE_MACHINE_AMD64:
#if defined(_WIN64)
        if (!RetrieveInfo(g_pszWerTweakDllName64))
        {
            throw CWERFaultDLLInjectError("Failed to retrieve 64-bit inject DLL file info");
        }
#else
        // Ignore in 32-bit builds
#endif
        break;

    default:
        throw CWERFaultDLLInjectError(std::format("Unexpected IMAGE_FILE_MACHINE: {:#x}",
                                                  wImageFileMachine));
        break;
    }
}

bool CWERFaultDLLInjectInfo::RetrieveInfo(LPCWSTR pszDLLName)
{
    bool                    bResult         = false;
    HANDLE                  hFile;
    HANDLE                  hFileMapping;
    PVOID                   pBaseAddress    = NULL;
    PIMAGE_NT_HEADERS       pNtHeaders      = NULL;
    PIMAGE_SECTION_HEADER   pSectionHeaders = NULL;

    if (!GetDLLPathToInject(pszDLLName, m_strFilename))
    {
        DbgOut("Failed to find %s", pszDLLName);
        return false;
    }

    hFile = CreateFile(m_strFilename.c_str(),
                       GENERIC_READ,
                       FILE_SHARE_READ,
                       NULL,
                       OPEN_EXISTING,
                       0,
                       NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        DbgOut("Failed to open file (%u)", GetLastError());
        goto exit;
    }

    hFileMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hFileMapping)
    {
        DbgOut("CreateFileMapping() failed (%u)", GetLastError());
        goto exit;
    }

    pBaseAddress = MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);
    if (!pBaseAddress)
    {
        DbgOut("MapViewOfFile() failed (%u)", GetLastError());
        goto exit;
    }

    pNtHeaders = ImageNtHeader(pBaseAddress);
    if (!pNtHeaders)
    {
        DbgOut("ImageNtHeader() failed (%u)", GetLastError());
        goto exit;
    }

    pSectionHeaders = IMAGE_FIRST_SECTION(pNtHeaders);
    for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++)
    {
        if (_strnicmp((const char *)pSectionHeaders[i].Name,
                      TRANSLATE_HPSS_SEGMENT_NAME,
                      ARRAYSIZE(pSectionHeaders[i].Name)) == 0)
        {
            DbgOut("Translate HPSS Section RVA: 0x%x, Size: 0x%x",
                   pSectionHeaders[i].VirtualAddress,
                   pSectionHeaders[i].SizeOfRawData);

            m_dwTranslateHpssSectionRVA    = pSectionHeaders[i].VirtualAddress;
            m_dwTranslateHpssSectionSize   = pSectionHeaders[i].SizeOfRawData;

            bResult = true;
        }
    }

exit:

    if (pBaseAddress)
    {
        UnmapViewOfFile(pBaseAddress);
        pBaseAddress = NULL;
    }

    CloseHandleSafe(&hFileMapping);
    CloseHandleSafe(&hFile);

    return bResult;
}

CWERFaultDLLInject::CWERFaultDLLInject(const wstring   &strDLLFilename32,
                                       const wstring   &strDLLFilename64) :
    m_hProcess(INVALID_HANDLE_VALUE),
    m_pDLLInfo32(NULL),
    m_pDLLInfo64(NULL),
    m_dwExitCode(0),
    CProcessDLLInject(strDLLFilename32, strDLLFilename64)
{
    throw CWERFaultDLLInjectError("Default constructor should not be called");
}

CWERFaultDLLInject::CWERFaultDLLInject(HANDLE          *phProcess) :
    m_hProcess(*phProcess),
    m_dwExitCode(0),
    // The following appears to be the only way to force the CWERFaultDLLInjectInfo objects to be
    // created *before* CProcessDLLInject's constructor
    CProcessDLLInject((m_pDLLInfo32 = new CWERFaultDLLInjectInfo(IMAGE_FILE_MACHINE_I386),
                       m_pDLLInfo32->m_strFilename),
                      (m_pDLLInfo64 = new CWERFaultDLLInjectInfo(IMAGE_FILE_MACHINE_AMD64),
                       m_pDLLInfo64->m_strFilename))
{
    *phProcess = INVALID_HANDLE_VALUE; /* take ownership */

    /*
     * When WerSvc launches WerFault.exe for a hung process, the service first captures a process
     * snapshot (PssCaptureSnapshot) and then duplicates the resulting snapshot handle into the
     * context of WerFault by calling PssDuplicateSnapshot().
     * However, just like with the kernel object handles above, when WerSvc actually launches
     * WerTweak instead of WerFault, the duplicated snapshot handle value is only valid in the
     * context of the WerTweak child process and not in the WerFault grandchild process. Because
     * process snapshot handles are *not* kernel object handles, they are not covered by the
     * MakeAllOurObjectHandlesInheritable() call above. Process snapshot handles also cannot be
     * made inheritable, so we need a different approach here: we enumerate all process snapshot
     * handles in the current process and duplicate each handle into the context of WerFault by also
     * calling PssDuplicateSnapshot(). Because the value of the duplicated handle will be different
     * from the value of the original handle, we must also hook all process snapshot functions
     * called by WerFault that receive a snapshot handle, and translate the original handle to the
     * duplicated handle before the hooked function is effectively called.
     */
    DuplicateAllOurProcessSnapshotHandles(m_hProcess);
}

CWERFaultDLLInject::~CWERFaultDLLInject()
{
    CloseHandleSafe(&m_hProcess);

    delete m_pDLLInfo32;
    m_pDLLInfo32 = NULL;

    delete m_pDLLInfo64;
    m_pDLLInfo64 = NULL;
}

bool CWERFaultDLLInject::OnProcessCreate(DWORD                      dwProcessID,
                                         DWORD                      dwThreadID,
                                         CREATE_PROCESS_DEBUG_INFO *pInfo)
{
    DbgOut("Process created, PID: %u", dwProcessID);

    __super::OnProcessCreate(dwProcessID, dwThreadID, pInfo);

    return true;
}

void CWERFaultDLLInject::OnProcessExit(DWORD                        dwProcessID,
                                       EXIT_PROCESS_DEBUG_INFO     *pInfo)
{
    DbgOut("Process with ID %u exited with code 0x%x", dwProcessID, pInfo->dwExitCode);

    __super::OnProcessExit(dwProcessID, pInfo);

    m_dwExitCode = pInfo->dwExitCode;
}

void CWERFaultDLLInject::OnDbgOut(LPCWSTR wszFormat, va_list argList)
{
    PWCHAR wszMessage = NULL;

    if (FormatArgListAlloc(wszFormat, argList, &wszMessage) == 0)
        return;

    DbgOut("%s", wszMessage);

    FormatArgListFree(&wszMessage);
}

/*
 * Returns true if DbgOut() calls should be suppressed in order not to delay WerFault's execution
 * too much in hot code paths.
 */
bool ShouldSuppressDbgOutputOnException(PEXCEPTION_RECORD pExceptionRecord)
{
    if (pExceptionRecord->ExceptionCode == STATUS_TRANSLATE_PROCESS_SNAPSHOT_HANDLE &&
        pExceptionRecord->NumberParameters ==
            STATUS_TRANSLATE_PROCESS_SNAPSHOT_HANDLE_PARAM_MAX_PLUS1)
    {
        ULONG_PTR dwFlags =
            pExceptionRecord->ExceptionInformation[STATUS_TRANSLATE_PROCESS_SNAPSHOT_HANDLE_PARAM_FLAGS];

        return ((dwFlags & TRANSLATE_PROCESS_SNAPSHOT_HANDLE_FLAG_SUPPRESS_DBG_OUTPUT) != 0);
    }
    else
    {
        return false;
    }
}

void CWERFaultDLLInject::OnException2(const tProcInfo              *pProcInfo,
                                      DWORD                         dwThreadID,
                                      EXCEPTION_DEBUG_INFO         *pInfo,
                                      bool                         *pbExceptionHandled)
{
    bool                    bSuppressDbgOutput;
    CWERFaultDLLInjectInfo *pDLLInfo = NULL;
    
    if (pProcInfo->bIs32Bit)
    {
        pDLLInfo = m_pDLLInfo32;
    }
    else
    {
        pDLLInfo = m_pDLLInfo64;
    }

    bSuppressDbgOutput  = ShouldSuppressDbgOutputOnException(&pInfo->ExceptionRecord);

    *pbExceptionHandled = false;

    if (!bSuppressDbgOutput)
    {
        DbgOut("Exception 0x%x at address 0x%p",
               pInfo->ExceptionRecord.ExceptionCode,
               pInfo->ExceptionRecord.ExceptionAddress);
    }

    if (pInfo->ExceptionRecord.ExceptionCode == STATUS_TRANSLATE_PROCESS_SNAPSHOT_HANDLE &&
        pProcInfo->pInjectedDllBaseInTarget &&
        pDLLInfo->m_dwTranslateHpssSectionRVA &&
        pDLLInfo->m_dwTranslateHpssSectionSize)
    {
        DWORD_PTR dwpExceptionAddress =
            (DWORD_PTR)pInfo->ExceptionRecord.ExceptionAddress;
        DWORD_PTR dwpTranslateHpssSectionStart =
            (DWORD_PTR)pProcInfo->pInjectedDllBaseInTarget +
            pDLLInfo->m_dwTranslateHpssSectionRVA;
        DWORD_PTR dwpTranslateHpssSectionEnd = dwpTranslateHpssSectionStart +
            pDLLInfo->m_dwTranslateHpssSectionSize;

        if (dwpExceptionAddress >= dwpTranslateHpssSectionStart &&
            dwpExceptionAddress < dwpTranslateHpssSectionEnd)
        {
            HandleTranslateProcessSnapshotHandle(pProcInfo, &pInfo->ExceptionRecord);

            *pbExceptionHandled = true;
        }
        else
        {
            DbgOut("Exception STATUS_TRANSLATE_PROCESS_SNAPSHOT_HANDLE outside of expected code "
                   "section");
        }
    }
}

void CWERFaultDLLInject::OnDebugString2(const tProcInfo            *pProcInfo,
                                        DWORD                       dwThreadID,
                                        OUTPUT_DEBUG_STRING_INFO   *pInfo,
                                        LPCWSTR                     wszDebugString)
{
    DbgOut("Debug string: %ws", wszDebugString);
}

DWORD PssDuplicateSnapshotExceptionFilter(DWORD dwExceptionCode)
{
    DbgOut("Exception during PssDuplicateSnapshot: 0x%x", dwExceptionCode);

    switch (dwExceptionCode)
    {
    case EXCEPTION_INVALID_HANDLE:
    // EXCEPTION_ACCESS_VIOLATION can occur when handling a Wow64 crash and the 32-bit WerFault only
    // passes us the lower 32 bits of a 64-bit HPSS handle.
    case EXCEPTION_ACCESS_VIOLATION:
        return EXCEPTION_EXECUTE_HANDLER;
    default:
        // Unexpected exception
        return EXCEPTION_CONTINUE_SEARCH;
    }
}

bool TryPssDuplicateSnapshot(HPSS hSnapshot, HANDLE hTargetProcess, HPSS *phTargetSnapshot)
{
    DWORD dwResult;

    __try
    {
        dwResult = PssDuplicateSnapshot(GetCurrentProcess(),
                                        hSnapshot,
                                        hTargetProcess,
                                        phTargetSnapshot,
                                        PSS_DUPLICATE_NONE);
        if (dwResult == ERROR_SUCCESS)
        {
            DbgOut("PssDuplicateSnapshot succeeded: 0x%p", *phTargetSnapshot);
        }
        else
        {
            DbgOut("PssDuplicateSnapshot failed (%u)", dwResult);
            return false;
        }
    }
    __except (PssDuplicateSnapshotExceptionFilter(GetExceptionCode()))
    {
        return false;
    }

    return true;
}

void CWERFaultDLLInject::DuplicateAllOurProcessSnapshotHandles(HANDLE hTargetProcess)
{
    PBYTE                       pBaseAddr       = NULL;
    DWORD                       dwNumSnapshots  = 0;
    MEMORY_BASIC_INFORMATION    mbi;

    while (VirtualQuery(pBaseAddr, &mbi, sizeof(mbi)))
    {
        if (mbi.State == MEM_COMMIT && mbi.Protect == PAGE_READWRITE)
        {
            if (mbi.Type != MEM_PRIVATE)
                goto next_region;

            /* This should always pass, but check anyway to be sure */
            if (mbi.RegionSize < sizeof(PSSNT_SIGNATURE_PSSD_LE))
                goto next_region;

            if (*(PDWORD)mbi.BaseAddress == PSSNT_SIGNATURE_PSSD_LE)
            {
                HPSS    hSnapshot       = (HPSS)mbi.BaseAddress;
                HPSS    hTargetSnapshot = NULL;

                if (TryPssDuplicateSnapshot(hSnapshot, hTargetProcess, &hTargetSnapshot))
                {
                    m_processSnapshotMap.insert({hSnapshot, hTargetSnapshot});

                    dwNumSnapshots++;
                }
                else
                {
                    DbgOut("Failed to duplicate snapshot handle 0x%p", hSnapshot);
                }
            }
        }

next_region:

        pBaseAddr += mbi.RegionSize;
    }

    DbgOut("Duplicated %u process snapshot handles", dwNumSnapshots);
}

bool CWERFaultDLLInject::HandleTranslateProcessSnapshotHandle(const tProcInfo   *pProcInfo,
                                                              PEXCEPTION_RECORD  pExceptionRecord)
{
    bool        bSuppressDbgOutput  = ShouldSuppressDbgOutputOnException(pExceptionRecord);
    ULONG_PTR  *pulpParams          = pExceptionRecord->ExceptionInformation;
    PVOID       pSnapshotHandle     = NULL;
    HPSS        hSnapshot           = NULL;
    HPSS        hTargetSnapshot     = NULL;

    /*
     * When being launched for a 32-bit process, WerFault doesn't appear to require any translation
     * of process snapshot handles (both on 32-bit and 64-bit Windows), so we can just skip this
     * case.
     * Note for 64-bit Windows (non-native): if this would every be required after all, the
     * ReadTargetMemory()/WriteTargetMemory() calls will have to be modified to read/write a 32-bit
     * HPSS value instead of a 64-bit value.
     * Note for 32-bit Windows (native): this was already quickly tested and should just work as is.
     */
    if (pProcInfo->bIs32Bit)
    {
        DbgOut("Snapshot handle translation only needed/supported for 64-bit processes");
        return true;
    }

    if (pExceptionRecord->NumberParameters !=
            STATUS_TRANSLATE_PROCESS_SNAPSHOT_HANDLE_PARAM_MAX_PLUS1)
    {
        DbgOut("Unexpected number of exception parameters: %u", pExceptionRecord->NumberParameters);
        return false;
    }

    pSnapshotHandle = (PVOID)pulpParams[STATUS_TRANSLATE_PROCESS_SNAPSHOT_HANDLE_PARAM_PHANDLE];

    if (!bSuppressDbgOutput)
    {
        DbgOut("Snapshot handle address: 0x%p", pSnapshotHandle);
    }

    if (!pSnapshotHandle)
        return false;

    if (!ReadTargetMemory(pProcInfo->createInfo.hProcess,
                          pSnapshotHandle,
                          &hSnapshot, sizeof(hSnapshot)))
    {
        DbgOut("Failed to read snapshot handle (%u)", GetLastError());
        return false;
    }

    tProcessSnapshotMap::const_iterator iter = m_processSnapshotMap.find(hSnapshot);
    if (iter == m_processSnapshotMap.end())
    {
        DbgOut("Snapshot handle 0x%p not found in map", hSnapshot);
        return false;
    }

    hTargetSnapshot = iter->second;

    if (!bSuppressDbgOutput)
    {
        DbgOut("Snapshot handle: 0x%p -> 0x%p", hSnapshot, hTargetSnapshot);
    }

    if (!WriteTargetMemory(pProcInfo->createInfo.hProcess,
                           pSnapshotHandle,
                           &hTargetSnapshot,
                           sizeof(hTargetSnapshot)))
    {
        DbgOut("Failed to write snapshot handle (%u)", GetLastError());
        return false;
    }

    return true;
}

DWORD CWERFaultDLLInject::GetExitCode()
{
    return m_dwExitCode;
}
