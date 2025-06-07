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
 * Implementation of IAT hook of WerFault.exe
 *
 ****************************************************************************/

#include "pch.h"

#include <DelayLoadUtils.h>

#include "PEUtils.h"
#include "WERExportHook.h"
#include "WERFaultHook.h"

// TODO: move to WERHook/ProcessSnapshotHook?
static const LPCSTR g_szProcessSnapshotApiSetName   = "api-ms-win-core-processsnapshot-l1-1-0.dll";

static const LPCSTR g_szPssQuerySnapshotName        = "PssQuerySnapshot";
static const LPCSTR g_szPssDuplicateSnapshotName    = "PssDuplicateSnapshot";
static const LPCSTR g_szPssWalkSnapshotName         = "PssWalkSnapshot";

// TODO: make sure that native/non-native x86 debuggee still works
TRANSLATE_HPSS_FUNC HPSS TranslateSnapshotHandleByDebugger(HPSS hSnapshot, DWORD dwFlags)
{
    HPSS               *phSnapshot      = &hSnapshot;
    EXCEPTION_RECORD    exceptionRecord = {};

    /*
     * Note: process snapshot handle translation is only needed/supported on x64, see comment in
     * WerTweakInject.cpp:HandleTranslateProcessSnapshotHandle.
     */
    if (IsDebuggerPresent())
    {
        exceptionRecord.ExceptionCode       = STATUS_TRANSLATE_PROCESS_SNAPSHOT_HANDLE;
        exceptionRecord.ExceptionFlags      = 0; /* continuable exception */
        exceptionRecord.NumberParameters    = STATUS_TRANSLATE_PROCESS_SNAPSHOT_HANDLE_PARAM_MAX_PLUS1;

        /*
         * We must pass the snapshot handle by reference here to allow the debugger (i.e.
         * WerTweakInject) to modify its value.
         */
        exceptionRecord.ExceptionInformation[STATUS_TRANSLATE_PROCESS_SNAPSHOT_HANDLE_PARAM_PHANDLE]
                = (ULONG_PTR)phSnapshot;

        exceptionRecord.ExceptionInformation[STATUS_TRANSLATE_PROCESS_SNAPSHOT_HANDLE_PARAM_FLAGS]
                = dwFlags;

        /*
         * Trigger an exception by calling RtlRaiseException(). Note that the address of this
         * exception is being checked by WerTweakInject so we cannot simply use RaiseException()
         * here (because then the exception address would be in KernelBase.dll instead of in this
         * DLL).
         */
        RtlRaiseException(&exceptionRecord);
    }

    return *phSnapshot;
}

PVOID g_pPrevPssQuerySnapshot = NULL;

DWORD WINAPI NewPssQuerySnapshot(HPSS                           SnapshotHandle,
                                 PSS_QUERY_INFORMATION_CLASS    InformationClass,
                                 void                          *Buffer,
                                 DWORD                          BufferLength)
{
    DWORD dwResult;

    DbgOut("PssQuerySnapshot(0x%p)", SnapshotHandle);

    SnapshotHandle = TranslateSnapshotHandleByDebugger(SnapshotHandle, 0);

    DbgOut("  handle after translation: 0x%p", SnapshotHandle);

    dwResult = ((PPSS_QUERY_SNAPSHOT)g_pPrevPssQuerySnapshot)(SnapshotHandle,
                                                              InformationClass,
                                                              Buffer,
                                                              BufferLength);

    DbgOut("  result=%u", dwResult);

    return dwResult;
}

void CWERFaultHook::HookWERFault()
{
    WalkImportModules();
}

void CWERFaultHook::PatchImportedModule(PIMAGE_THUNK_DATA pOrigFirstThunk,
                                        PIMAGE_THUNK_DATA pFirstThunk)
{
    PIMAGE_THUNK_DATA pOrigThunk    = pOrigFirstThunk;
    PIMAGE_THUNK_DATA pThunk        = pFirstThunk;

    while (pOrigThunk->u1.AddressOfData && pThunk->u1.AddressOfData)
    {
        PIMAGE_IMPORT_BY_NAME   pImport     = NULL;
        const char             *importName  = NULL;

        // Ignore imports by ordinal
        if (pOrigThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
            goto next;

        pImport     = (PIMAGE_IMPORT_BY_NAME)RVAToAbsolute(pOrigThunk->u1.AddressOfData);
        importName  = pImport->Name;

        if (lstrcmpA(importName, g_szPssQuerySnapshotName) == 0)
        {
            // TODO: add error checking
            PatchImport(pThunk, NewPssQuerySnapshot, (PVOID *)&g_pPrevPssQuerySnapshot);
        }
        else if (lstrcmpA(importName, g_szWerpTraceSnapshotStatisticsName) == 0)
        {
            // TODO: add error checking
            PatchImport(pThunk,
                        NewWerpTraceSnapshotStatistics,
                        (PVOID *)&g_pPrevWerpTraceSnapshotStatistics);
        }

next:

        pOrigThunk++;
        pThunk++;
    }
}

bool CWERFaultHook::ImportModuleProc(PIMAGE_IMPORT_DESCRIPTOR  pImpDesc,
                                     const char               *name)
{
    PIMAGE_THUNK_DATA pOrigFirstThunk   = NULL;
    PIMAGE_THUNK_DATA pFirstThunk       = NULL;

    if (lstrcmpiA(name, g_szProcessSnapshotApiSetName) == 0 ||
        lstrcmpiA(name, g_szWerDllName) == 0)
    {
        pOrigFirstThunk = (PIMAGE_THUNK_DATA)RVAToAbsolute(pImpDesc->OriginalFirstThunk);
        pFirstThunk     = (PIMAGE_THUNK_DATA)RVAToAbsolute(pImpDesc->FirstThunk);

        PatchImportedModule(pOrigFirstThunk, pFirstThunk);
    }

    return true;
}
