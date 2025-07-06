/****************************************************************************
 *
 *            WerTweak
 *
 *            Copyright (c) 2020-2021 Tim De Baets
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
 * Implementation of IAT hook of wer.dll
 *
 ****************************************************************************/

#include "pch.h"

#include <DelayLoadUtils.h>

#include "..\WerTweak.h"
#include "PEUtils.h"
#include "WERFaultHook.h"
#include "WERHook.h"
#include "WERUIHook.h"
#include "WERUIExportHook.h"

/*
 * Some of the DbgOut() calls below (e.g. in NewWERPssWalkSnapshot) occur in WerFault's hot code
 * paths and introduce too much delay in its execution. These are compiled out by default, but can
 * be included again by uncommenting this define.
 */
//#define COMPILE_DBGOUT_CALLS_IN_HOT_PATHS

PRESOLVE_DELAY_LOADED_API g_pPrevWERResolveDelayLoadedAPI = NULL;

void WERTryHookDelayLoadImport(PVOID               ParentModuleBase,
                               PIMAGE_THUNK_DATA   ThunkAddress,
                               PIMAGE_THUNK_DATA   pAddrThunk,
                               PIMAGE_THUNK_DATA   pNameThunk,
                               PVOID              *ppImportAddress)
{
    PIMAGE_IMPORT_BY_NAME pImportName = NULL;

    if (!pAddrThunk->u1.AddressOfData || !pNameThunk->u1.AddressOfData)
        return;

    if ((pNameThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) == 0)
    {
        // import by name

        pImportName = (PIMAGE_IMPORT_BY_NAME)RVAToAbsolute(ParentModuleBase,
                                                           pNameThunk->u1.AddressOfData);

        if (lstrcmpiA(pImportName->Name, g_szWerUICreateName) == 0)
        {
            // TODO: add error checking
            PatchImport(pAddrThunk, NewWerUICreate, (PVOID *)&g_pPrevWerUICreate);

            // If ResolveDelayLoadedAPI was called for this specific import, we need to pass back
            // the hook address for the ResolveDelayLoadedAPI hook function to put the address in
            // its return value.
            if (ThunkAddress == pAddrThunk)
            {
                *ppImportAddress = NewWerUICreate;
            }
        }
    }
}

// TODO: move?
void TryHookWerUI()
{
    HMODULE hmodWerUI = GetModuleHandleA(g_szWerUIDllName);

    if (!hmodWerUI)
    {
        DbgOut("Warning: %hs module not loaded", g_szWerUIDllName);
        return;
    }

    try
    {
        CWERUIHook werUIHook(hmodWerUI);

        werUIHook.HookWERUI();
    }
    catch (CPEModuleWalkerError & error)
    {
        DbgOut("Error walking %hs import modules: %s", g_szWerUIDllName, error.what());
    }
}

// TODO: make common by putting it in a utility class (DelayLoadPEModuleWalker?)
PVOID WINAPI WERNewResolveDelayLoadedAPI(PVOID                             ParentModuleBase,
                                         PCIMAGE_DELAYLOAD_DESCRIPTOR      DelayloadDescriptor,
                                         PDELAYLOAD_FAILURE_DLL_CALLBACK   FailureDllHook,
                                         PVOID                             FailureSystemHook,
                                         PIMAGE_THUNK_DATA                 ThunkAddress,
                                         ULONG                             Flags)
{
    PIMAGE_THUNK_DATA   pAddrThunk      = NULL;
    PIMAGE_THUNK_DATA   pNameThunk      = NULL;
    PVOID               pImportAddress  = NULL;
    const char         *dllName         = NULL;

    pImportAddress = g_pPrevWERResolveDelayLoadedAPI(ParentModuleBase,
                                                     DelayloadDescriptor,
                                                     FailureDllHook,
                                                     FailureSystemHook,
                                                     ThunkAddress,
                                                     Flags);

    if (!CheckResolveDelayLoadedAPIResult(ParentModuleBase, DelayloadDescriptor, ThunkAddress))
        return pImportAddress;

    dllName = (const char *)RVAToAbsolute(ParentModuleBase, DelayloadDescriptor->DllNameRVA);

    if (lstrcmpiA(dllName, g_szWerUIApiSetName) == 0)
    {
        pAddrThunk =
            (PIMAGE_THUNK_DATA)RVAToAbsolute(ParentModuleBase,
                                             DelayloadDescriptor->ImportAddressTableRVA);
        pNameThunk =
            (PIMAGE_THUNK_DATA)RVAToAbsolute(ParentModuleBase,
                                             DelayloadDescriptor->ImportNameTableRVA);

        while (pAddrThunk->u1.AddressOfData && pNameThunk->u1.AddressOfData)
        {
            WERTryHookDelayLoadImport(ParentModuleBase,
                                      ThunkAddress,
                                      pAddrThunk,
                                      pNameThunk,
                                      &pImportAddress);

            pAddrThunk++;
            pNameThunk++;
        }

        TryHookWerUI();
    }

    return pImportAddress;
}

PVOID g_pPrevWERPssQuerySnapshot = NULL;

DWORD WINAPI NewWERPssQuerySnapshot(HPSS                           SnapshotHandle,
                                    PSS_QUERY_INFORMATION_CLASS    InformationClass,
                                    void                          *Buffer,
                                    DWORD                          BufferLength)
{
    DWORD dwResult;

    DbgOut("WER PssQuerySnapshot(0x%p)", SnapshotHandle);

    SnapshotHandle = TranslateSnapshotHandleByDebugger(SnapshotHandle, 0);

    DbgOut("  handle after translation: 0x%p", SnapshotHandle);

    dwResult = ((PPSS_QUERY_SNAPSHOT)g_pPrevWERPssQuerySnapshot)(SnapshotHandle,
                                                                 InformationClass,
                                                                 Buffer,
                                                                 BufferLength);

    DbgOut("  result=%u", dwResult);

    return dwResult;
}

PVOID g_pPrevWERPssDuplicateSnapshot = NULL;

DWORD WINAPI NewWERPssDuplicateSnapshot(HANDLE                 SourceProcessHandle,
                                        HPSS                   SnapshotHandle,
                                        HANDLE                 TargetProcessHandle,
                                        HPSS                  *TargetSnapshotHandle,
                                        PSS_DUPLICATE_FLAGS    Flags)
{
    DWORD dwResult;

    DbgOut("WER PssDuplicateSnapshot(0x%p)", SnapshotHandle);

    SnapshotHandle = TranslateSnapshotHandleByDebugger(SnapshotHandle, 0);

    DbgOut("  handle after translation: 0x%p", SnapshotHandle);

    dwResult = ((PPSS_DUPLICATE_SNAPSHOT)g_pPrevWERPssDuplicateSnapshot)(SourceProcessHandle,
                                                                         SnapshotHandle,
                                                                         TargetProcessHandle,
                                                                         TargetSnapshotHandle,
                                                                         Flags);

    DbgOut("  result=%u", dwResult);

    return dwResult;
}

PVOID g_pPrevWERPssWalkSnapshot = NULL;

DWORD WINAPI NewWERPssWalkSnapshot(HPSS                         SnapshotHandle,
                                   PSS_WALK_INFORMATION_CLASS   InformationClass,
                                   HPSSWALK                     WalkMarkerHandle,
                                   void                        *Buffer,
                                   DWORD                        BufferLength)
{
    DWORD dwResult;

#if defined(COMPILE_DBGOUT_CALLS_IN_HOT_PATHS)
    DbgOut("WER PssWalkSnapshot(0x%p, %u)", SnapshotHandle, InformationClass);
#endif

    /*
     * Note: PssWalkSnapshot() gets called a *lot* (several thousands of times) by WerFault. The
     * DbgOut() calls in WerTweakInject.cpp that are triggered by process snapshot handle
     * translation introduce too much delay to allow WerFault to complete in a reasonable amount of
     * time. So we pass the TRANSLATE_PROCESS_SNAPSHOT_HANDLE_FLAG_SUPPRESS_DBG_OUTPUT flag that
     * suppresses these calls.
     */
    SnapshotHandle = TranslateSnapshotHandleByDebugger(
            SnapshotHandle,
            TRANSLATE_PROCESS_SNAPSHOT_HANDLE_FLAG_SUPPRESS_DBG_OUTPUT);

#if defined(COMPILE_DBGOUT_CALLS_IN_HOT_PATHS)
    DbgOut("  handle after translation: 0x%p", SnapshotHandle);
#endif

    dwResult = ((PPSS_WALK_SNAPSHOT)g_pPrevWERPssWalkSnapshot)(SnapshotHandle,
                                                               InformationClass,
                                                               WalkMarkerHandle,
                                                               Buffer,
                                                               BufferLength);

#if defined(COMPILE_DBGOUT_CALLS_IN_HOT_PATHS)
    DbgOut("  result=%u", dwResult);
#endif

    return dwResult;
}

void CWERHook::HookWER()
{
    WalkImportModules();
}

void CWERHook::PatchImportedModule(PIMAGE_THUNK_DATA pOrigFirstThunk,
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

        if (lstrcmpA(importName, g_szResolveDelayLoadedAPIName) == 0)
        {
            // TODO: add error checking
            PatchImport(pThunk,
                        WERNewResolveDelayLoadedAPI,
                        (PVOID *)&g_pPrevWERResolveDelayLoadedAPI);
        }
        else if (lstrcmpA(importName, g_szPssQuerySnapshotName) == 0)
        {
            // TODO: add error checking
            PatchImport(pThunk, NewWERPssQuerySnapshot, (PVOID *)&g_pPrevWERPssQuerySnapshot);
        }
        else if (lstrcmpA(importName, g_szPssDuplicateSnapshotName) == 0)
        {
            // TODO: add error checking
            PatchImport(pThunk, NewWERPssDuplicateSnapshot, (PVOID *)&g_pPrevWERPssDuplicateSnapshot);
        }
        else if (lstrcmpA(importName, g_szPssWalkSnapshotName) == 0)
        {
            // TODO: add error checking
            PatchImport(pThunk, NewWERPssWalkSnapshot, (PVOID *)&g_pPrevWERPssWalkSnapshot);
        }

next:

        pOrigThunk++;
        pThunk++;
    }
}

bool CWERHook::ImportModuleProc(PIMAGE_IMPORT_DESCRIPTOR  pImpDesc,
                                const char               *name)
{
    PIMAGE_THUNK_DATA pOrigFirstThunk   = NULL;
    PIMAGE_THUNK_DATA pFirstThunk       = NULL;

    if (lstrcmpiA(name, g_szDelayLoadApiSetName) == 0 ||
        lstrcmpiA(name, g_szProcessSnapshotApiSetName) == 0)
    {
        pOrigFirstThunk = (PIMAGE_THUNK_DATA)RVAToAbsolute(pImpDesc->OriginalFirstThunk);
        pFirstThunk     = (PIMAGE_THUNK_DATA)RVAToAbsolute(pImpDesc->FirstThunk);

        PatchImportedModule(pOrigFirstThunk, pFirstThunk);
    }

    return true;
}
