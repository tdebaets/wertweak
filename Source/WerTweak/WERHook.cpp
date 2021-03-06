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
 * Implementation of IAT hook of wer.dll
 *
 ****************************************************************************/

#include "pch.h"

#include <DelayLoadUtils.h>

#include "PEUtils.h"
#include "ProjectUtils.h"
#include "WERHook.h"
#include "WERUIHook.h"
#include "WERUIExportHook.h"

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

// TODO: make common?
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

    if (lstrcmpiA(name, g_szDelayLoadApiSetName) == 0)
    {
        pOrigFirstThunk = (PIMAGE_THUNK_DATA)RVAToAbsolute(pImpDesc->OriginalFirstThunk);
        pFirstThunk     = (PIMAGE_THUNK_DATA)RVAToAbsolute(pImpDesc->FirstThunk);

        PatchImportedModule(pOrigFirstThunk, pFirstThunk);
    }

    return true;
}
