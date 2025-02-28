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
 * Implementation of IAT hook of werui.dll
 *
 ****************************************************************************/

#include "pch.h"

#include <DelayLoadUtils.h>

#include "PEUtils.h"
#include "ProjectUtils.h"
#include "WERUIHook.h"

static const LPCSTR g_szWindow0ApiSetName = "ext-ms-win-ntuser-window-l1-1-0.dll";

static const LPCSTR g_szSetWindowPosName = "SetWindowPos";

typedef BOOL (WINAPI *PSET_WINDOW_POS) (HWND    hWnd,
                                        HWND    hWndInsertAfter,
                                        int     X,
                                        int     Y,
                                        int     cx,
                                        int     cy,
                                        UINT    uFlags);

PVOID g_pPrevSetWindowPos = NULL;

BOOL WINAPI NewSetWindowPos(HWND    hWnd,
                            HWND    hWndInsertAfter,
                            int     X,
                            int     Y,
                            int     cx,
                            int     cy,
                            UINT    uFlags)
{
    if (hWndInsertAfter == HWND_TOPMOST)
    {
        DbgOut("SetWindowPos with hWndInsertAfter==HWND_TOPMOST, setting SWP_NOZORDER flag");
        uFlags |= SWP_NOZORDER;
    }

    return ((PSET_WINDOW_POS)g_pPrevSetWindowPos)(hWnd, hWndInsertAfter, X, Y, cx, cy, uFlags);
}

PRESOLVE_DELAY_LOADED_API g_pPrevWERUIResolveDelayLoadedAPI = NULL;

void WERUITryHookDelayLoadImport(PVOID               ParentModuleBase,
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

        if (lstrcmpiA(pImportName->Name, g_szSetWindowPosName) == 0)
        {
            // TODO: add error checking
            PatchImport(pAddrThunk, NewSetWindowPos, &g_pPrevSetWindowPos);

            // If ResolveDelayLoadedAPI was called for this specific import, we need to pass back
            // the hook address for the ResolveDelayLoadedAPI hook function to put the address in
            // its return value.
            if (ThunkAddress == pAddrThunk)
            {
                *ppImportAddress = NewSetWindowPos;
            }
        }
    }
}

// TODO: make common by putting it in a utility class (DelayLoadPEModuleWalker?)
PVOID WINAPI WERUINewResolveDelayLoadedAPI(PVOID                             ParentModuleBase,
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

    pImportAddress = g_pPrevWERUIResolveDelayLoadedAPI(ParentModuleBase,
                                                       DelayloadDescriptor,
                                                       FailureDllHook,
                                                       FailureSystemHook,
                                                       ThunkAddress,
                                                       Flags);

    if (!CheckResolveDelayLoadedAPIResult(ParentModuleBase, DelayloadDescriptor, ThunkAddress))
        return pImportAddress;

    dllName = (const char *)RVAToAbsolute(ParentModuleBase, DelayloadDescriptor->DllNameRVA);

    if (lstrcmpiA(dllName, g_szWindow0ApiSetName) == 0)
    {
        pAddrThunk =
            (PIMAGE_THUNK_DATA)RVAToAbsolute(ParentModuleBase,
                                             DelayloadDescriptor->ImportAddressTableRVA);
        pNameThunk =
            (PIMAGE_THUNK_DATA)RVAToAbsolute(ParentModuleBase,
                                             DelayloadDescriptor->ImportNameTableRVA);

        while (pAddrThunk->u1.AddressOfData && pNameThunk->u1.AddressOfData)
        {
            WERUITryHookDelayLoadImport(ParentModuleBase,
                                        ThunkAddress,
                                        pAddrThunk,
                                        pNameThunk,
                                        &pImportAddress);

            pAddrThunk++;
            pNameThunk++;
        }
    }

    return pImportAddress;
}

void CWERUIHook::HookWERUI()
{
    WalkImportModules();
}

void CWERUIHook::PatchImportedModule(PIMAGE_THUNK_DATA pOrigFirstThunk,
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

        if (lstrcmpA(importName, g_szSetWindowPosName) == 0)
        {
            // TODO: add error checking
            PatchImport(pThunk, NewSetWindowPos, &g_pPrevSetWindowPos);
        }
        else if (lstrcmpiA(importName, g_szResolveDelayLoadedAPIName) == 0)
        {
            // TODO: add error checking
            PatchImport(pThunk,
                        WERUINewResolveDelayLoadedAPI,
                        (PVOID *)&g_pPrevWERUIResolveDelayLoadedAPI);
        }

next:

        pOrigThunk++;
        pThunk++;
    }
}

bool CWERUIHook::ImportModuleProc(PIMAGE_IMPORT_DESCRIPTOR  pImpDesc,
                                  const char               *name)
{
    PIMAGE_THUNK_DATA pOrigFirstThunk   = NULL;
    PIMAGE_THUNK_DATA pFirstThunk       = NULL;

    if (lstrcmpiA(name, g_szKernel32) == 0 || lstrcmpiA(name, g_szUser32) == 0)
    {
        pOrigFirstThunk = (PIMAGE_THUNK_DATA)RVAToAbsolute(pImpDesc->OriginalFirstThunk);
        pFirstThunk     = (PIMAGE_THUNK_DATA)RVAToAbsolute(pImpDesc->FirstThunk);

        PatchImportedModule(pOrigFirstThunk, pFirstThunk);
    }

    return true;
}
