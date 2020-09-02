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
 * Implementation of IAT hook of werui.dll
 *
 ****************************************************************************/

#include "pch.h"

#include "PEUtils.h"
#include "ProjectUtils.h"
#include "WERUIHook.h"

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

    if (lstrcmpiA(name, g_szUser32) == 0)
    {
        pOrigFirstThunk = (PIMAGE_THUNK_DATA)RVAToAbsolute(pImpDesc->OriginalFirstThunk);
        pFirstThunk     = (PIMAGE_THUNK_DATA)RVAToAbsolute(pImpDesc->FirstThunk);

        PatchImportedModule(pOrigFirstThunk, pFirstThunk);
    }

    return true;
}
