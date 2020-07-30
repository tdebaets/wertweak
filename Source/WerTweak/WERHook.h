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
 * Definitions for IAT hook of wer.dll
 *
 ****************************************************************************/

#pragma once

#include "PEModuleWalker.h"

extern const LPCSTR g_szWERDllName;
extern const LPCSTR g_szWERReportSubmitName;

extern PVOID g_pPrevWerReportSubmit;

HRESULT NewWerReportSubmit(HREPORT               hReportHandle,
                           WER_CONSENT           consent,
                           DWORD                 dwFlags,
                           PWER_SUBMIT_RESULT    pSubmitResult);

class CWERHook : public CPEModuleWalker
{

public:
    CWERHook(HMODULE hMod) : CPEModuleWalker(hMod) {}
    void HookWER();

protected:
    virtual bool ImportModuleProc(PIMAGE_IMPORT_DESCRIPTOR  pImpDesc,
                                  const char               *name);

private:
    void PatchImportedModule(PIMAGE_THUNK_DATA pOrigFirstThunk,
                             PIMAGE_THUNK_DATA pFirstThunk);

};
