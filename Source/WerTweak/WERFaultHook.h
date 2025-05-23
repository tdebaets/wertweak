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
 * Definitions for IAT hook of WerFault.exe
 *
 ****************************************************************************/

#pragma once

#include "PEModuleWalker.h"
#include "ProjectUtils.h"

extern const LPCSTR g_szProcessSnapshotApiSetName;

/*
 * To allow WerTweakInject to detect the debug breakpoint in TranslateSnapshotHandleByDebugger(),
 * we put this function in a separate, dedicated PE section. Note that just specifying 'code_seg'
 * has no effect when compiling in a release configuration since then the function is being inlined,
 * so we must also specify 'noinline'.
 */
#define TRANSLATE_HPSS_FUNC __declspec(noinline code_seg(TRANSLATE_HPSS_SEGMENT_NAME))

extern TRANSLATE_HPSS_FUNC HPSS TranslateSnapshotHandleByDebugger(HPSS SnapshotHandle);

class CWERFaultHook : public CPEModuleWalker
{

public:
    CWERFaultHook(HMODULE hMod) : CPEModuleWalker(hMod) {}
    void HookWERFault();

protected:
    virtual bool ImportModuleProc(PIMAGE_IMPORT_DESCRIPTOR  pImpDesc,
                                  const char               *name);

private:
    void PatchImportedModule(PIMAGE_THUNK_DATA pOrigFirstThunk,
                             PIMAGE_THUNK_DATA pFirstThunk);

};
