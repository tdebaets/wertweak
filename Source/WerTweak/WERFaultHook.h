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

extern const LPCSTR g_szProcessSnapshotApiSetName;

extern HPSS TranslateSnapshotHandleByDebugger(HPSS SnapshotHandle);

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
