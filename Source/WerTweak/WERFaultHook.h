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

extern const LPCSTR g_szPssQuerySnapshotName;
extern const LPCSTR g_szPssDuplicateSnapshotName;
extern const LPCSTR g_szPssWalkSnapshotName;

typedef DWORD (WINAPI *PPSS_QUERY_SNAPSHOT) (HPSS                           SnapshotHandle,
                                             PSS_QUERY_INFORMATION_CLASS    InformationClass,
                                             void                          *Buffer,
                                             DWORD                          BufferLength);

typedef DWORD (WINAPI *PPSS_DUPLICATE_SNAPSHOT) (HANDLE                 SourceProcessHandle,
                                                 HPSS                   SnapshotHandle,
                                                 HANDLE                 TargetProcessHandle,
                                                 HPSS                  *TargetSnapshotHandle,
                                                 PSS_DUPLICATE_FLAGS    Flags);

typedef DWORD (WINAPI *PPSS_WALK_SNAPSHOT) (HPSS                         SnapshotHandle,
                                            PSS_WALK_INFORMATION_CLASS   InformationClass,
                                            HPSSWALK                     WalkMarkerHandle,
                                            void                        *Buffer,
                                            DWORD                        BufferLength);
/*
 * To allow WerTweakInject to check the address of the exception raised in
 * TranslateSnapshotHandleByDebugger(), we put this function in a separate, dedicated PE section.
 * Note that just specifying 'code_seg' has no effect when compiling in a release configuration
 * since then the function is being inlined, so we must also specify 'noinline'.
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
