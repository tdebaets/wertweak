/****************************************************************************
 *
 *            WerTweak
 *
 *            Copyright (c) 2020-2025 Tim De Baets
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
 * Hook implementation for functions exported by werui.dll
 *
 ****************************************************************************/

#include "pch.h"
#include "..\WerTweak.h"
#include "WERUIExportHook.h"

static const LPCSTR g_szWerUIDllName    = "werui.dll";
static const LPCSTR g_szWerUIApiSetName = "ext-ms-win-wer-ui-l1-1-0.dll";
static const LPCSTR g_szWerUICreateName = "WerUICreate";

extern PVOID g_pPrevWerUICreate = NULL;

// Except for consentFlag and pfnUiCallback, all other parameter meanings are educated guesses
typedef HRESULT (WINAPI *PWER_UI_CREATE) (LPVOID                 pUnknown1,
                                          WER_UIC_CONSENT_FLAG   consentFlag,
                                          LPVOID                 pfnUiCallback,
                                          LPVOID                 pUnknown2,
                                          HANDLE                 hEvent1,
                                          HANDLE                 hEvent2,
                                          HANDLE                 hEvent3,
                                          LPVOID                 pUnknown3);

HRESULT WINAPI NewWerUICreate(LPVOID                pUnknown1,
                              WER_UIC_CONSENT_FLAG  consentFlag,
                              LPVOID                pfnUiCallback,
                              LPVOID                pUnknown2,
                              HANDLE                hEvent1,
                              HANDLE                hEvent2,
                              HANDLE                hEvent3,
                              LPVOID                pUnknown3)
{
    // TODO: remove
    DbgOut("NewWerUICreate");

    if (consentFlag == WerConsentHide)
    {
        DbgOut("WerUICreate call with hidden consent detected, modifying to show consent instead");

        consentFlag = WerConsentShow;
    }

    return ((PWER_UI_CREATE)g_pPrevWerUICreate)(pUnknown1,
                                                consentFlag,
                                                pfnUiCallback,
                                                pUnknown2,
                                                hEvent1,
                                                hEvent2,
                                                hEvent3,
                                                pUnknown3);
}
