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
 * Hook definitions for functions exported by werui.dll
 *
 ****************************************************************************/

#pragma once

extern const LPCSTR g_szWerUiApiSetName;
extern const LPCSTR g_szWerUiCreateName;

extern PVOID g_pPrevWerUICreate;

/*
 * Possible values for the consentFlag parameter of WerUICreate()
 * (undocumented, other possible values might exist but are currently not known)
 */
typedef enum _WER_UIC_CONSENT_FLAG
{
    WerConsentShow = 0,
    WerConsentHide = 1,
} WER_UIC_CONSENT_FLAG;

HRESULT WINAPI NewWerUICreate(LPVOID                pUnknown1,
                              WER_UIC_CONSENT_FLAG  consentFlag,
                              LPVOID                pfnUiCallback,
                              LPVOID                pUnknown2,
                              HANDLE                hEvent1,
                              HANDLE                hEvent2,
                              HANDLE                hEvent3,
                              LPVOID                pUnknown3);
