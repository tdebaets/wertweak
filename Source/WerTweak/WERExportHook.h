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
 * Hook definitions for functions exported by wer.dll
 *
 ****************************************************************************/

#pragma once

extern const LPCSTR g_szWerDllName;
extern const LPCSTR g_szWerReportSubmitName;
extern const LPCSTR g_szWerpTraceSnapshotStatisticsName;

extern PVOID g_pPrevWerReportSubmit;

HRESULT WINAPI NewWerReportSubmit(HREPORT               hReportHandle,
                                  WER_CONSENT           consent,
                                  DWORD                 dwFlags,
                                  PWER_SUBMIT_RESULT    pSubmitResult);

extern PVOID g_pPrevWerpTraceSnapshotStatistics;

// Taken from debug symbol CProcessDump::static_vLogCallbackRoutine in Wer.pdb
typedef void (__cdecl *PWERP_TRACE_SNAPSHOT_STATS_CALLBACK) (
    void *,
    unsigned long,
    wchar_t const *,
    char *);

DWORD64 WINAPI NewWerpTraceSnapshotStatistics(PWERP_TRACE_SNAPSHOT_STATS_CALLBACK   pCallbackProc,
                                              PDWORD64                              pdwUnknown,
                                              HPSS                                  SnapshotHandle);
