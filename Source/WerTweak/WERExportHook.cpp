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
 * Hook implementation for functions exported by wer.dll
 *
 ****************************************************************************/

#include "pch.h"

#include "..\WerTweak.h"
#include "WERExportHook.h"
#include "WERFaultHook.h"

// Undocumented flag for WerReportSubmit
// TODO: research if not known anywhere
#define WER_SUBMIT_PROCESS_IS_IMMERSIVE_BROKER  0x00080000 // PROCESS_UICONTEXT_IMMERSIVE_BROKER
#define WER_SUBMIT_PROCESS_IS_IMMERSIVE         0x00100000 // PROCESS_UICONTEXT_IMMERSIVE

static const LPCSTR g_szWerDllName                      = "wer.dll";
static const LPCSTR g_szWerReportSubmitName             = "WerReportSubmit";
static const LPCSTR g_szWerpTraceSnapshotStatisticsName = "WerpTraceSnapshotStatistics";

PVOID g_pPrevWerReportSubmit = NULL;

typedef HRESULT (WINAPI *PWER_REPORT_SUBMIT) (HREPORT               hReportHandle,
                                              WER_CONSENT           consent,
                                              DWORD                 dwFlags,
                                              PWER_SUBMIT_RESULT    pSubmitResult);

HRESULT WINAPI NewWerReportSubmit(HREPORT               hReportHandle,
                                  WER_CONSENT           consent,
                                  DWORD                 dwFlags,
                                  PWER_SUBMIT_RESULT    pSubmitResult)
{
    // TODO: remove?
    DbgOut("WerReportSubmit dwFlags==%x", dwFlags);

    if (dwFlags & WER_SUBMIT_HONOR_RESTART)
    {
        // This flag gets included by FaultRep.dll if the application has called the
        // RegisterApplicationRestart function without the RESTART_NO_CRASH flag
        // (checked by calling the internal WerpGetRestartCommandLine function, which reads the
        // command line from the process's PEB - probably via the WerRegistrationData field)
        DbgOut("Removing WER_SUBMIT_HONOR_RESTART flag");
        dwFlags &= ~WER_SUBMIT_HONOR_RESTART;
    }

    if (dwFlags & WER_SUBMIT_QUEUE)
    {
        // This flag gets included by FaultRep.dll for Explorer.exe
        // (checked by calling GetShellWindows/GetWindowThreadProcessId, comparing the process IDs,
        // and setting an internal flag if they match)
        DbgOut("Removing WER_SUBMIT_QUEUE flag");
        dwFlags &= ~WER_SUBMIT_QUEUE;
    }

    if (dwFlags & WER_SUBMIT_PROCESS_IS_IMMERSIVE_BROKER)
    {
        // This flag gets included by FaultRep.dll for immersive broker processes
        // (checked by calling NtUserGetProcessUIContextInformation and checking against
        // PROCESS_UICONTEXT_IMMERSIVE_BROKER)
        DbgOut("Removing WER_SUBMIT_PROCESS_IS_IMMERSIVE_BROKER flag");
        dwFlags &= ~WER_SUBMIT_PROCESS_IS_IMMERSIVE_BROKER;
    }

    return ((PWER_REPORT_SUBMIT)g_pPrevWerReportSubmit)(hReportHandle,
                                                        consent,
                                                        dwFlags,
                                                        pSubmitResult);
}

PVOID g_pPrevWerpTraceSnapshotStatistics = NULL;

// The original function doesn't seem to return any value, but preserve it anyway to be safe
typedef DWORD64 (WINAPI *PWERP_TRACE_SNAPSHOT_STATS) (
    PWERP_TRACE_SNAPSHOT_STATS_CALLBACK pCallbackProc,
    PDWORD64                            pdwUnknown,
    HPSS                                SnapshotHandle);

DWORD64 WINAPI NewWerpTraceSnapshotStatistics(PWERP_TRACE_SNAPSHOT_STATS_CALLBACK   pCallbackProc,
                                              PDWORD64                              pdwUnknown,
                                              HPSS                                  SnapshotHandle)
{
    // TODO: remove?
    DbgOut("WerpTraceSnapshotStatistics SnapshotHandle==0x%p", SnapshotHandle);

    SnapshotHandle = TranslateSnapshotHandleByDebugger(SnapshotHandle, 0);

    DbgOut("  handle after translation: 0x%p", SnapshotHandle);

    return ((PWERP_TRACE_SNAPSHOT_STATS)g_pPrevWerpTraceSnapshotStatistics)(pCallbackProc,
                                                                            pdwUnknown,
                                                                            SnapshotHandle);
}
