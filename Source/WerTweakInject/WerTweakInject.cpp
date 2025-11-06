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
 * Main implementation of the WerTweak injector application
 *
 ****************************************************************************/

#include "pch.h"

#include <Processes.h>
#include <Wow64Utils.h>

#include "..\WerTweak.h"
#include "DLLInject.h"
#include "WerTweakInject.h"

// TODO: retest on 32-bit OS
// TODO: fix release mode WerTweak64.exe crashing on process close when handling hang/crash (only on Win10?)
// TODO: retest with crash handling
// TODO: test on Win11 insider preview
// TODO: retest WerpTraceSnapshotStatistics hook
// TODO: make sure that the WER DontShowUI policy is also set to disabled (otherwise there's no UI at all)
//   HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting\DontShowUI
//   HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Windows Error Reporting\DontShowUI
//   "Disabled" value in same keys should also be set to 0
// Should also be set to value 1:
//  HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection\AllowTelemetry
// Check these values and correct them in installer?
// TODO: try to fix double report on Explorer.exe crash (might be related to Symantec Endpoint Protection)
// TODO: add memleak checks

void MakeAllOurObjectHandlesInheritable()
{
    PPROCESS_HANDLE_SNAPSHOT_INFORMATION    pHandles        = NULL;
    DWORD                                   dwNumHandles    = 0;
    NTSTATUS                                status;

    status = PhEnumHandlesEx2(GetCurrentProcess(), &pHandles);
    if (!NT_SUCCESS(status))
    {
        DbgOut("PhEnumHandlesEx2 failed (%x)", status);
        return;
    }

    for (int i = 0; i < pHandles->NumberOfHandles; i++)
    {
        PROCESS_HANDLE_TABLE_ENTRY_INFO *pInfo = &pHandles->Handles[i];

        // TODO: only for specific object types? (check ObjectTypeIndex)
        // TODO: add generic macro for checking flag in bitmask
        if ((pInfo->HandleAttributes & OBJ_INHERIT) == 0)
        {
            if (SetHandleInformation(pInfo->HandleValue, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT))
            {
                dwNumHandles++;
            }
            else
            {
                DbgOut("SetHandleInformation(0x%p) failed (%u)", pInfo->HandleValue, GetLastError());
            }
        }
    }

    DbgOut("Made %u object handles inheritable", dwNumHandles);

    delete[] pHandles;
}

int APIENTRY wWinMain(_In_ HINSTANCE        hInstance,
                      _In_opt_ HINSTANCE    hPrevInstance,
                      _In_ LPWSTR           lpCmdLine,
                      _In_ int              nCmdShow)
{
    UNREFERENCED_PARAMETER(hPrevInstance);

    STARTUPINFO         startupInfo = {};
    PROCESS_INFORMATION procInfo    = {};
    SidWrapper          procSid;
    DWORD               dwExitCode  = 0;

    startupInfo.cb = sizeof(startupInfo);

    // TODO: remove
    DbgOut("%s", lpCmdLine);

    if (lpCmdLine[0] == '\0')
    {
        // TODO: print usage?
        return 1;
    }

    if (!GetProcessSid(GetCurrentProcessId(), GetCurrentProcess(), procSid))
    {
        DbgOut("Failed to get our process SID, exiting");
        return 2;
    }

    /*
     * When WerSvc launches WerFault.exe for a hung process, the service duplicates a few object
     * handles into the context of WerFault (in my testing, 2 file mapping handles and 5 event
     * handles). The duplicated handle values are then passed to WerFault via a named file mapping,
     * of which the name is passed to WerFault via the command line (example:
     * "/shared Global\8928ad8824614ac9aadef800e0ddd09f"). However, for duplicating these handles,
     * WerSvc uses DuplicateHandle() calls with the bInheritHandle parameter set to FALSE, so when
     * WerSvc actually launches WerTweak instead of WerFault, the duplicated handle values are only
     * valid in the context of the WerTweak child process and not in the WerFault grandchild process.
     * This causes WerFault to fail to properly handle the hung process and exit prematurely with an
     * exit code of 0x80070006 ("Invalid handle").
     * To fix this, we enumerate all object handles in the current process, check if they have the
     * 'inheritable' flag set, and if not, set the flag after all. This might seem like overkill, but
     * it's probably the only way to ensure that the duplicated handle values stay valid in
     * WerFault's context.
     */
    MakeAllOurObjectHandlesInheritable();

    // NOTE: bInheritHandles=TRUE is required for WerFault to function correctly! (and even more so
    // in the case of a hung process, see comment above)
    // TODO: disable debug heap (by setting _NO_DEBUG_HEAP environment variable)
    // TODO: use NtCreateUserProcess with IFEOSkipDebugger flag if WerFault.exe process runs as SYSTEM?
    if (!CreateProcess(NULL,
                       lpCmdLine,
                       NULL, NULL,
                       TRUE, /* bInheritHandles */
                       DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS,
                       NULL, NULL,
                       &startupInfo,
                       &procInfo))
    {
        DbgOut("CreateProcess failed (%u)", GetLastError());
        return 3;
    }

    if (!DebugSetProcessKillOnExit(FALSE))
    {
        DbgOut("DebugSetProcessKillOnExit failed! (%u)", GetLastError());
    }

    try
    {
        CWERFaultDLLInject dllInject(&procInfo.hProcess);

        /*
         * When a process crashes, Windows 10 starts two instances of WerFault.exe: one instance as
         * a SYSTEM process, and one instance as a regular user process. We're only interested in
         * hooking the user process, so exit if we're running as SYSTEM.
         */
        if (IsSystemSid((PSID)&procSid[0]))
        {
            DbgOut("Running as a SYSTEM process, exiting");
            goto exit;
        }

        /*
         * Run the debug loop. Note: for the WerFault.exe regular user process, using a debugger
         * loop is required for it to function correctly!
         */
        dllInject.Run();

        dwExitCode = dllInject.GetExitCode();
    }
    catch (CProcessDLLInjectError& error)
    {
        DbgOut("%hs", error.what());
        return 4;
    }
    catch (CWERFaultDLLInjectError& error)
    {
        DbgOut("%hs", error.what());
        return 5;
    }

    DbgOut("Done");

exit:

    CloseHandleSafe(&procInfo.hProcess);
    CloseHandleSafe(&procInfo.hThread);

    return dwExitCode;
}
