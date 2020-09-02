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
 * Defines the entry point for the WerTweak DLL
 *
 ****************************************************************************/

#include "pch.h"

#include "FaultRepHook.h"
#include "Processes.h"
#include "ProjectUtils.h"
#include "WERExportHook.h"
#include "WERHook.h"

// TODO: remove topmost extended style from crash report dialogs?
// TODO: create new library for common includes
// TODO: rename or move all framework.h files to a single pch.h file for each project (https://docs.microsoft.com/en-us/windows/uwp/cpp-and-winrt-apis/get-started)
// TODO: make sure that the WER DontShowUI policy is also set to disabled (otherwise there's no UI at all)
//   HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting\DontShowUI
//   "Disabled" value in same key should also be set to 0
// Should also be set to value 1:
//  HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection\AllowTelemetry
// TODO: try to fix double report on Explorer.exe crash (might be related to Symantec Endpoint Protection)

static const LPCSTR g_szFaultRepDllName = "faultrep.dll";

void HandleProcessAttach(HMODULE hModule)
{
    SidWrapper  procSid;
    HMODULE     hmodWer         = NULL;
    HMODULE     hmodFaultRep    = NULL;

    DbgOut("WerTweak start"); // TODO: remove?

    if (!GetProcessSid(GetCurrentProcessId(), GetCurrentProcess(), procSid))
    {
        DbgOut("Failed to get our process SID, exiting");
        return;
    }

    /*
     * When a process crashes, Windows 10 starts two instances of WerFault.exe:
     * one instance as a SYSTEM process, and one instance as a regular user
     * process. We're only interested in hooking the user process, so exit if
     * we're running as SYSTEM.
     */
    if (IsSystemSid((PSID)&procSid[0]))
    {
        DbgOut("Running as a SYSTEM process, exiting");
        return;
    }

    hmodWer = GetModuleHandleA(g_szWerDllName);
    if (!hmodWer)
    {
        DbgOut("%s module not loaded, exiting", g_szWerDllName);
        return;
    }

    try
    {
        CWERHook werHook(hmodWer);

        werHook.HookWER();
    }
    catch (CPEModuleWalkerError & error)
    {
        DbgOut("Error walking %s import modules: %s", g_szWerDllName, error.what());
    }

    hmodFaultRep = GetModuleHandleA(g_szFaultRepDllName);
    if (hmodFaultRep)
    {
        try
        {
            CFaultRepHook faultRepHook(hmodFaultRep);

            faultRepHook.HookFaultRep();
        }
        catch (CPEModuleWalkerError & error)
        {
            DbgOut("Error walking %s import modules: %s", g_szFaultRepDllName, error.what());
        }
    }
    else
    {
        DbgOut("Warning: %s module not loaded", g_szFaultRepDllName);
    }
}

BOOL APIENTRY DllMain(HMODULE   hModule,
                      DWORD     ul_reason_for_call,
                      LPVOID    lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        HandleProcessAttach(hModule);
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
