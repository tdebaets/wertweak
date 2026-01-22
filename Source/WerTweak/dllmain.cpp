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
 * Defines the entry point for the WerTweak DLL
 *
 ****************************************************************************/

#include "pch.h"

#include "..\WerTweak.h"
#include "FaultRepHook.h"
#include "Processes.h"
#include "WERExportHook.h"
#include "WERFaultHook.h"
#include "WERHook.h"

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

    try
    {
        CWERFaultHook werFaultHook(GetModuleHandle(NULL));

        werFaultHook.HookWERFault();
    }
    catch (CPEModuleWalkerError & error)
    {
        DbgOut("Error walking WerFault.exe import modules: %hs", error.what());
    }

    hmodWer = GetModuleHandleA(g_szWerDllName);
    if (!hmodWer)
    {
        DbgOut("%hs module not loaded, exiting", g_szWerDllName);
        return;
    }

    try
    {
        CWERHook werHook(hmodWer);

        werHook.HookWER();
    }
    catch (CPEModuleWalkerError & error)
    {
        DbgOut("Error walking %hs import modules: %hs", g_szWerDllName, error.what());
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
            DbgOut("Error walking %hs import modules: %hs", g_szFaultRepDllName, error.what());
        }
    }
    else
    {
        DbgOut("Warning: %hs module not loaded", g_szFaultRepDllName);
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
