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
 * Defines the entry point for the WerTweak stub DLL
 *
 ****************************************************************************/

#include "pch.h"
#include "Utils.h"

static const LPCWSTR g_szWerFaultExeName = L"WerFault.exe";
//static const LPCWSTR g_szWerFaultExeName = L"WerTweakTest.exe";

#if _WIN64
static const LPCWSTR g_szWerTweakDllName = L"WerTweak64.dll";
#elif _WIN32
static const LPCWSTR g_szWerTweakDllName = L"WerTweak.dll";
#endif

void HandleProcessAttach(HMODULE hModule)
{
    wstring exeFileName;

    DisableThreadLibraryCalls(hModule); // optimization

    exeFileName = GetModuleName(NULL);
    //DbgOut(L"%s", exeFileName.c_str());

    PathStripPath(&exeFileName[0]);
    exeFileName.resize(lstrlenW(exeFileName.c_str()));
    
    if (lstrcmpiW(exeFileName.c_str(), g_szWerFaultExeName) == 0)
    {
        wstring         ourDllFileName = GetModuleName(hModule);
        wostringstream  oss;

        PathRemoveFileSpec(&ourDllFileName[0]);
        ourDllFileName.resize(lstrlenW(ourDllFileName.c_str()));

        oss << ourDllFileName << L"\\" << g_szWerTweakDllName;

        DbgOut(L"%s", oss.str().c_str());

        LoadLibrary(oss.str().c_str());
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
