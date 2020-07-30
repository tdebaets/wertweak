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
 * Implementation of IAT hook of wer.dll
 *
 ****************************************************************************/

#include "pch.h"

#include <DelayLoadUtils.h>

#include "PEUtils.h"
#include "ProjectUtils.h"
#include "WERHook.h"
#include "WERUIHook.h"

// Undocumented flag for WerReportSubmit
// TODO: research if not known anywhere
#define WER_SUBMIT_PROCESS_IS_IMMERSIVE_BROKER  0x00080000 // PROCESS_UICONTEXT_IMMERSIVE_BROKER
#define WER_SUBMIT_PROCESS_IS_IMMERSIVE         0x00100000 // PROCESS_UICONTEXT_IMMERSIVE

static const LPCSTR g_szWERDllName          = "wer.dll";
static const LPCSTR g_szWERReportSubmitName = "WerReportSubmit";

PRESOLVE_DELAY_LOADED_API   g_pWERPrevResolveDelayLoadedAPI = NULL;
PVOID                       g_pPrevWerReportSubmit          = NULL;

typedef HRESULT (WINAPI *PWER_REPORT_SUBMIT) (HREPORT               hReportHandle,
                                              WER_CONSENT           consent,
                                              DWORD                 dwFlags,
                                              PWER_SUBMIT_RESULT    pSubmitResult);

HRESULT NewWerReportSubmit(HREPORT               hReportHandle,
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

void WERTryHookDelayLoadImport(PVOID               ParentModuleBase,
                               PIMAGE_THUNK_DATA   ThunkAddress,
                               PIMAGE_THUNK_DATA   pAddrThunk,
                               PIMAGE_THUNK_DATA   pNameThunk,
                               PVOID              *ppImportAddress)
{
    PIMAGE_IMPORT_BY_NAME pImportName = NULL;

    if (!pAddrThunk->u1.AddressOfData || !pNameThunk->u1.AddressOfData)
        return;

    if ((pNameThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) == 0)
    {
        // import by name

        pImportName = (PIMAGE_IMPORT_BY_NAME)RVAToAbsolute(ParentModuleBase,
                                                           pNameThunk->u1.AddressOfData);

        if (lstrcmpiA(pImportName->Name, g_szWerUiCreateName) == 0)
        {
            // TODO: add error checking
            PatchImport(pAddrThunk, NewWerUICreate, (PVOID *)&g_pPrevWerUICreate);

            // If ResolveDelayLoadedAPI was called for this specific import, we need to pass back
            // the hook address for the ResolveDelayLoadedAPI hook function to put the address in
            // its return value.
            if (ThunkAddress == pAddrThunk)
            {
                *ppImportAddress = NewWerUICreate;
            }
        }
    }
}

// TODO: make common?
PVOID WINAPI WERNewResolveDelayLoadedAPI(PVOID                             ParentModuleBase,
                                         PCIMAGE_DELAYLOAD_DESCRIPTOR      DelayloadDescriptor,
                                         PDELAYLOAD_FAILURE_DLL_CALLBACK   FailureDllHook,
                                         PVOID                             FailureSystemHook,
                                         PIMAGE_THUNK_DATA                 ThunkAddress,
                                         ULONG                             Flags)
{
    PIMAGE_THUNK_DATA   pAddrThunk      = NULL;
    PIMAGE_THUNK_DATA   pNameThunk      = NULL;
    PVOID               pImportAddress  = NULL;
    const char         *dllName         = NULL;

    pImportAddress = g_pWERPrevResolveDelayLoadedAPI(ParentModuleBase,
                                                     DelayloadDescriptor,
                                                     FailureDllHook,
                                                     FailureSystemHook,
                                                     ThunkAddress,
                                                     Flags);

    if (!CheckResolveDelayLoadedAPIResult(ParentModuleBase, DelayloadDescriptor, ThunkAddress))
        return pImportAddress;

    dllName = (const char *)RVAToAbsolute(ParentModuleBase, DelayloadDescriptor->DllNameRVA);

    if (lstrcmpiA(dllName, g_szWerUiApiSetName) == 0)
    {
        pAddrThunk =
            (PIMAGE_THUNK_DATA)RVAToAbsolute(ParentModuleBase,
                                             DelayloadDescriptor->ImportAddressTableRVA);
        pNameThunk =
            (PIMAGE_THUNK_DATA)RVAToAbsolute(ParentModuleBase,
                                             DelayloadDescriptor->ImportNameTableRVA);

        while (pAddrThunk->u1.AddressOfData && pNameThunk->u1.AddressOfData)
        {
            WERTryHookDelayLoadImport(ParentModuleBase,
                                      ThunkAddress,
                                      pAddrThunk,
                                      pNameThunk,
                                      &pImportAddress);

            pAddrThunk++;
            pNameThunk++;
        }
    }

    return pImportAddress;
}

void CWERHook::HookWER()
{
    WalkImportModules();
}

void CWERHook::PatchImportedModule(PIMAGE_THUNK_DATA pOrigFirstThunk,
                                   PIMAGE_THUNK_DATA pFirstThunk)
{
    PIMAGE_THUNK_DATA pOrigThunk    = pOrigFirstThunk;
    PIMAGE_THUNK_DATA pThunk        = pFirstThunk;

    while (pOrigThunk->u1.AddressOfData && pThunk->u1.AddressOfData)
    {
        PIMAGE_IMPORT_BY_NAME   pImport     = NULL;
        const char             *importName  = NULL;

        pImport     = (PIMAGE_IMPORT_BY_NAME)RVAToAbsolute(pOrigThunk->u1.AddressOfData);
        importName  = pImport->Name;

        if (lstrcmpA(importName, g_szResolveDelayLoadedAPIName) == 0)
        {
            // TODO: add error checking
            PatchImport(pThunk,
                        WERNewResolveDelayLoadedAPI,
                        (PVOID *)&g_pWERPrevResolveDelayLoadedAPI);
        }

        pOrigThunk++;
        pThunk++;
    }
}

bool CWERHook::ImportModuleProc(PIMAGE_IMPORT_DESCRIPTOR  pImpDesc,
                                const char               *name)
{
    PIMAGE_THUNK_DATA pOrigFirstThunk   = NULL;
    PIMAGE_THUNK_DATA pFirstThunk       = NULL;

    if (lstrcmpiA(name, g_szDelayLoadApiSetName) == 0)
    {
        pOrigFirstThunk = (PIMAGE_THUNK_DATA)RVAToAbsolute(pImpDesc->OriginalFirstThunk);
        pFirstThunk     = (PIMAGE_THUNK_DATA)RVAToAbsolute(pImpDesc->FirstThunk);

        PatchImportedModule(pOrigFirstThunk, pFirstThunk);
    }

    return true;
}
