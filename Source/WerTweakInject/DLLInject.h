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
 * Class for injecting the WerTweak DLL into the WerFault.exe process
 *
 ****************************************************************************/

#pragma once

#include "pch.h"

#include <ProcessDLLInject.h>

#include "..\WerTweak.h"

class CWERFaultDLLInjectInfo
{
public:

    CWERFaultDLLInjectInfo(WORD wImageFileMachine /* IMAGE_FILE_MACHINE_* */);

private:
    bool RetrieveInfo(LPCWSTR pszDLLName);

public: // TODO: improve? getters?

    wstring m_strFilename;
    DWORD   m_dwTranslateHpssSectionRVA;
    DWORD   m_dwTranslateHpssSectionSize;
};

class CWERFaultDLLInjectError : public runtime_error
{
public:
    CWERFaultDLLInjectError(const string &_Message) : runtime_error(_Message.c_str()) {}

    CWERFaultDLLInjectError(const char *_Message) : runtime_error(_Message) {}
};

class CWERFaultDLLInject : public CProcessDLLInject
{
public:

    CWERFaultDLLInject(const wstring   &strDLLFilename32,
                       const wstring   &strDLLFilename64);

    CWERFaultDLLInject(HANDLE          *phProcess);

    ~CWERFaultDLLInject();

    DWORD GetExitCode();

protected:

    /* CProcessDebug */

    virtual bool OnProcessCreate(DWORD                      dwProcessID,
                                 DWORD                      dwThreadID,
                                 CREATE_PROCESS_DEBUG_INFO *pInfo);

    virtual void OnProcessExit(DWORD                        dwProcessID,
                               EXIT_PROCESS_DEBUG_INFO     *pInfo);

    virtual void OnDbgOut(LPCWSTR wszFormat, va_list argList);

    /* CProcessDLLInject */

    virtual void OnException2(const tProcInfo              *pProcInfo,
                              DWORD                         dwThreadID,
                              EXCEPTION_DEBUG_INFO         *pInfo,
                              bool                         *pbExceptionHandled);

    virtual void OnDebugString2(const tProcInfo            *pProcInfo,
                                DWORD                       dwThreadID,
                                OUTPUT_DEBUG_STRING_INFO   *pInfo,
                                LPCWSTR                     wszDebugString);

private:

    void DuplicateAllOurProcessSnapshotHandles(HANDLE hTargetProcess);

    bool HandleTranslateProcessSnapshotHandle(const tProcInfo   *pProcInfo,
                                              PEXCEPTION_RECORD  pExceptionRecord);

private:

    HANDLE                  m_hProcess;

    CWERFaultDLLInjectInfo *m_pDLLInfo32;
    CWERFaultDLLInjectInfo *m_pDLLInfo64;

    DWORD                   m_dwExitCode;

    /*
     * Mapping of process snapshot handles in the context of the current process to snapshot handles
     * in the context of WerFault.exe. Used for translating these snapshot handles from the original
     * handle value to the duplicated handle value, see HandleTranslateProcessSnapshotHandle().
     */
    typedef std::map<HPSS, HPSS> tProcessSnapshotMap;
    tProcessSnapshotMap m_processSnapshotMap;

};
