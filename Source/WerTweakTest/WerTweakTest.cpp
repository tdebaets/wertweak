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
 * Main implementation of the WerTweak test application
 *
 ****************************************************************************/

#include "framework.h"
#include "WerTweakTest.h"

#include <WerApi.h>
#include <Wow64Utils.h>

#include "..\WerTweak\ProjectUtils.h"

#define MAX_LOADSTRING 100

#if _WIN64
static const LPCWSTR g_wszWerTweakStubDllName   = L"WerTweakStub64.dll";
static const LPCWSTR g_wszWerTweakDllName       = L"WerTweak64.dll";
#elif _WIN32
static const LPCWSTR g_wszWerTweakStubDllName   = L"WerTweakStub.dll";
static const LPCWSTR g_wszWerTweakDllName       = L"WerTweak.dll";
#endif

// Report name shouldn't be too long or else WerReportCreate() will fail
static const LPCWSTR g_wszWerReportName         = L"Dummy WER report created by WerTweak";

// Global Variables:
HINSTANCE hInst;                                // current instance
WCHAR szTitle[MAX_LOADSTRING];                  // The title bar text
WCHAR szWindowClass[MAX_LOADSTRING];            // the main window class name

// Forward declarations of functions included in this code module:
ATOM                MyRegisterClass(HINSTANCE hInstance);
BOOL                InitInstance(HINSTANCE, int);
LRESULT CALLBACK    WndProc(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK    About(HWND, UINT, WPARAM, LPARAM);

int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
                     _In_opt_ HINSTANCE hPrevInstance,
                     _In_ LPWSTR    lpCmdLine,
                     _In_ int       nCmdShow)
{
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);

    // Initialize global strings
    LoadStringW(hInstance, IDS_APP_TITLE, szTitle, MAX_LOADSTRING);
    LoadStringW(hInstance, IDC_WERTWEAKTEST, szWindowClass, MAX_LOADSTRING);
    MyRegisterClass(hInstance);

    // Perform application initialization:
    if (!InitInstance (hInstance, nCmdShow))
    {
        return FALSE;
    }

    HACCEL hAccelTable = LoadAccelerators(hInstance, MAKEINTRESOURCE(IDC_WERTWEAKTEST));

    MSG msg;

    // Main message loop:
    while (GetMessage(&msg, nullptr, 0, 0))
    {
        if (!TranslateAccelerator(msg.hwnd, hAccelTable, &msg))
        {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }

    return (int) msg.wParam;
}



//
//  FUNCTION: MyRegisterClass()
//
//  PURPOSE: Registers the window class.
//
ATOM MyRegisterClass(HINSTANCE hInstance)
{
    WNDCLASSEXW wcex;

    wcex.cbSize = sizeof(WNDCLASSEX);

    wcex.style          = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc    = WndProc;
    wcex.cbClsExtra     = 0;
    wcex.cbWndExtra     = 0;
    wcex.hInstance      = hInstance;
    wcex.hIcon          = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_WERTWEAKTEST));
    wcex.hCursor        = LoadCursor(nullptr, IDC_ARROW);
    wcex.hbrBackground  = (HBRUSH)(COLOR_WINDOW+1);
    wcex.lpszMenuName   = MAKEINTRESOURCEW(IDC_WERTWEAKTEST);
    wcex.lpszClassName  = szWindowClass;
    wcex.hIconSm        = LoadIcon(wcex.hInstance, MAKEINTRESOURCE(IDI_SMALL));

    return RegisterClassExW(&wcex);
}

//
//   FUNCTION: InitInstance(HINSTANCE, int)
//
//   PURPOSE: Saves instance handle and creates main window
//
//   COMMENTS:
//
//        In this function, we save the instance handle in a global variable and
//        create and display the main program window.
//
BOOL InitInstance(HINSTANCE hInstance, int nCmdShow)
{
   hInst = hInstance; // Store instance handle in our global variable

   HWND hWnd = CreateWindowW(
       szWindowClass,
       szTitle,
       WS_OVERLAPPEDWINDOW,
       CW_USEDEFAULT, CW_USEDEFAULT,
       400, 200,
       nullptr, nullptr, hInstance, nullptr);

   if (!hWnd)
   {
      return FALSE;
   }

   ShowWindow(hWnd, nCmdShow);
   UpdateWindow(hWnd);

   return TRUE;
}

void LoadWerTweakStub()
{
    LoadLibrary(g_wszWerTweakStubDllName);
}

void LoadWerTweak()
{
    LoadLibrary(g_wszWerTweakDllName);
}

void DoWerReportSubmit(HWND hWnd)
{
    WER_REPORT_INFORMATION  reportInfo  = {};
    WER_SUBMIT_RESULT       submitResult;
    HREPORT                 hReport     = 0;
    HRESULT                 hr          = E_FAIL;
    LPCWSTR                 wszFuncName = L"";

    reportInfo.dwSize = sizeof(reportInfo);
    
    GetModuleFileNameW(NULL, reportInfo.wzApplicationPath, ARRAYSIZE(reportInfo.wzApplicationPath));
    StringCchCopy(reportInfo.wzDescription, ARRAYSIZE(reportInfo.wzDescription), g_wszWerReportName);
    reportInfo.hwndParent = hWnd;

    hr = WerReportCreate(g_wszWerReportName, WerReportCritical, &reportInfo, &hReport);
    if (!SUCCEEDED(hr))
    {
        wszFuncName = L"WerReportCreate";
        goto exit;
    }

    hr = WerReportSubmit(hReport, WerConsentNotAsked, WER_SUBMIT_NO_ARCHIVE, &submitResult);
    if (!SUCCEEDED(hr))
    {
        wszFuncName = L"WerReportSubmit";
        goto exit;
    }

exit:

    if (hReport)
    {
        WerReportCloseHandle(hReport);
    }

    if (!SUCCEEDED(hr))
    {
        wostringstream oss;

        oss << wszFuncName << L" failed: 0x" << hex << hr;

        MessageBox(hWnd, oss.str().c_str(), NULL, MB_ICONERROR);
    }
}

void DoWerSetFlags(HWND hWnd)
{
    HRESULT hr = E_FAIL;

    //hr = WerSetFlags(0);
    SetErrorMode(SEM_NOGPFAULTERRORBOX);

    /*if (!SUCCEEDED(hr))
    {
        wostringstream oss;

        oss << L"WerSetFlags() failed: 0x" << hex << hr;

        MessageBox(hWnd, oss.str().c_str(), NULL, MB_ICONERROR);
    }*/
}
#define ProcessDefaultHardErrorMode ((PROCESSINFOCLASS)12)

void DoGetProcessErrorMode(HWND hWnd)
{
    HRESULT     hr              = E_FAIL;
    NTSTATUS    status          = 0;
    HANDLE      hProcess        = 0;
    DWORD       dwWerFlags      = 0;
    DWORD       dwRestartFlags  = 0;
    DWORD       dwSize          = 0;
    DWORD       dwPingInterval  = 0;
    UINT        uMode           = 0;
    PVOID       pvRecoveryParam = NULL;
    WCHAR       wzCmdLine[RESTART_MAX_CMD_LINE];
    APPLICATION_RECOVERY_CALLBACK recoveryCb = NULL;

    dwSize = ARRAYSIZE(wzCmdLine);

    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, 17448);
    if (!hProcess)
        goto exit;

    status = NtQueryInformationProcess(hProcess,
                                       ProcessDefaultHardErrorMode,
                                       &uMode, sizeof(uMode),
                                       NULL);
    if (!NT_SUCCESS(status))
        goto exit;

    hr = WerGetFlags(hProcess, &dwWerFlags);
    if (!SUCCEEDED(hr))
        goto exit;

    DbgOut("Error mode: %u, WER flags: %x", uMode, dwWerFlags);

    hr = GetApplicationRestartSettings(hProcess, wzCmdLine, &dwSize, &dwRestartFlags);
    if (!SUCCEEDED(hr))
        goto exit;

    DbgOut("Restart command line: %ws, flags: %u", wzCmdLine, dwRestartFlags);

    hr = GetApplicationRecoveryCallback(hProcess,
                                        &recoveryCb,
                                        &pvRecoveryParam,
                                        &dwPingInterval,
                                        NULL);
    if (!SUCCEEDED(hr))
        goto exit;

    DbgOut("Restart recovery callback: %p, param: %p, ping interval: %u",
           recoveryCb,
           pvRecoveryParam,
           dwPingInterval);

exit:

    CloseHandleSafe(&hProcess);
}

void DoRegisterAppRestart(HWND hWnd)
{
    HRESULT hr = E_FAIL;

    hr = RegisterApplicationRestart(L"/restart", 0);
    if (!SUCCEEDED(hr))
    {
        wostringstream oss;

        oss << L"RegisterApplicationRestart() failed: 0x" << hex << hr;

        MessageBox(hWnd, oss.str().c_str(), NULL, MB_ICONERROR);
    }
}

void DoCrash()
{
    LPDWORD *pdwTest = NULL;

    *pdwTest = 0;
}

void DoWow64GetKnownDllProcAddress(HWND hWnd)
{
    TCHAR message[64];

    FARPROC pAddress = Wow64GetKnownDllProcAddress("kernel32.dll", "LoadLibraryW");
    //FARPROC pAddress = Wow64GetKnownDllProcAddress("kernel32.dll", "HeapAlloc");

    StringCbPrintf(message, sizeof(message), TEXT("0x%p"), pAddress);

    MessageBox(hWnd, message, NULL, MB_OK);
}

//
//  FUNCTION: WndProc(HWND, UINT, WPARAM, LPARAM)
//
//  PURPOSE: Processes messages for the main window.
//
//  WM_COMMAND  - process the application menu
//  WM_PAINT    - Paint the main window
//  WM_DESTROY  - post a quit message and return
//
//
LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message)
    {
    case WM_COMMAND:
        {
            int wmId = LOWORD(wParam);
            // Parse the menu selections:
            switch (wmId)
            {
            case IDM_LOAD_STUB_DLL:
                LoadWerTweakStub();
                break;
            case IDM_LOAD_DLL:
                LoadWerTweak();
                break;
            case IDM_WER_REPORT_SUBMIT:
                DoWerReportSubmit(hWnd);
                break;
            case IDM_WER_SET_FLAGS:
                DoWerSetFlags(hWnd);
                break;
            case IDM_GET_PROCESS_ERROR_MODE:
                DoGetProcessErrorMode(hWnd);
                break;
            case IDM_WOW64_GET_KNOWNDLL_PROCADDR:
                DoWow64GetKnownDllProcAddress(hWnd);
                break;
            case IDM_REGISTER_APP_RESTART:
                DoRegisterAppRestart(hWnd);
                break;
            case IDM_ABOUT:
                DialogBox(hInst, MAKEINTRESOURCE(IDD_ABOUTBOX), hWnd, About);
                break;
            case IDM_EXIT:
                DestroyWindow(hWnd);
                break;
            case IDM_CRASH:
                DoCrash();
                break;
            default:
                return DefWindowProc(hWnd, message, wParam, lParam);
            }
        }
        break;
    case WM_PAINT:
        {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hWnd, &ps);
            // TODO: Add any drawing code that uses hdc here...
            EndPaint(hWnd, &ps);
        }
        break;
    case WM_DESTROY:
        PostQuitMessage(0);
        break;
    default:
        return DefWindowProc(hWnd, message, wParam, lParam);
    }
    return 0;
}

// Message handler for about box.
INT_PTR CALLBACK About(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    UNREFERENCED_PARAMETER(lParam);
    switch (message)
    {
    case WM_INITDIALOG:
        return (INT_PTR)TRUE;

    case WM_COMMAND:
        if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL)
        {
            EndDialog(hDlg, LOWORD(wParam));
            return (INT_PTR)TRUE;
        }
        break;
    }
    return (INT_PTR)FALSE;
}
