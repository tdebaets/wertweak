@echo off

rem **************************************************************************
rem *
rem *            WerTweak
rem *
rem *            Copyright (c) 2020 Tim De Baets
rem *
rem **************************************************************************
rem *
rem * This Source Code Form is subject to the terms of the Mozilla Public
rem * License, v. 2.0. If a copy of the MPL was not distributed with this
rem * file, You can obtain one at https://mozilla.org/MPL/2.0/.
rem *
rem * This Source Code Form is "Incompatible With Secondary Licenses", as
rem * defined by the Mozilla Public License, v. 2.0.
rem *
rem **************************************************************************
rem *
rem * Post-build script for WerTweak DLL Visual Studio project
rem *
rem **************************************************************************

setlocal

set CONFIGURATION=%1
set PLATFORM=%2

set COMMONPATH=..\..\common
set OUTPATH=..\..\Output

if [%CONFIGURATION%] equ [] (
    goto usage
)

if [%PLATFORM%] equ [] (
    goto usage
)

if [%PLATFORM%] equ [Win32] (
    call %COMMONPATH%\Scripts\mycopy.bat ^
        "%OUTPATH%\%CONFIGURATION%\WerTweak.dll" "%OUTPATH%\x64\%CONFIGURATION%"
    if errorlevel 1 goto failed
)

goto exit

:usage
echo ERROR: usage: %~nx0 ^<configuration^> ^<platform^>

:failed
exit /b 1

:exit
