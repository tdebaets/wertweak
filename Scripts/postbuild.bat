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

set COMMONDIR=..\..\common
set OUTDIR=..\..\Output

set SRCDIR=%OUTDIR%\%CONFIGURATION%
set DSTDIR=%OUTDIR%\x64\%CONFIGURATION%

if [%CONFIGURATION%] equ [] (
    goto usage
)

if [%PLATFORM%] equ [] (
    goto usage
)

if [%PLATFORM%] equ [Win32] (
    call %COMMONDIR%\Scripts\createdir.bat "%DSTDIR%"
    if errorlevel 1 goto failed
    
    call %COMMONDIR%\Scripts\mycopy.bat "%SRCDIR%\WerTweak.dll" "%DSTDIR%"
    if errorlevel 1 goto failed
)

goto exit

:usage
echo ERROR: usage: %~nx0 ^<configuration^> ^<platform^>

:failed
exit /b 1

:exit
