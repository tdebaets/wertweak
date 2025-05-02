@echo off

rem **************************************************************************
rem *
rem *            WerTweak
rem *
rem *            Copyright (c) 2025 Tim De Baets
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
rem * Compile script
rem *
rem **************************************************************************

setlocal

for /F %%i in ('dir /b /a "common\*" 2^>NUL') do (
    rem common submodule folder not empty, ok
    goto common_ok
)

echo The common subdirectory was not found or is still empty.
echo Did you run postclone.bat yet?
goto failed2

:common_ok

rem Retrieve user-specific settings from file
call common\Scripts\getuserprefs.bat
if errorlevel 1 goto failed

cd Source
if errorlevel 1 goto failed

:msbuild

set SOLUTIONFILE=WerTweak.sln

call ..\common\Scripts\msbuild.bat %SOLUTIONFILE% Debug x86
if errorlevel 1 goto failed

call ..\common\Scripts\msbuild.bat %SOLUTIONFILE% Debug x64
if errorlevel 1 goto failed

call ..\common\Scripts\msbuild.bat %SOLUTIONFILE% Release x86
if errorlevel 1 goto failed

call ..\common\Scripts\msbuild.bat %SOLUTIONFILE% Release x64
if errorlevel 1 goto failed

echo:
echo Success!
cd ..
goto exit

:failed

echo *** FAILED ***
cd ..

:failed2

exit /b 1

:exit
