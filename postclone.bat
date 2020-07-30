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
rem * One-time script to run after cloning the repository
rem *
rem **************************************************************************

setlocal

echo Initializing and updating submodules...

git submodule init
if errorlevel 1 goto failed

git submodule update
if errorlevel 1 goto failed

call .\common\Scripts\setuprepo.bat %*
if errorlevel 1 goto failed

set REPONAME=
for /f %%i in ('.\common\Scripts\getreponame.bat') do (
    set REPONAME=%%i
)

echo %REPONAME%: creating directories...

call .\common\Scripts\createdir.bat "Output"
if errorlevel 1 goto failed

echo Success!
goto exit

:failed
echo *** FAILED ***
:failed2
exit /b 1

:exit
