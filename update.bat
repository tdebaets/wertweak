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
rem * Script to update the repository to the latest changes
rem *
rem **************************************************************************

setlocal

for /F %%i in ('dir /b /a "common\*" 2^>NUL') do (
    rem common submodule folder not empty, ok
    goto do_update
)

echo The common subdirectory was not found or is still empty.
echo Did you run postclone.bat yet?
goto failed

:do_update

rem Intentionally not using 'call' here because this script should stop
rem executing. Otherwise, strange effects can occur if this script gets updated
rem while it is being executed!
.\common\Scripts\updaterepo.bat %*

rem If any processing is needed after the update, it should be added to the
rem Scripts\postupdate.bat file

echo ERROR: We should never get here!
goto failed

:failed
exit /b 1

:exit
