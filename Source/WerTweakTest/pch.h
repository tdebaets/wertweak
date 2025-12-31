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
 * Pre-compiled header file for the WerTweak test application
 *
 ****************************************************************************/

#pragma once

#include "targetver.h"
#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
// Windows Header Files
#include <windows.h>
#include <DbgHelp.h>
#include <shlwapi.h>
#include <strsafe.h>
// C RunTime Header Files
#include <stdlib.h>
#include <malloc.h>
#include <memory.h>
#include <tchar.h>
#include <winternl.h>
#include <ProcessSnapshot.h>

#include <set>
#include <sstream>

using namespace std;
