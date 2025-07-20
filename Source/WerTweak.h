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
 * Project-specific utility definitions
 *
 ****************************************************************************/

#pragma once

#include "Utils.h"

#undef DbgOut
#define DbgOut(kwszDebugFormatString, ...) \
    _DbgOut(L"WerTweak: " kwszDebugFormatString, __VA_ARGS__)

#define TRANSLATE_HPSS_SEGMENT_NAME ".thpss"

#define FACILITY_WERTWEAK 0x2DA // randomly generated

// Actual exception code value: 0x62DA1ECE
#define STATUS_TRANSLATE_PROCESS_SNAPSHOT_HANDLE            \
    MAKE_EXCEPTION_CODE(STATUS_SEVERITY_INFORMATIONAL,      \
                        FACILITY_WERTWEAK,                  \
                        0x1ECE /* randomly generated */)

#define TRANSLATE_PROCESS_SNAPSHOT_HANDLE_FLAG_SUPPRESS_DBG_OUTPUT  0x01

#define STATUS_TRANSLATE_PROCESS_SNAPSHOT_HANDLE_PARAM_PHANDLE      0
#define STATUS_TRANSLATE_PROCESS_SNAPSHOT_HANDLE_PARAM_FLAGS        1
#define STATUS_TRANSLATE_PROCESS_SNAPSHOT_HANDLE_PARAM_MAX_PLUS1    2 // always last
