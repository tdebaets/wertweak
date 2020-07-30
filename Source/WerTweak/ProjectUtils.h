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
