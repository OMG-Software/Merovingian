// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>

namespace merovingian::events
{

// The forms a power level may take in a room version. Room versions 1-9 permit
// an integer encoded as a string (rooms/v10.md removed it), and 1-5 also permit a
// float, read by truncation (rooms/v3.md; v6 enforces Canonical JSON). Such
// events are valid: reading a value as absent would silently apply a default
// instead of the level the room actually set, so the encoding must follow the
// room's own version (power_level_encoding) rather than be chosen per call
// site. The parameters default to `integers` (strict) so a caller that has not
// considered the question gets the v10+ behaviour, not a more permissive one.
enum class PowerLevelEncoding : std::uint8_t
{
    integers,
    integers_or_strings,
    integers_strings_or_floats,
};

} // namespace merovingian::events
