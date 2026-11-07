// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>

namespace merovingian::identity
{

// Parsed `GET /_matrix/identity/v2/3pid/getValidated3pid` response (200): the
// identity server's statement that the session was validated, for which 3PID
// and when. All three fields are mandatory in the spec; `validated_at_ms` is a
// positive millisecond timestamp.
struct ValidatedThreepid final
{
    std::string medium{};
    std::string address{};
    std::uint64_t validated_at_ms{0U};
};

} // namespace merovingian::identity
