// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>

namespace merovingian::homeserver
{

// Admission for remote media fetches handed to the media fetch pool (ADR-0121):
// running and queued fetches together, and of those, for one client.
struct MediaFetchAdmissionCaps final
{
    std::uint32_t global{0U};
    std::uint32_t per_client{0U};
};

} // namespace merovingian::homeserver
