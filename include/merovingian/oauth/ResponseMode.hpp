// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>

namespace merovingian::oauth
{

// Where an authorisation answer travels to the client's redirect URI (spec "Login flow", `response_mode`): in the
// query string or in the fragment. The two values `response_modes_supported` advertises.
enum class ResponseMode : std::uint8_t
{
    query,
    fragment,
};

} // namespace merovingian::oauth
