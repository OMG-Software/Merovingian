// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/homeserver/TlsConnection.hpp"

#include <optional>
#include <string>

namespace merovingian::homeserver
{

struct TlsConnectionResult final
{
    std::optional<TlsConnection> connection{};
    std::string error{};

    [[nodiscard]] auto ok() const noexcept -> bool;
};

} // namespace merovingian::homeserver
