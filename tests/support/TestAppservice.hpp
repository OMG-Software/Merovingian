// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <optional>
#include <string>
#include <vector>

namespace merovingian::tests
{

struct TestAppservice final
{
    std::string id{"bridge"};
    // The registration's `url`; nullopt writes `url: null` ("no traffic is required").
    std::optional<std::string> url{};
    // POSIX ERE patterns; an empty string leaves that namespace out.
    std::string users_regex{};
    std::string aliases_regex{};
    std::string rooms_regex{};
    std::vector<std::string> protocols{};
    bool receive_ephemeral{false};

    [[nodiscard]] auto as_token() const -> std::string
    {
        return "as-token-" + id;
    }

    [[nodiscard]] auto hs_token() const -> std::string
    {
        return "hs-token-" + id;
    }
};

} // namespace merovingian::tests
