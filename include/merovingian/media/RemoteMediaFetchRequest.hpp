// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>
#include <vector>

namespace merovingian::media
{

struct RemoteMediaFetchRequest final
{
    std::string origin_server{};
    std::string media_id{};
    std::string resolved_host{};
    std::vector<std::string> resolved_addresses{};
    bool isolate_remote_media{true};
    bool private_address_fetches_blocked{true};
    // security.federation.allow_private_ip_ranges (ADR-0231).
    std::vector<std::string> allowed_private_ranges{};
};

} // namespace merovingian::media
