// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <optional>
#include <string>
#include <utility>

namespace merovingian::homeserver
{

// Which rooms are listed: the homeserver's own published directory by default; one third-party network's
// when a request names it with `third_party_instance_id`; both, plus every network's, with
// `include_all_networks`.
struct PublicRoomsScope final
{
    bool include_all_networks{false};
    // The (appservice id, protocol) a `third_party_instance_id` resolved to; empty strings for an id that
    // names no network, which lists nothing.
    std::optional<std::pair<std::string, std::string>> network{};
};

} // namespace merovingian::homeserver
