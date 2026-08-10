// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/canonicaljson/value.hpp"

#include <string_view>

namespace merovingian::homeserver
{

// Matrix v1.19 CS API §push-notifications server-default push ruleset — the
// `content`/`override`/`room`/`sender`/`underride` arrays returned by
// GET /_matrix/client/v3/pushrules/ and GET .../pushrules/global/. `user_id`
// parameterises the handful of rules that reference the receiving user
// directly (`.m.rule.invite_for_me`'s state_key match, `.m.rule.is_user_mention`'s
// `content.m\.mentions.user_ids` match).
//
// Shared by client_server.cpp (which serves this verbatim to clients over
// GET /pushrules) and room_service.cpp (which parses it via
// push::parse_push_ruleset to gate real delivery), so the ruleset a client is
// told it has and the ruleset that actually decides whether a push fires can
// never drift apart. Merovingian does not yet persist per-user rule
// customisation (no PUT to /pushrules/... is implemented), so this default
// ruleset — not a stored one — is authoritative for every user.
[[nodiscard]] auto default_push_ruleset(std::string_view user_id) -> canonicaljson::Object;

} // namespace merovingian::homeserver
