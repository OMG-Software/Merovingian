// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/persistent_store.hpp"
#include "merovingian/push/push_rules.hpp"
#include "merovingian/push/user_push_rules.hpp"

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>

namespace merovingian::homeserver
{

// The global account-data type a user's push rules are kept under (R19, ADR-0204). Spec
// (client-server-api.md, "Push Rules: Events"): "When a user changes their push rules a
// m.push_rules event is sent to all clients in the account_data section of their next /sync
// request. The content of the event is the current push rules for the user." Clients may read it
// but not set it: PUT /account_data/m.push_rules is refused with 405 ("Server Behaviour" of
// Client Config).
inline constexpr auto push_rules_account_data_type = std::string_view{"m.push_rules"};

// `user_id`'s push rules: the server defaults with the user's stored `m.push_rules` applied
// (see push::UserPushRules). A user with no stored rules, or whose stored content is not an
// object with a `global` object, has the server defaults. Reads only the in-memory store, so it is
// safe under runtime.mutex.
[[nodiscard]] auto load_user_push_rules(database::PersistentStore const& store, std::string_view user_id,
                                        std::size_t max_user_rules) -> push::UserPushRules;

// The same rules parsed for evaluation (push::evaluate_push_rules).
[[nodiscard]] auto load_push_ruleset(database::PersistentStore const& store, std::string_view user_id,
                                     std::size_t max_user_rules) -> push::PushRuleset;

// The `m.push_rules` account-data content for `rules`: `{"global": rules.ruleset()}` in canonical
// JSON, or nullopt if it cannot be serialised.
[[nodiscard]] auto push_rules_account_data_content(push::UserPushRules const& rules) -> std::optional<std::string>;

} // namespace merovingian::homeserver
