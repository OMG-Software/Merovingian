// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/canonicaljson/Value.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/federation/ServerAclBudget.hpp"
#include "merovingian/federation/ServerAclEvaluation.hpp"
#include "merovingian/federation/ServerAclEvent.hpp"

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace merovingian::federation
{

// The most patterns (allow and deny together) and the longest pattern an ACL may hold to be evaluated. A server name is
// at most 255 bytes and the event is at most 64 KiB; an ACL past either cap refuses every server (ADR-0640).
inline constexpr auto server_acl_max_patterns = std::size_t{4096U};
inline constexpr auto server_acl_max_pattern_length = std::size_t{255U};

// The glob steps one ACL check may spend over all of its patterns. A real ACL needs about the pattern count times the
// server name length (4096 patterns against a 24-character name is about 100,000); past this the check stops and
// refuses the server (ADR-0640, ADR-0653). A request spends from a ServerAclBudget as well.
inline constexpr auto server_acl_max_glob_steps = std::size_t{100'000U};

// Parses the content of an m.room.server_acl state event. Missing or
// malformed fields fall back to the spec defaults (empty lists, allow
// IP literals), so a malformed ACL event is still enforceable.
[[nodiscard]] auto parse_server_acl(canonicaljson::Value const& content) -> ServerAclEvent;

// Returns the server name with any trailing port stripped. IPv6 literals
// are expected in bracketed form (e.g. "[::1]:8448" -> "[::1]") per the
// Matrix server-name grammar.
[[nodiscard]] auto strip_server_port(std::string_view server_name) noexcept -> std::string;

// True when the server name (after port stripping and bracket removal)
// is a syntactically valid IPv4 or IPv6 address literal.
[[nodiscard]] auto server_name_is_ip_literal(std::string_view server_name) noexcept -> bool;

// Evaluates the ACL rules from Matrix v1.19 CS API §Server Access Control
// Lists against a single server name. The server name's port is ignored.
[[nodiscard]] auto evaluate_server_acl(std::string_view server_name, ServerAclEvent const& acl) -> ServerAclEvaluation;

// As above, spending from `budget`, which the caller shares across every check of one EDU or request (ADR-0653).
[[nodiscard]] auto evaluate_server_acl(std::string_view server_name, ServerAclEvent const& acl, ServerAclBudget& budget)
    -> ServerAclEvaluation;

// Loads the current m.room.server_acl state event for a room and parses
// its content. Returns std::nullopt when the room has no ACL event.
[[nodiscard]] auto load_room_server_acl(database::PersistentStore const& store, std::string_view room_id)
    -> std::optional<ServerAclEvent>;

// Convenience: true when the server is allowed by the room's current ACL.
// Rooms with no ACL event allow all servers.
[[nodiscard]] auto room_server_acl_allows(database::PersistentStore const& store, std::string_view room_id,
                                          std::string_view server_name) -> bool;

// As above, for a request that checks several rooms or servers: every check spends from the one `budget`, and the
// answer for an (ACL event, server name) pair is remembered, so asking again costs no glob step (ADR-0653). The cache
// has its own mutex, so a check may run under any lock.
[[nodiscard]] auto room_server_acl_allows(database::PersistentStore const& store, std::string_view room_id,
                                          std::string_view server_name, ServerAclBudget& budget) -> bool;

} // namespace merovingian::federation
