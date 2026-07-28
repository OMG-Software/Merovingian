// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/database/persistent_store.hpp"

#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace merovingian::federation
{

struct ServerAclEvent final
{
    std::vector<std::string> allow{};
    std::vector<std::string> deny{};
    bool allow_ip_literals{true};
};

enum class ServerAclDecision : std::uint8_t
{
    allow,
    deny,
};

struct ServerAclEvaluation final
{
    ServerAclDecision decision{ServerAclDecision::deny};
    std::string rule{};
    std::string reason{};
};

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

// Loads the current m.room.server_acl state event for a room and parses
// its content. Returns std::nullopt when the room has no ACL event.
[[nodiscard]] auto load_room_server_acl(database::PersistentStore const& store, std::string_view room_id)
    -> std::optional<ServerAclEvent>;

// Convenience: true when the server is allowed by the room's current ACL.
// Rooms with no ACL event allow all servers.
[[nodiscard]] auto room_server_acl_allows(database::PersistentStore const& store, std::string_view room_id,
                                          std::string_view server_name) -> bool;

} // namespace merovingian::federation
