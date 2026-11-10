// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

// GHSA-3p5v-vrg8-f545 (ADR-0595): binding a federation worker's relays to the request main verified.
//
// A worker serving a forwarded request may relay four calls to main that reach data its own database role is
// denied: a one-time-key claim (which deletes keys), a device-keys query, a device list and a profile. Main admits
// such a relay only against a digest it computed itself from the request it forwarded, once. The argument each
// digest covers is extracted by the functions below, which the federation handlers also use, so the worker and
// main can never disagree about it.

#include "merovingian/federation/WorkerRelayKind.hpp"

#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace merovingian::federation
{

// The percent-decoded value of the first `name` parameter in the query string of `target`, or "" when absent.
[[nodiscard]] auto request_query_parameter(std::string_view target, std::string_view name) -> std::string;

// The user ID `GET /_matrix/federation/v1/user/devices/{userId}` names: the percent-decoded path segment after the
// prefix, the query string ignored. nullopt when the path is not that route's or names nothing.
[[nodiscard]] auto user_devices_path_user_id(std::string_view target) -> std::optional<std::string>;

// The digest a relay of `kind` carrying `argument` is admitted against. The kind's name and the argument's length
// are hashed ahead of it, and the preimage starts with "relay:", where an EDU digest's starts with a digit
// (edu_relay_digest), so no digest of one kind or of an EDU equals one of another. nullopt only if the hash fails.
[[nodiscard]] auto worker_relay_digest(WorkerRelayKind kind, std::string_view argument) -> std::optional<std::string>;

// The digests of the relays a worker may make while serving this request: one for a claim or keys query (its body),
// a device list (its user ID) or a profile query (its user_id), none for any other route or for a request whose
// argument cannot be read. Call it only for a request whose signature main verified.
[[nodiscard]] auto verified_request_relay_digests(std::string_view method, std::string_view target,
                                                  std::string_view body) -> std::vector<std::string>;

} // namespace merovingian::federation
