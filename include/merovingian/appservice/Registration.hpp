// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/appservice/AppserviceRegistration.hpp"
#include "merovingian/appservice/AppserviceRegistrationFinding.hpp"
#include "merovingian/appservice/AppserviceRegistrationParseResult.hpp"
#include "merovingian/appservice/EventInterestFacts.hpp"
#include "merovingian/appservice/LoadRegistrationsResult.hpp"
#include "merovingian/appservice/Namespace.hpp"

#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

namespace merovingian::appservice
{

// Parses one registration file's JSON text into an AppserviceRegistration.
// `result.error` (ErrorCode::parse_failure) describes the first problem
// found for a malformed document or a document missing a required field
// (`as_token`, `hs_token`, `id`, `sender_localpart`, `namespaces`, or `url`
// — `url` must be present as either a string or JSON `null`).
[[nodiscard]] auto parse_registration_json(std::string_view json_text) -> AppserviceRegistrationParseResult;

// Parses one registration file's YAML text into an AppserviceRegistration.
// This is the format the spec's own example uses and the format real bridges
// ship (`registration.yaml`): 2-space-indented block maps and lists, plain
// and quoted scalars, `#` comments, `null`/`~`. It is a strict bounded
// subset, not a general YAML parser — anchors, aliases, tags, flow
// collections, block scalars, tabs and document markers are parse failures
// rather than being silently coerced, and the input is bounded (256 KiB
// file, 4 KiB line, 64 namespace entries, 32 protocols) because a
// registration file is operator-authored configuration.
[[nodiscard]] auto parse_registration_yaml(std::string_view contents) -> AppserviceRegistrationParseResult;

// Reads and parses the registration file at `path`. `result.error`
// (ErrorCode::io_failure) is set if the file cannot be opened/read,
// otherwise this defers to parse_registration_json.
[[nodiscard]] auto load_registration_file(std::string_view path) -> AppserviceRegistrationParseResult;

// The longest identifier a namespace is matched against: the spec's limit for a user ID and a room alias. std::regex
// recurses on its input, so nothing longer reaches it (ADR-0613).
inline constexpr std::size_t max_namespace_match_input_bytes = 255U;

// Matches `value` against `pattern` as a POSIX extended regular expression
// (spec: "namespace ... regex: A POSIX regular expression"), over the whole
// identifier (std::regex_match): an unanchored search would let `@_irc_.*`
// also claim `@evil@_irc_bob:example.org`. An invalid `pattern` never throws —
// it is treated as matching nothing, and so is a `value` over
// max_namespace_match_input_bytes. This compiles `pattern` on every call;
// request paths match through a Namespace, whose pattern is compiled once.
[[nodiscard]] auto namespace_matches(std::string_view pattern, std::string_view value) noexcept -> bool;

// True when `value` matches at least one namespace entry in `namespaces`.
[[nodiscard]] auto any_namespace_matches(std::vector<Namespace> const& namespaces, std::string_view value) noexcept
    -> bool;

// True when `value` matches at least one *exclusive* namespace entry.
// Used to enforce Matrix v1.19's "exclusive namespace" rule: an exclusive
// namespace blocks creation/deletion of matching entities by anyone other
// than the owning appservice.
[[nodiscard]] auto any_exclusive_namespace_matches(std::vector<Namespace> const& namespaces,
                                                   std::string_view value) noexcept -> bool;

// The full Matrix user ID of the appservice's own bot user
// (`@<sender_localpart>:<server_name>`).
[[nodiscard]] auto sender_user_id(AppserviceRegistration const& registration, std::string_view server_name)
    -> std::string;

// True when `user_id` is covered by this appservice: either it IS the
// appservice's own sender_localpart user, or it matches one of the
// appservice's `users` namespaces.
[[nodiscard]] auto appservice_owns_user(AppserviceRegistration const& registration, std::string_view server_name,
                                        std::string_view user_id) noexcept -> bool;

// True when `registration` is interested in an event that occurred in a
// room, per Matrix v1.19 Application Service API §"Registration": "An
// application service is said to be 'interested' in a given event if it
// matches any of the namespaces" — `rooms`/`aliases` namespaces match "all
// events in a matching room"; the `users` namespace (and the appservice's
// own sender_localpart, which is always implicitly covered — see
// appservice_owns_user) matches when "a local user matching one of the
// namespaces is the target of the event, or is a joined member of the room
// where the event occurred." The target of a membership event is its
// `state_key` (an invite names the invitee there, who is not yet joined), the
// sender is also a user the event is about, and only LOCAL users count: "Events
// affecting users on other homeservers are not sent to an application service,
// even if the user happens to match one of the users namespaces" unless the
// room is of interest for another reason.
[[nodiscard]] auto registration_interested_in_room_event(AppserviceRegistration const& registration,
                                                         std::string_view server_name,
                                                         EventInterestFacts const& facts) noexcept -> bool;

// Validates `registrations` for duplicate `id`/`as_token` values (constant-
// time for as_token) and structurally invalid namespace regexes. Returns
// every problem found; an empty result means the set is safe to load.
// `server_name` builds each registration's sender user id so it can be checked
// against the other registrations' exclusive namespaces; pass the homeserver's
// own name. An empty `server_name` skips only that check.
[[nodiscard]] auto validate_registrations(std::vector<AppserviceRegistration> const& registrations,
                                          std::string_view server_name = {})
    -> std::vector<AppserviceRegistrationFinding>;

// Loads and validates every registration file named in `paths`, in order.
// A file that fails to load or parse is recorded in `findings` and
// skipped (fail-closed per-file, not fail-closed for the whole server —
// one operator typo in one bridge's file must not prevent every other
// appservice, or the rest of the homeserver, from starting). The returned
// registry contains only the registrations that parsed AND passed
// cross-registration validation (duplicate id/as_token); when a duplicate
// is found, every registration is dropped and the problem is recorded,
// since the spec-mandated uniqueness makes a duplicate a fail-closed
// condition (routing further requests would be ambiguous).
//
// ADR-0515: a registration whose non-null `url` is not a valid http(s) url, has a query string, or is
// `http` to a host that is neither a loopback IP literal nor in `allowed_cleartext_hosts`
// (`appservice.allow_cleartext_hosts`) is rejected as a per-file finding, because the hs_token is sent
// to that url in every request. The finding names the problem and never contains a token or the url.
[[nodiscard]] auto load_registrations(std::vector<std::string> const& paths, std::string_view server_name = {},
                                      std::vector<std::string> const& allowed_cleartext_hosts = {})
    -> LoadRegistrationsResult;

} // namespace merovingian::appservice
