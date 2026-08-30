// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/core/error.hpp"
#include "merovingian/core/secret_buffer.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace merovingian::appservice
{

// One entry of a `namespaces.{users,aliases,rooms}` array (Matrix v1.19
// Application Service API §Registration). `regex` is a POSIX regular
// expression, matched with `namespace_matches()` below. `exclusive` marks
// this namespace as reserved for this appservice: no other appservice or
// human user may create/delete entities matching it.
struct Namespace final
{
    bool exclusive{false};
    std::string regex{};
};

struct Namespaces final
{
    std::vector<Namespace> users{};
    std::vector<Namespace> aliases{};
    std::vector<Namespace> rooms{};
};

// A parsed appservice registration file (Matrix v1.19 Application Service
// API §Registration). `as_token`/`hs_token` are held in `core::SecretBuffer`
// per the project's secret-handling rules (see security/AGENTS.md,
// src/crypto/AGENTS.md): the raw bytes are mlocked and zeroised on
// destruction, and comparisons against a presented token MUST go through
// `crypto::constant_time_equal_variable_length`, never `==`.
//
// `url` is `std::nullopt` when the registration file set it to JSON `null`
// ("no traffic is required" per spec) — the homeserver never attempts an
// outbound call (transactions, queries, third-party lookups) to such an
// appservice.
//
// Registration files are parsed as JSON (see `parse_registration_json`
// below) rather than full YAML: the spec describes the format as "normally
// encoded as an object in a YAML file", and JSON is a strict subset of
// YAML 1.2, so a JSON registration file is a valid YAML registration file.
// Full YAML syntax (anchors, comments, unquoted scalars, flow-less block
// style) is NOT supported — see docs/user-manual.md "Application Service
// API" for the operator-facing note. This avoids pulling in a new
// third-party YAML dependency (with its own supply-chain pinning and
// license-review burden — see security/AGENTS.md) purely to parse a
// config artifact the project's own JSON parser already reads losslessly.
struct AppserviceRegistration final
{
    std::string id{};
    std::optional<std::string> url{};
    core::SecretBuffer as_token{};
    core::SecretBuffer hs_token{};
    std::string sender_localpart{};
    Namespaces namespaces{};
    std::vector<std::string> protocols{};
    bool rate_limited{true};
    bool receive_ephemeral{false};

    AppserviceRegistration() = default;
    AppserviceRegistration(AppserviceRegistration const&) = delete;
    auto operator=(AppserviceRegistration const&) -> AppserviceRegistration& = delete;
    AppserviceRegistration(AppserviceRegistration&&) noexcept = default;
    auto operator=(AppserviceRegistration&&) noexcept -> AppserviceRegistration& = default;
    ~AppserviceRegistration() = default;
};

// Result of parsing or loading one registration document: either a
// populated `value` (parsing succeeded) or an `error` describing why not.
// Not `std::expected<AppserviceRegistration, core::Error>` — this project's
// toolchain (clang + libstdc++, see docs/dev-environment.md) does not build
// `<expected>` cleanly, and no other module in the codebase uses it, so
// fallible operations here follow the same `optional value + separate
// error` shape used throughout config_parser.cpp and auth_service.cpp.
struct AppserviceRegistrationParseResult final
{
    std::optional<AppserviceRegistration> value{};
    core::Error error{};
};

// Parses one registration file's JSON text into an AppserviceRegistration.
// `result.error` (ErrorCode::parse_failure) describes the first problem
// found for a malformed document or a document missing a required field
// (`as_token`, `hs_token`, `id`, `sender_localpart`, `namespaces`, or `url`
// — `url` must be present as either a string or JSON `null`).
[[nodiscard]] auto parse_registration_json(std::string_view json_text) -> AppserviceRegistrationParseResult;

// Reads and parses the registration file at `path`. `result.error`
// (ErrorCode::io_failure) is set if the file cannot be opened/read,
// otherwise this defers to parse_registration_json.
[[nodiscard]] auto load_registration_file(std::string_view path) -> AppserviceRegistrationParseResult;

// Matches `value` against `pattern` as a POSIX extended regular expression
// (spec: "namespace ... regex: A POSIX regular expression"). Unanchored
// (equivalent to a substring search), matching common appservice-bridge
// registration conventions where the pattern itself supplies `^`/`$` when a
// full-string match is intended. An invalid `pattern` never throws — it is
// treated as matching nothing.
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

// Immutable, load-once collection of every registered appservice. Built at
// startup from `config::AppserviceConfig::registration_files` (see
// `load_registry`). Registrations are looked up by `as_token` under
// constant-time comparison, never by `==`/substring search, because the
// as_token is a bearer credential.
class AppserviceRegistry final
{
public:
    AppserviceRegistry() = default;
    explicit AppserviceRegistry(std::vector<AppserviceRegistration> registrations) noexcept;

    AppserviceRegistry(AppserviceRegistry const&) = delete;
    auto operator=(AppserviceRegistry const&) -> AppserviceRegistry& = delete;
    AppserviceRegistry(AppserviceRegistry&&) noexcept = default;
    auto operator=(AppserviceRegistry&&) noexcept -> AppserviceRegistry& = default;
    ~AppserviceRegistry() = default;

    [[nodiscard]] auto empty() const noexcept -> bool;
    [[nodiscard]] auto size() const noexcept -> std::size_t;
    [[nodiscard]] auto all() const noexcept -> std::vector<AppserviceRegistration> const&;

    // Constant-time lookup by presented as_token (a client-server bearer
    // token, or the `access_token` query parameter). Returns nullptr when no
    // registration's as_token matches.
    [[nodiscard]] auto find_by_as_token(std::string_view presented_token) const noexcept
        -> AppserviceRegistration const*;

    // Lookup by registration `id` (used by the client-server ping endpoint,
    // `POST /_matrix/client/v1/appservice/{appserviceId}/ping`). Not a
    // secret, so an ordinary comparison is fine.
    [[nodiscard]] auto find_by_id(std::string_view id) const noexcept -> AppserviceRegistration const*;

    // True when `value` falls in an EXCLUSIVE users namespace owned by an
    // appservice OTHER than `excluded_id` (pass an empty excluded_id to
    // check against every registered appservice). Used to enforce the
    // spec's cross-appservice/human exclusivity rule for registration and
    // alias creation.
    [[nodiscard]] auto user_namespace_exclusively_owned_by_other(std::string_view user_id,
                                                                 std::string_view excluded_id) const noexcept -> bool;
    [[nodiscard]] auto alias_namespace_exclusively_owned_by_other(std::string_view alias,
                                                                  std::string_view excluded_id) const noexcept -> bool;

private:
    std::vector<AppserviceRegistration> m_registrations{};
};

// Findings from validating a set of freshly-parsed registrations before
// they become an AppserviceRegistry: spec v1.19 "If the homeserver in
// question has multiple application services, each as_token and id MUST be
// unique per application service as these are used to identify the
// application service. The homeserver MUST enforce this."
struct AppserviceRegistrationFinding final
{
    std::string source{}; // file path, for operator diagnostics
    std::string message{};
};

// Validates `registrations` for duplicate `id`/`as_token` values (constant-
// time for as_token) and structurally invalid namespace regexes. Returns
// every problem found; an empty result means the set is safe to load.
[[nodiscard]] auto validate_registrations(std::vector<AppserviceRegistration> const& registrations)
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
struct LoadRegistrationsResult final
{
    AppserviceRegistry registry{};
    std::vector<AppserviceRegistrationFinding> findings{};
};

[[nodiscard]] auto load_registrations(std::vector<std::string> const& paths) -> LoadRegistrationsResult;

} // namespace merovingian::appservice
