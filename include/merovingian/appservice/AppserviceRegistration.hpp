// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/appservice/Namespaces.hpp"
#include "merovingian/core/secret_buffer.hpp"

#include <optional>
#include <string>
#include <vector>

namespace merovingian::appservice
{

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

} // namespace merovingian::appservice
