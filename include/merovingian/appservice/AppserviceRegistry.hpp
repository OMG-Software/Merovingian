// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/appservice/AppserviceRegistration.hpp"

#include <cstddef>
#include <string_view>
#include <vector>

namespace merovingian::appservice
{

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

    // True when `value` is the sender_localpart user of any registered
    // appservice. Used at startup to ensure every sender exists (AUTH-3).
    [[nodiscard]] auto is_sender_user_id(std::string_view user_id, std::string_view server_name) const noexcept -> bool;

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

} // namespace merovingian::appservice
