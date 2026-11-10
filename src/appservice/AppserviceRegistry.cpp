// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/appservice/AppserviceRegistry.hpp"

#include "merovingian/appservice/AppserviceRegistration.hpp"
#include "merovingian/appservice/Registration.hpp"
#include "merovingian/appservice/SecretView.hpp"
#include "merovingian/crypto/ConstantTime.hpp"

#include <algorithm>
#include <string_view>
#include <utility>

namespace merovingian::appservice
{

AppserviceRegistry::AppserviceRegistry(std::vector<AppserviceRegistration> registrations) noexcept
    : m_registrations{std::move(registrations)}
{
}

auto AppserviceRegistry::empty() const noexcept -> bool
{
    return m_registrations.empty();
}

auto AppserviceRegistry::size() const noexcept -> std::size_t
{
    return m_registrations.size();
}

auto AppserviceRegistry::all() const noexcept -> std::vector<AppserviceRegistration> const&
{
    return m_registrations;
}

auto AppserviceRegistry::find_by_as_token(std::string_view presented_token) const noexcept
    -> AppserviceRegistration const*
{
    if (presented_token.empty())
    {
        return nullptr;
    }
    for (auto const& registration : m_registrations)
    {
        if (crypto::constant_time_equal_variable_length(presented_token, secret_view(registration.as_token)))
        {
            return &registration;
        }
    }
    return nullptr;
}

auto AppserviceRegistry::find_by_id(std::string_view id) const noexcept -> AppserviceRegistration const*
{
    auto const it = std::ranges::find_if(m_registrations, [id](AppserviceRegistration const& reg) {
        return reg.id == id;
    });
    return it == m_registrations.end() ? nullptr : &(*it);
}

auto AppserviceRegistry::is_sender_user_id(std::string_view user_id, std::string_view server_name) const noexcept
    -> bool
{
    return std::ranges::any_of(m_registrations, [user_id, server_name](AppserviceRegistration const& reg) {
        return sender_user_id(reg, server_name) == user_id;
    });
}

auto AppserviceRegistry::user_namespace_exclusively_owned_by_other(std::string_view user_id,
                                                                   std::string_view excluded_id) const noexcept -> bool
{
    return std::ranges::any_of(m_registrations, [user_id, excluded_id](AppserviceRegistration const& reg) {
        return reg.id != excluded_id && any_exclusive_namespace_matches(reg.namespaces.users, user_id);
    });
}

auto AppserviceRegistry::alias_namespace_exclusively_owned_by_other(std::string_view alias,
                                                                    std::string_view excluded_id) const noexcept -> bool
{
    return std::ranges::any_of(m_registrations, [alias, excluded_id](AppserviceRegistration const& reg) {
        return reg.id != excluded_id && any_exclusive_namespace_matches(reg.namespaces.aliases, alias);
    });
}

} // namespace merovingian::appservice
