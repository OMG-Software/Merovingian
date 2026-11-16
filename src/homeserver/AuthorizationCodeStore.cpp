// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#include "merovingian/homeserver/AuthorizationCodeStore.hpp"

#include "merovingian/homeserver/OAuthSecret.hpp"

#include <utility>

namespace merovingian::homeserver
{

auto AuthorizationCodeStore::forget_unredeemed(Entry const& entry) -> void
{
    auto const client = m_unredeemed_expiries_by_client.find(entry.grant.client_id);
    if (client == m_unredeemed_expiries_by_client.end())
    {
        return;
    }
    if (auto const expiry = client->second.find(entry.expires_at_ms); expiry != client->second.end())
    {
        client->second.erase(expiry);
    }
    if (client->second.empty())
    {
        m_unredeemed_expiries_by_client.erase(client);
    }
}

auto AuthorizationCodeStore::erase_expired(std::uint64_t now_ms) -> void
{
    m_codes.erase_expired(now_ms, [this](Entry const& entry) {
        if (!entry.redeemed)
        {
            forget_unredeemed(entry);
        }
    });
}

auto AuthorizationCodeStore::issue(AuthorizationGrant grant, std::uint64_t now_ms) -> std::variant<std::string, Refusal>
{
    erase_expired(now_ms);
    if (m_codes.size() >= max_codes)
    {
        return Refusal::store_full;
    }
    auto code = make_oauth_secret();
    auto code_hash = code.has_value() ? oauth_secret_hash(*code) : std::nullopt;
    if (!code_hash.has_value())
    {
        return Refusal::secret_unavailable;
    }
    auto const expires_at_ms = now_ms + lifetime_ms;
    m_unredeemed_expiries_by_client[grant.client_id].insert(expires_at_ms);
    m_codes.insert(std::move(*code_hash), Entry{std::move(grant), expires_at_ms, false}, expires_at_ms);
    return std::move(*code);
}

auto AuthorizationCodeStore::redeem(std::string_view code, std::uint64_t now_ms) -> AuthorizationCodeRedemption
{
    erase_expired(now_ms);
    auto const code_hash = oauth_secret_hash(code);
    auto* entry = code_hash.has_value() ? m_codes.find(*code_hash) : nullptr;
    if (entry == nullptr)
    {
        return {};
    }
    if (entry->redeemed)
    {
        return {AuthorizationCodeRedemption::Outcome::replayed, {}, entry->grant.user_id, entry->grant.device_id};
    }
    forget_unredeemed(*entry);
    entry->redeemed = true;
    return {AuthorizationCodeRedemption::Outcome::fresh, entry->grant, entry->grant.user_id, entry->grant.device_id};
}

auto AuthorizationCodeStore::unredeemed_count_for_client(std::string_view client_id, std::uint64_t now_ms)
    -> std::size_t
{
    erase_expired(now_ms);
    auto const client = m_unredeemed_expiries_by_client.find(client_id);
    return client == m_unredeemed_expiries_by_client.end() ? 0U : client->second.size();
}

auto AuthorizationCodeStore::holds_unredeemed_code_for_client(std::string_view client_id, std::uint64_t now_ms) const
    -> bool
{
    auto const client = m_unredeemed_expiries_by_client.find(client_id);
    return client != m_unredeemed_expiries_by_client.end() && !client->second.empty() &&
           *client->second.rbegin() > now_ms;
}

auto AuthorizationCodeStore::size() const noexcept -> std::size_t
{
    return m_codes.size();
}

} // namespace merovingian::homeserver
