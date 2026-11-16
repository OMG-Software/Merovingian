// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#include "merovingian/homeserver/PendingAuthorisationStore.hpp"

#include "merovingian/crypto/ConstantTime.hpp"
#include "merovingian/homeserver/OAuthSecret.hpp"

#include <utility>

namespace merovingian::homeserver
{
namespace
{

    // Compared with the offered token's hash when no entry matched the identifier, so a wrong token and an unknown
    // identifier cost the same comparison. 64 hex digits, as every `oauth_secret_hash` is.
    constexpr auto unmatched_token_hash =
        std::string_view{"0000000000000000000000000000000000000000000000000000000000000000"};

} // namespace

auto PendingAuthorisationStore::forget(Entry const& entry) -> void
{
    if (auto const address = m_count_by_address.find(entry.authorisation.client_address_key);
        address != m_count_by_address.end())
    {
        if (--address->second == 0U)
        {
            m_count_by_address.erase(address);
        }
    }
    if (auto const client = m_expiries_by_client.find(entry.authorisation.client_id);
        client != m_expiries_by_client.end())
    {
        if (auto const expiry = client->second.find(entry.expires_at_ms); expiry != client->second.end())
        {
            client->second.erase(expiry);
        }
        if (client->second.empty())
        {
            m_expiries_by_client.erase(client);
        }
    }
}

auto PendingAuthorisationStore::erase_expired(std::uint64_t now_ms) -> void
{
    m_entries.erase_expired(now_ms, [this](Entry const& entry) {
        forget(entry);
    });
}

auto PendingAuthorisationStore::create(PendingAuthorisation authorisation, std::string_view browser_token,
                                       std::string_view client_address_key, std::uint64_t now_ms)
    -> std::variant<std::string, Refusal>
{
    if (browser_token.empty())
    {
        return Refusal::no_browser_token;
    }
    erase_expired(now_ms);
    if (m_entries.size() >= max_entries)
    {
        return Refusal::store_full;
    }
    if (auto const address = m_count_by_address.find(client_address_key);
        address != m_count_by_address.end() && address->second >= max_entries_per_address)
    {
        return Refusal::address_full;
    }
    auto identifier = make_oauth_secret();
    auto identifier_hash = identifier.has_value() ? oauth_secret_hash(*identifier) : std::nullopt;
    auto browser_token_hash = oauth_secret_hash(browser_token);
    if (!identifier_hash.has_value() || !browser_token_hash.has_value())
    {
        return Refusal::secret_unavailable;
    }
    authorisation.client_address_key = std::string{client_address_key};
    authorisation.created_at_ms = now_ms;
    authorisation.user_id.clear();
    authorisation.credential_stamp.clear();
    auto const expires_at_ms = now_ms + lifetime_ms;
    ++m_count_by_address[authorisation.client_address_key];
    m_expiries_by_client[authorisation.client_id].insert(expires_at_ms);
    m_entries.insert(std::move(*identifier_hash),
                     Entry{std::move(authorisation), std::move(*browser_token_hash), expires_at_ms}, expires_at_ms);
    return std::move(*identifier);
}

auto PendingAuthorisationStore::bound_entry(std::string_view identifier, std::string_view browser_token,
                                            std::uint64_t now_ms) -> std::pair<Entry*, std::string>
{
    erase_expired(now_ms);
    auto identifier_hash = oauth_secret_hash(identifier);
    auto const token_hash = oauth_secret_hash(browser_token);
    if (!identifier_hash.has_value() || !token_hash.has_value())
    {
        return {nullptr, {}};
    }
    auto* entry = m_entries.find(*identifier_hash);
    // Compare the token whether or not the identifier was found, so both refusals cost the same.
    auto const token_matches = crypto::constant_time_equal(
        entry == nullptr ? unmatched_token_hash : std::string_view{entry->browser_token_hash}, *token_hash);
    if (entry == nullptr || !token_matches || browser_token.empty())
    {
        return {nullptr, {}};
    }
    return {entry, std::move(*identifier_hash)};
}

auto PendingAuthorisationStore::find(std::string_view identifier, std::string_view browser_token, std::uint64_t now_ms)
    -> std::optional<PendingAuthorisation>
{
    auto* const entry = bound_entry(identifier, browser_token, now_ms).first;
    if (entry == nullptr)
    {
        return std::nullopt;
    }
    return entry->authorisation;
}

auto PendingAuthorisationStore::record_user(std::string_view identifier, std::string_view browser_token,
                                            std::string_view user_id, std::string_view credential_stamp,
                                            std::uint64_t now_ms) -> bool
{
    auto* const entry = bound_entry(identifier, browser_token, now_ms).first;
    if (entry == nullptr)
    {
        return false;
    }
    entry->authorisation.user_id = std::string{user_id};
    entry->authorisation.credential_stamp = std::string{credential_stamp};
    return true;
}

auto PendingAuthorisationStore::consume(std::string_view identifier, std::string_view browser_token,
                                        std::uint64_t now_ms) -> std::optional<PendingAuthorisation>
{
    auto const [entry, identifier_hash] = bound_entry(identifier, browser_token, now_ms);
    if (entry == nullptr)
    {
        return std::nullopt;
    }
    auto taken = m_entries.erase(identifier_hash);
    if (!taken.has_value())
    {
        return std::nullopt;
    }
    forget(*taken);
    return std::move(taken->authorisation);
}

auto PendingAuthorisationStore::live_count_for_client(std::string_view client_id, std::uint64_t now_ms) -> std::size_t
{
    erase_expired(now_ms);
    auto const client = m_expiries_by_client.find(client_id);
    return client == m_expiries_by_client.end() ? 0U : client->second.size();
}

auto PendingAuthorisationStore::holds_live_entry_for_client(std::string_view client_id, std::uint64_t now_ms) const
    -> bool
{
    auto const client = m_expiries_by_client.find(client_id);
    return client != m_expiries_by_client.end() && !client->second.empty() && *client->second.rbegin() > now_ms;
}

auto PendingAuthorisationStore::size() const noexcept -> std::size_t
{
    return m_entries.size();
}

} // namespace merovingian::homeserver
