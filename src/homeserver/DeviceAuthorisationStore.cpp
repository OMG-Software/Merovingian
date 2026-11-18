// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/DeviceAuthorisationStore.hpp"

#include "merovingian/crypto/ConstantTime.hpp"
#include "merovingian/crypto/Random.hpp"
#include "merovingian/homeserver/OAuthSecret.hpp"
#include "merovingian/oauth/UserCode.hpp"

#include <span>
#include <utility>

namespace merovingian::homeserver
{

DeviceAuthorisationStore::DeviceAuthorisationStore(RandomSource random)
    : m_random{random ? std::move(random) : RandomSource{[](std::size_t size) {
        return crypto::secure_random_bytes(size);
    }}}
{
}

auto DeviceAuthorisationStore::forget(Entry const& entry) -> void
{
    m_by_user_code.erase(entry.user_code_hash);
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
        if (auto const expiry = client->second.find(entry.authorisation.expires_at_ms); expiry != client->second.end())
        {
            client->second.erase(expiry);
        }
        if (client->second.empty())
        {
            m_expiries_by_client.erase(client);
        }
    }
}

auto DeviceAuthorisationStore::erase_expired(std::uint64_t now_ms) -> void
{
    m_entries.erase_expired(now_ms, [this](Entry const& entry) {
        forget(entry);
    });
}

auto DeviceAuthorisationStore::draw_user_code() -> std::optional<std::string>
{
    for (auto draw = std::size_t{0U}; draw < max_user_code_draws; ++draw)
    {
        auto const bytes = m_random(user_code_random_bytes);
        if (!bytes.has_value())
        {
            return std::nullopt;
        }
        auto code = oauth::user_code_from_bytes(std::span<std::uint8_t const>{*bytes});
        if (!code.has_value())
        {
            continue;
        }
        auto const hash = oauth_secret_hash(*code);
        if (!hash.has_value())
        {
            return std::nullopt;
        }
        if (!m_by_user_code.contains(*hash))
        {
            return code;
        }
    }
    return std::nullopt;
}

auto DeviceAuthorisationStore::create(std::string_view client_id, std::string_view scope, std::string_view device_id,
                                      std::string_view client_address_key, std::uint64_t now_ms)
    -> std::variant<Started, Refusal>
{
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
    auto device_code = make_oauth_secret();
    auto device_code_hash = device_code.has_value() ? oauth_secret_hash(*device_code) : std::nullopt;
    auto user_code = draw_user_code();
    auto user_code_hash = user_code.has_value() ? oauth_secret_hash(*user_code) : std::nullopt;
    if (!device_code_hash.has_value() || !user_code_hash.has_value())
    {
        return Refusal::secret_unavailable;
    }
    auto entry = Entry{};
    auto& authorisation = entry.authorisation;
    authorisation.client_id = std::string{client_id};
    authorisation.scope = std::string{scope};
    authorisation.device_id = std::string{device_id};
    authorisation.user_code = *user_code;
    authorisation.client_address_key = std::string{client_address_key};
    authorisation.created_at_ms = now_ms;
    authorisation.expires_at_ms = now_ms + lifetime_ms;
    authorisation.interval_ms = initial_interval_ms;
    entry.user_code_hash = *user_code_hash;
    ++m_count_by_address[authorisation.client_address_key];
    m_expiries_by_client[authorisation.client_id].insert(authorisation.expires_at_ms);
    m_by_user_code.emplace(std::move(*user_code_hash), *device_code_hash);
    auto const expires_at_ms = authorisation.expires_at_ms;
    m_entries.insert(std::move(*device_code_hash), std::move(entry), expires_at_ms);
    return Started{std::move(*device_code), std::move(*user_code), lifetime_ms, initial_interval_ms};
}

auto DeviceAuthorisationStore::attach(std::string_view user_code, std::string_view browser_token, std::uint64_t now_ms)
    -> std::variant<Attached, Busy, NotFound>
{
    erase_expired(now_ms);
    auto const user_code_hash = oauth_secret_hash(user_code);
    auto token_hash = oauth_secret_hash(browser_token);
    if (!user_code_hash.has_value() || !token_hash.has_value() || browser_token.empty())
    {
        return NotFound::unknown;
    }
    auto const indexed = m_by_user_code.find(*user_code_hash);
    if (indexed == m_by_user_code.end())
    {
        return NotFound::unknown;
    }
    auto* entry = m_entries.find(indexed->second);
    if (entry == nullptr || entry->authorisation.state != DeviceAuthorisationState::pending)
    {
        return NotFound::unknown;
    }
    if (entry->attachment.has_value() && entry->attachment->lease_until_ms > now_ms &&
        !crypto::constant_time_equal(entry->attachment->browser_token_hash, *token_hash))
    {
        return Busy{entry->attachment->lease_until_ms - now_ms};
    }
    auto const id = ++m_next_attachment;
    entry->attachment = Attachment{id, std::move(*token_hash), now_ms + attachment_lease_ms};
    return Attached{indexed->second, id, entry->authorisation};
}

auto DeviceAuthorisationStore::attached_entry(std::string_view key, std::uint64_t attachment, std::uint64_t now_ms)
    -> Entry*
{
    erase_expired(now_ms);
    auto* entry = m_entries.find(key);
    if (entry == nullptr || entry->authorisation.state != DeviceAuthorisationState::pending ||
        !entry->attachment.has_value() || entry->attachment->id != attachment)
    {
        return nullptr;
    }
    return entry;
}

auto DeviceAuthorisationStore::find_attached(std::string_view key, std::uint64_t attachment, std::uint64_t now_ms)
    -> std::optional<DeviceAuthorisation>
{
    auto const* entry = attached_entry(key, attachment, now_ms);
    if (entry == nullptr)
    {
        return std::nullopt;
    }
    return entry->authorisation;
}

auto DeviceAuthorisationStore::renew(std::string_view key, std::uint64_t attachment, std::uint64_t now_ms) -> bool
{
    auto* entry = attached_entry(key, attachment, now_ms);
    if (entry == nullptr)
    {
        return false;
    }
    entry->attachment->lease_until_ms = now_ms + attachment_lease_ms;
    return true;
}

auto DeviceAuthorisationStore::release(std::string_view key, std::uint64_t attachment) -> void
{
    auto* entry = m_entries.find(key);
    if (entry != nullptr && entry->attachment.has_value() && entry->attachment->id == attachment)
    {
        entry->attachment.reset();
    }
}

auto DeviceAuthorisationStore::decide(std::string_view key, std::uint64_t attachment, std::string_view user_id,
                                      std::string_view credential_stamp, bool approve, std::uint64_t now_ms) -> bool
{
    auto* entry = attached_entry(key, attachment, now_ms);
    if (entry == nullptr)
    {
        return false;
    }
    entry->authorisation.state = approve ? DeviceAuthorisationState::approved : DeviceAuthorisationState::denied;
    entry->authorisation.user_id = std::string{user_id};
    entry->authorisation.credential_stamp = approve ? std::string{credential_stamp} : std::string{};
    entry->attachment.reset();
    return true;
}

auto DeviceAuthorisationStore::poll(std::string_view device_code, std::string_view client_id, std::uint64_t now_ms)
    -> PollResult
{
    erase_expired(now_ms);
    auto const device_code_hash = oauth_secret_hash(device_code);
    auto* entry = device_code_hash.has_value() ? m_entries.find(*device_code_hash) : nullptr;
    if (entry == nullptr)
    {
        return PollResult{PollOutcome::expired_token, 0U, std::nullopt};
    }
    auto& authorisation = entry->authorisation;
    if (authorisation.client_id != client_id)
    {
        return PollResult{PollOutcome::wrong_client, 0U, std::nullopt};
    }
    switch (authorisation.state)
    {
    case DeviceAuthorisationState::denied:
        return PollResult{PollOutcome::access_denied, authorisation.interval_ms, std::nullopt};
    case DeviceAuthorisationState::approved: {
        // Redeemed once: the entry leaves the store, so a second poll with the code is `expired_token` (ADR-0804).
        auto taken = m_entries.erase(*device_code_hash);
        if (!taken.has_value())
        {
            return PollResult{PollOutcome::expired_token, 0U, std::nullopt};
        }
        forget(*taken);
        auto const interval_ms = taken->authorisation.interval_ms;
        return PollResult{PollOutcome::approved, interval_ms, std::move(taken->authorisation)};
    }
    case DeviceAuthorisationState::pending:
        break;
    }
    auto const too_soon =
        authorisation.last_poll_ms.has_value() && now_ms - *authorisation.last_poll_ms < authorisation.interval_ms;
    authorisation.last_poll_ms = now_ms;
    if (too_soon)
    {
        authorisation.interval_ms += slow_down_step_ms;
        return PollResult{PollOutcome::slow_down, authorisation.interval_ms, std::nullopt};
    }
    return PollResult{PollOutcome::authorization_pending, authorisation.interval_ms, std::nullopt};
}

auto DeviceAuthorisationStore::live_count_for_client(std::string_view client_id, std::uint64_t now_ms) -> std::size_t
{
    erase_expired(now_ms);
    auto const client = m_expiries_by_client.find(client_id);
    return client == m_expiries_by_client.end() ? 0U : client->second.size();
}

auto DeviceAuthorisationStore::holds_live_entry_for_client(std::string_view client_id, std::uint64_t now_ms) const
    -> bool
{
    auto const client = m_expiries_by_client.find(client_id);
    return client != m_expiries_by_client.end() && !client->second.empty() && *client->second.rbegin() > now_ms;
}

auto DeviceAuthorisationStore::size() const noexcept -> std::size_t
{
    return m_entries.size();
}

} // namespace merovingian::homeserver
