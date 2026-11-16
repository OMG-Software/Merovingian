// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#include "merovingian/homeserver/AccountSessionStore.hpp"

#include "merovingian/crypto/ConstantTime.hpp"
#include "merovingian/crypto/GenericHash.hpp"
#include "merovingian/homeserver/OAuthSecret.hpp"

#include <algorithm>
#include <array>
#include <utility>

namespace merovingian::homeserver
{
namespace
{

    // Separates the form token from every other hash of the session secret (the stored `oauth_secret_hash` is
    // unlabelled), so the token cannot be computed from what the store keeps and is never the cookie value.
    constexpr auto form_token_label = std::string_view{"merovingian.account.form_token.v1"};

} // namespace

auto AccountSessionStore::forget(Entry const& entry) -> void
{
    auto const user = m_hashes_by_user.find(entry.session.user_id);
    if (user == m_hashes_by_user.end())
    {
        return;
    }
    // The per-user list is a hash we stored ourselves, not a secret a request offered: a plain comparison is enough.
    std::erase(user->second, entry.secret_hash);
    if (user->second.empty())
    {
        m_hashes_by_user.erase(user);
    }
}

auto AccountSessionStore::erase_hash(std::string_view secret_hash) -> bool
{
    auto taken = m_sessions.erase(secret_hash);
    if (!taken.has_value())
    {
        return false;
    }
    forget(*taken);
    return true;
}

auto AccountSessionStore::erase_expired(std::uint64_t now_ms) -> void
{
    m_sessions.erase_expired(now_ms, [this](Entry const& entry) {
        forget(entry);
    });
}

auto AccountSessionStore::create(std::string_view user_id, std::uint64_t now_ms) -> std::variant<std::string, Refusal>
{
    if (user_id.empty())
    {
        return Refusal::no_user;
    }
    erase_expired(now_ms);
    auto secret = make_oauth_secret();
    auto secret_hash = secret.has_value() ? oauth_secret_hash(*secret) : std::nullopt;
    if (!secret_hash.has_value())
    {
        return Refusal::secret_unavailable;
    }
    if (auto const user = m_hashes_by_user.find(user_id);
        user != m_hashes_by_user.end() && user->second.size() >= max_sessions_per_user)
    {
        // Replace this user's oldest session; every session has the same lifetime, so the oldest is the first.
        auto const oldest = user->second.front();
        erase_hash(oldest);
    }
    else if (m_sessions.size() >= max_sessions)
    {
        return Refusal::store_full;
    }
    auto const expires_at_ms = now_ms + lifetime_ms;
    auto session = AccountSession{std::string{user_id}, now_ms, expires_at_ms};
    m_hashes_by_user[session.user_id].push_back(*secret_hash);
    auto hash_copy = *secret_hash;
    m_sessions.insert(std::move(*secret_hash), Entry{std::move(session), std::move(hash_copy)}, expires_at_ms);
    return std::move(*secret);
}

auto AccountSessionStore::find(std::string_view secret, std::uint64_t now_ms) -> std::optional<AccountSession>
{
    erase_expired(now_ms);
    if (secret.empty())
    {
        return std::nullopt;
    }
    auto const secret_hash = oauth_secret_hash(secret);
    if (!secret_hash.has_value())
    {
        return std::nullopt;
    }
    auto const* entry = m_sessions.find(*secret_hash);
    if (entry == nullptr)
    {
        return std::nullopt;
    }
    return entry->session;
}

auto AccountSessionStore::end(std::string_view secret, std::uint64_t now_ms) -> bool
{
    erase_expired(now_ms);
    if (secret.empty())
    {
        return false;
    }
    auto const secret_hash = oauth_secret_hash(secret);
    return secret_hash.has_value() && erase_hash(*secret_hash);
}

auto AccountSessionStore::end_user(std::string_view user_id) -> std::size_t
{
    auto const user = m_hashes_by_user.find(user_id);
    if (user == m_hashes_by_user.end())
    {
        return 0U;
    }
    // Copied first: each erase edits the list through `forget`.
    auto const hashes = user->second;
    auto ended = std::size_t{0U};
    for (auto const& hash : hashes)
    {
        if (erase_hash(hash))
        {
            ++ended;
        }
    }
    return ended;
}

auto AccountSessionStore::form_token(std::string_view secret) -> std::optional<std::string>
{
    if (secret.empty())
    {
        return std::nullopt;
    }
    auto const pieces = std::array<std::string_view, 2>{form_token_label, secret};
    return crypto::generic_hash(pieces);
}

auto AccountSessionStore::form_token_matches(std::string_view secret, std::string_view offered) -> bool
{
    auto const expected = form_token(secret);
    if (!expected.has_value() || offered.empty())
    {
        return false;
    }
    return crypto::constant_time_equal(*expected, offered);
}

auto AccountSessionStore::live_count_for_user(std::string_view user_id, std::uint64_t now_ms) -> std::size_t
{
    erase_expired(now_ms);
    auto const user = m_hashes_by_user.find(user_id);
    return user == m_hashes_by_user.end() ? 0U : user->second.size();
}

auto AccountSessionStore::size() const noexcept -> std::size_t
{
    return m_sessions.size();
}

} // namespace merovingian::homeserver
