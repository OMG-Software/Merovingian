// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/crypto/ConstantTime.hpp"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>

namespace merovingian::homeserver
{

// The table behind the in-memory OAuth 2.0 stores (`PendingAuthorisationStore`, `AuthorizationCodeStore`, ADR-0782):
// values keyed by the hash of a secret, each with an expiry, found without a scan and expired without a scan.
//
// Entries are held in a map ordered by (expiry, insertion sequence), so the soonest to expire is always first and
// `erase_expired` costs only the entries it removes. Beside it an index maps a digest of the stored hash to the
// entry's key, as `SessionTable` indexes its sessions (ADR-0488): the digest is `std::hash` of the hash, itself a
// uniformly distributed BLAKE2b output, so a client holding only a secret cannot steer which bucket a lookup lands in.
// The index only narrows the search: `find` confirms every candidate with `crypto::constant_time_equal` on the full
// hash and never decides a match from the digest. There is no fall-back scan for a miss.
//
// The caller bounds the table (it decides whether `insert` may run) and keeps any per-key counters, which it updates
// from the value `erase` and `erase_expired` hand back. Not thread-safe: `runtime.mutex` serialises every use.
template <typename Value>
class HashedSecretTable final
{
public:
    // Adds `value` under `secret_hash`, expiring at `expires_at_ms`. The caller has checked the caps.
    auto insert(std::string secret_hash, Value value, std::uint64_t expires_at_ms) -> void
    {
        auto const key = Key{expires_at_ms, m_next_sequence++};
        auto const digest = digest_of(secret_hash);
        m_entries.emplace(key, Entry{std::move(secret_hash), std::move(value)});
        m_index.emplace(digest, key);
    }

    // The value held under `secret_hash`, or nullptr. Every candidate the index offers is compared in constant time.
    // Valid until the next insert or erase.
    [[nodiscard]] auto find(std::string_view secret_hash) -> Value*
    {
        auto const key = find_key(secret_hash);
        if (!key.has_value())
        {
            return nullptr;
        }
        return &m_entries.find(*key)->second.value;
    }

    // Removes the value held under `secret_hash` and hands it back, or nothing when none is held.
    [[nodiscard]] auto erase(std::string_view secret_hash) -> std::optional<Value>
    {
        auto const key = find_key(secret_hash);
        if (!key.has_value())
        {
            return std::nullopt;
        }
        return erase_at(m_entries.find(*key));
    }

    // Removes every value whose expiry is at or before `now_ms`, soonest first, handing each to `on_erase` after it
    // left the table. Costs the values removed, not the table.
    template <typename OnErase>
    auto erase_expired(std::uint64_t now_ms, OnErase&& on_erase) -> void
    {
        while (!m_entries.empty() && m_entries.begin()->first.first <= now_ms)
        {
            auto const value = erase_at(m_entries.begin());
            std::invoke(on_erase, value);
        }
    }

    [[nodiscard]] auto size() const noexcept -> std::size_t
    {
        return m_entries.size();
    }

private:
    // (expiry, insertion sequence): unique, and ordered soonest expiry first.
    using Key = std::pair<std::uint64_t, std::uint64_t>;

    struct Entry final
    {
        std::string secret_hash{};
        Value value;
    };

    [[nodiscard]] static auto digest_of(std::string_view secret_hash) noexcept -> std::size_t
    {
        return std::hash<std::string_view>{}(secret_hash);
    }

    [[nodiscard]] auto find_key(std::string_view secret_hash) const -> std::optional<Key>
    {
        auto found = std::optional<Key>{};
        auto const [first, last] = m_index.equal_range(digest_of(secret_hash));
        for (auto candidate = first; candidate != last; ++candidate)
        {
            auto const entry = m_entries.find(candidate->second);
            // Every candidate is compared, whatever matched first, so the work does not depend on which one matched.
            if (entry != m_entries.end() && crypto::constant_time_equal(entry->second.secret_hash, secret_hash))
            {
                found = candidate->second;
            }
        }
        return found;
    }

    [[nodiscard]] auto erase_at(typename std::map<Key, Entry>::iterator entry) -> Value
    {
        auto const [first, last] = m_index.equal_range(digest_of(entry->second.secret_hash));
        for (auto candidate = first; candidate != last; ++candidate)
        {
            if (candidate->second == entry->first)
            {
                m_index.erase(candidate);
                break;
            }
        }
        auto value = std::move(entry->second.value);
        m_entries.erase(entry);
        return value;
    }

    std::map<Key, Entry> m_entries{};
    std::unordered_multimap<std::size_t, Key> m_index{};
    std::uint64_t m_next_sequence{0U};
};

} // namespace merovingian::homeserver
