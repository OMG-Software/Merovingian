// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/ExaminedRows.hpp"
#include "merovingian/homeserver/LocalSession.hpp"

#include <cstddef>
#include <functional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace merovingian::homeserver
{

// The in-memory mirror of the access-token table, with a lookup that does not scan it (P7).
//
// The sessions stay in a vector in insertion order, so iteration, `front()`, `back()` and `size()` behave as
// they did when the field was a plain vector; `erase_if` keeps the order of what remains. The one exception is
// `erase_device`, which moves the last session into each hole (so a request can drop one device's sessions in
// time proportional to them), after which `back()` is no longer the newest session. Production code relies on the
// order nowhere: only tests read `front()`/`back()`. Beside the vector sits an index from a digest of the token
// HASH to the session's position, and one from (user ID, device ID) to the device's positions. The digest is
// `std::hash` of the stored hash, itself a uniformly distributed BLAKE2b output (keyed for v3 and v4), so a client that
// holds only a bearer token cannot steer which bucket a lookup lands in, and the index compares only the digests, never
// the hashes. `find` then confirms every candidate with the caller's predicate, which compares the full hashes with
// `crypto::constant_time_equal` (src/auth/AGENTS.md rule 3): the index narrows the search and never decides a match.
//
// Not thread-safe: the runtime mutex serialises every use, as it did the vector this replaces.
//
// Writing `access_token_hash` through an iterator bypasses the index. Use `set_access_token_hash`. A hash
// written behind the index's back is found by nothing: the lookup fails closed, never open.
class SessionTable final
{
public:
    using Container = std::vector<LocalSession>;
    using iterator = Container::iterator;
    using const_iterator = Container::const_iterator;

    [[nodiscard]] auto begin() noexcept -> iterator
    {
        return sessions_.begin();
    }
    [[nodiscard]] auto end() noexcept -> iterator
    {
        return sessions_.end();
    }
    [[nodiscard]] auto begin() const noexcept -> const_iterator
    {
        return sessions_.begin();
    }
    [[nodiscard]] auto end() const noexcept -> const_iterator
    {
        return sessions_.end();
    }
    [[nodiscard]] auto size() const noexcept -> std::size_t
    {
        return sessions_.size();
    }
    [[nodiscard]] auto empty() const noexcept -> bool
    {
        return sessions_.empty();
    }
    [[nodiscard]] auto front() -> LocalSession&
    {
        return sessions_.front();
    }
    [[nodiscard]] auto front() const -> LocalSession const&
    {
        return sessions_.front();
    }
    [[nodiscard]] auto back() -> LocalSession&
    {
        return sessions_.back();
    }
    [[nodiscard]] auto back() const -> LocalSession const&
    {
        return sessions_.back();
    }

    auto reserve(std::size_t capacity) -> void;
    auto push_back(LocalSession session) -> void;

    // Replaces `session`'s hash (the v3 to v4 upgrade) and moves its index entry. `session` must be an element
    // of this table.
    auto set_access_token_hash(LocalSession& session, std::string hash) -> void;

    // Removes every session of the device and returns how many went. Costs the device's sessions, not the table:
    // the last session fills each hole, so insertion order is not kept (see the class comment).
    auto erase_device(std::string_view user_id, std::string_view device_id) -> std::size_t;

    // Marks every session of the device revoked and returns how many it reached. Costs the device's sessions, not the
    // table (run-3 C02); a device with none costs one lookup.
    auto revoke_device(std::string_view user_id, std::string_view device_id) -> std::size_t;

    // How many sessions `erase_device` visited, in total, for tests that prove its cost (F-08).
    [[nodiscard]] auto rows_examined() const noexcept -> database::ExaminedRows const&
    {
        return examined_;
    }

    // Removes every session `should_remove` accepts and returns how many went. One pass over the vector and one
    // rebuild of the index: for the retention sweep, never for a request.
    template <typename Predicate>
    auto erase_if(Predicate&& should_remove) -> std::size_t
    {
        auto const removed = std::erase_if(sessions_, std::forward<Predicate>(should_remove));
        if (removed != 0U)
        {
            rebuild_index();
        }
        return removed;
    }

    // The first session that one of the candidate hashes leads to and `accept(session, candidate)` confirms.
    // Looks only at the sessions whose index digest equals a candidate's, so the cost does not depend on how
    // many sessions exist. `accept` must compare the two hashes in constant time.
    template <typename Accept>
    [[nodiscard]] auto find(std::span<std::string const> candidate_hashes, Accept&& accept) const -> LocalSession const*
    {
        for (auto const& candidate : candidate_hashes)
        {
            auto const [first, last] = index_.equal_range(digest(candidate));
            for (auto entry = first; entry != last; ++entry)
            {
                if (entry->second >= sessions_.size())
                {
                    continue;
                }
                auto const& session = sessions_[entry->second];
                if (accept(session, candidate))
                {
                    return &session;
                }
            }
        }
        return nullptr;
    }

private:
    [[nodiscard]] static auto digest(std::string_view hash) noexcept -> std::size_t
    {
        return std::hash<std::string_view>{}(hash);
    }

    // The length prefix makes the pair unambiguous: ("a", "bc") and ("ab", "c") get different keys.
    [[nodiscard]] static auto device_key(std::string_view user_id, std::string_view device_id) -> std::string;

    auto rebuild_index() -> void;
    auto index_session(std::size_t position) -> void;
    auto unindex_session(std::size_t position) -> void;

    Container sessions_{};
    std::unordered_multimap<std::size_t, std::size_t> index_{};
    // device_key(user_id, device_id) -> positions in sessions_. Keyed on identifiers, not secrets. A session's user
    // and device are never changed after push_back.
    std::unordered_map<std::string, std::vector<std::size_t>> device_index_{};
    database::ExaminedRows examined_{};
};

} // namespace merovingian::homeserver
