// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/crypto/constant_time.hpp"
#include "merovingian/database/ExaminedRows.hpp"
#include "merovingian/database/StateGroupKeyHash.hpp"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <functional>
#include <limits>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace merovingian::database
{

// `access_tokens` and `refresh_tokens`: the rows of a credential table with the indexes a request needs, so that
// no token lookup or revocation scans the table (security audit run-4 F-08, ADR-0325, ADR-0488). The class owns the
// rows and shows them read-only, so a writer that bypasses it does not compile and the indexes cannot drift from the
// rows. Indexes hold positions into `rows_`, so the defaulted copy and move keep them valid (ADR-0523). Row order
// means nothing: an erase moves the last row into the hole.
//
// `Row` needs `user_id`, `device_id`, `token_hash` and `revoked`; a row that also has `predecessor_hash` (the refresh
// token) gets the predecessor index and its methods.
//
// The index by token hash is a DIGEST index (ADR-0488): its key is `std::hash` of the stored hash, so it only narrows,
// and every candidate is confirmed with `crypto::constant_time_equal` before it counts as a match (src/auth/AGENTS.md
// rule 3). The index alone never answers a lookup and a miss is never followed by a scan. The predecessor index is of
// the same kind. The device and user indexes are keyed on identifiers, not secrets.
//
// A row's hash, user, device and predecessor never change after `insert`; `revoked` changes only through the revoke
// methods, one way. The table has no lock: a reader needs exclusion from writers (`runtime.mutex`), and a pointer
// `find` returns is valid only until the table is next changed by `insert`, `erase`, `erase_if` or `clear`.
template <typename Row>
class CredentialTable final
{
    static constexpr auto npos = std::numeric_limits<std::size_t>::max();
    static constexpr bool kHasPredecessor = requires(Row const& row) { row.predecessor_hash; };

public:
    using value_type = Row;
    using size_type = std::size_t;
    using const_iterator = typename std::vector<Row>::const_iterator;
    using iterator = const_iterator;

    [[nodiscard]] auto begin() const noexcept -> const_iterator
    {
        return rows_.begin();
    }
    [[nodiscard]] auto end() const noexcept -> const_iterator
    {
        return rows_.end();
    }
    [[nodiscard]] auto size() const noexcept -> size_type
    {
        return rows_.size();
    }
    [[nodiscard]] auto empty() const noexcept -> bool
    {
        return rows_.empty();
    }
    [[nodiscard]] auto operator[](size_type position) const -> Row const&
    {
        return rows_[position];
    }
    [[nodiscard]] auto front() const -> Row const&
    {
        return rows_.front();
    }
    [[nodiscard]] auto back() const -> Row const&
    {
        return rows_.back();
    }

    // How many rows the lookup and revoke methods visited, in total. Iterating with `begin`/`end` is not counted.
    [[nodiscard]] auto rows_examined() const noexcept -> ExaminedRows const&
    {
        return examined_;
    }

    // The row whose hash equals `token_hash`, or nullptr. Costs the rows in one digest bucket.
    [[nodiscard]] auto find(std::string_view token_hash) const -> Row const*
    {
        auto const position = position_of(token_hash);
        return position == npos ? nullptr : &rows_[position];
    }

    // The first row one of `candidate_hashes` equals (a presented token has several candidate hashes, one per hash
    // version).
    [[nodiscard]] auto find(std::span<std::string const> candidate_hashes) const -> Row const*
    {
        for (auto const& candidate : candidate_hashes)
        {
            if (auto const* row = find(std::string_view{candidate}); row != nullptr)
            {
                return row;
            }
        }
        return nullptr;
    }

    [[nodiscard]] auto contains(std::string_view token_hash) const -> bool
    {
        return position_of(token_hash) != npos;
    }

    // Whether `token_hash` names a row that is not revoked.
    [[nodiscard]] auto has_unrevoked_hash(std::string_view token_hash) const -> bool
    {
        auto const* row = find(token_hash);
        return row != nullptr && !row->revoked;
    }

    // Whether the device holds a row that is not revoked.
    [[nodiscard]] auto has_unrevoked_for_device(std::string_view user_id, std::string_view device_id) const -> bool
    {
        return any_unrevoked(positions_of_device(user_id, device_id));
    }

    // Whether the user holds a row that is not revoked.
    [[nodiscard]] auto has_unrevoked_for_user(std::string_view user_id) const -> bool
    {
        return any_unrevoked(positions_of_user(user_id));
    }

    // Whether the user holds a row that is not revoked on a device other than `keep_device_id`.
    [[nodiscard]] auto has_unrevoked_for_user_except_device(std::string_view user_id,
                                                            std::string_view keep_device_id) const -> bool
    {
        auto const* positions = positions_of_user(user_id);
        if (positions == nullptr)
        {
            return false;
        }
        for (auto const position : *positions)
        {
            examined_.add(1U);
            if (!rows_[position].revoked && rows_[position].device_id != keep_device_id)
            {
                return true;
            }
        }
        return false;
    }

    // Whether a row minted from `predecessor_hash` is not revoked.
    [[nodiscard]] auto has_unrevoked_with_predecessor(std::string_view predecessor_hash) const -> bool
        requires(kHasPredecessor)
    {
        if (predecessor_hash.empty())
        {
            return false;
        }
        auto const [first, last] = predecessor_index_.equal_range(digest(predecessor_hash));
        for (auto entry = first; entry != last; ++entry)
        {
            examined_.add(1U);
            auto const& row = rows_[entry->second];
            if (!row.revoked && crypto::constant_time_equal(row.predecessor_hash, predecessor_hash))
            {
                return true;
            }
        }
        return false;
    }

    // Adds `row`. False, and nothing changes, when a row with its hash is already held.
    auto insert(Row row) -> bool
    {
        if (position_of(row.token_hash) != npos)
        {
            return false;
        }
        rows_.push_back(std::move(row));
        index_row(rows_.size() - 1U);
        return true;
    }

    // Removes the row `token_hash` names. False when none does.
    auto erase(std::string_view token_hash) -> bool
    {
        auto const position = position_of(token_hash);
        if (position == npos)
        {
            return false;
        }
        unindex_row(position);
        auto const last = rows_.size() - 1U;
        if (position != last)
        {
            // Swap-and-pop: the last row fills the hole and is indexed again under its new position.
            unindex_row(last);
            rows_[position] = std::move(rows_[last]);
            index_row(position);
        }
        rows_.pop_back();
        return true;
    }

    // Removes every row `should_remove` accepts, in one pass over the table and one rebuild of the indexes: for the
    // retention sweep, never for a request.
    template <typename Predicate>
    auto erase_if(Predicate&& should_remove) -> size_type
    {
        examined_.add(rows_.size());
        auto const removed = std::erase_if(rows_, std::forward<Predicate>(should_remove));
        if (removed != 0U)
        {
            rebuild_indexes();
        }
        return removed;
    }

    // Revoke methods: set `revoked` on every matching row that is not yet revoked and return how many changed.
    auto revoke_hash(std::string_view token_hash) -> size_type
    {
        auto revoked = size_type{0U};
        auto const [first, last] = hash_index_.equal_range(digest(token_hash));
        for (auto entry = first; entry != last; ++entry)
        {
            examined_.add(1U);
            auto& row = rows_[entry->second];
            if (!row.revoked && crypto::constant_time_equal(row.token_hash, token_hash))
            {
                row.revoked = true;
                ++revoked;
            }
        }
        return revoked;
    }

    auto revoke_for_user(std::string_view user_id) -> size_type
    {
        return revoke_positions(positions_of_user(user_id), [](Row const&) {
            return true;
        });
    }

    auto revoke_for_device(std::string_view user_id, std::string_view device_id) -> size_type
    {
        return revoke_positions(positions_of_device(user_id, device_id), [](Row const&) {
            return true;
        });
    }

    auto revoke_for_user_except_device(std::string_view user_id, std::string_view keep_device_id) -> size_type
    {
        return revoke_positions(positions_of_user(user_id), [keep_device_id](Row const& row) {
            return row.device_id != keep_device_id;
        });
    }

    // Revokes the rows minted from `predecessor_hash` (an empty one names none).
    auto revoke_with_predecessor(std::string_view predecessor_hash) -> size_type
        requires(kHasPredecessor)
    {
        auto revoked = size_type{0U};
        if (predecessor_hash.empty())
        {
            return revoked;
        }
        auto const [first, last] = predecessor_index_.equal_range(digest(predecessor_hash));
        for (auto entry = first; entry != last; ++entry)
        {
            examined_.add(1U);
            auto& row = rows_[entry->second];
            if (!row.revoked && crypto::constant_time_equal(row.predecessor_hash, predecessor_hash))
            {
                row.revoked = true;
                ++revoked;
            }
        }
        return revoked;
    }

    // Sets the expiry of every row `pick` accepts and returns how many it set. The expiry is not indexed. A scan of
    // the whole table: for tests that age rows, never for a request.
    template <typename Predicate>
    auto set_expires_at_where(Predicate&& pick, std::chrono::system_clock::time_point expires_at) -> size_type
    {
        examined_.add(rows_.size());
        auto changed = size_type{0U};
        for (auto& row : rows_)
        {
            if (pick(std::as_const(row)))
            {
                row.expires_at = expires_at;
                ++changed;
            }
        }
        return changed;
    }

    auto clear() noexcept -> void
    {
        rows_.clear();
        hash_index_.clear();
        predecessor_index_.clear();
        device_index_.clear();
        user_index_.clear();
    }

private:
    using DigestIndex = std::unordered_multimap<std::size_t, std::size_t>;
    using PositionsByKey =
        std::unordered_map<std::string, std::vector<std::size_t>, detail::StateGroupKeyHash, std::equal_to<>>;

    [[nodiscard]] static auto digest(std::string_view hash) noexcept -> std::size_t
    {
        return std::hash<std::string_view>{}(hash);
    }

    // The length prefix makes the pair unambiguous: ("a", "bc") and ("ab", "c") get different keys.
    [[nodiscard]] static auto device_key(std::string_view user_id, std::string_view device_id) -> std::string
    {
        auto key = std::to_string(user_id.size());
        key += ':';
        key += user_id;
        key += device_id;
        return key;
    }

    [[nodiscard]] auto position_of(std::string_view token_hash) const -> std::size_t
    {
        auto const [first, last] = hash_index_.equal_range(digest(token_hash));
        for (auto entry = first; entry != last; ++entry)
        {
            examined_.add(1U);
            if (crypto::constant_time_equal(rows_[entry->second].token_hash, token_hash))
            {
                return entry->second;
            }
        }
        return npos;
    }

    [[nodiscard]] auto positions_of_user(std::string_view user_id) const -> std::vector<std::size_t> const*
    {
        auto const found = user_index_.find(user_id);
        return found == user_index_.end() ? nullptr : &found->second;
    }

    [[nodiscard]] auto positions_of_device(std::string_view user_id, std::string_view device_id) const
        -> std::vector<std::size_t> const*
    {
        auto const found = device_index_.find(device_key(user_id, device_id));
        return found == device_index_.end() ? nullptr : &found->second;
    }

    [[nodiscard]] auto any_unrevoked(std::vector<std::size_t> const* positions) const -> bool
    {
        if (positions == nullptr)
        {
            return false;
        }
        for (auto const position : *positions)
        {
            examined_.add(1U);
            if (!rows_[position].revoked)
            {
                return true;
            }
        }
        return false;
    }

    template <typename Accept>
    auto revoke_positions(std::vector<std::size_t> const* positions, Accept&& accept) -> size_type
    {
        auto revoked = size_type{0U};
        if (positions == nullptr)
        {
            return revoked;
        }
        for (auto const position : *positions)
        {
            examined_.add(1U);
            auto& row = rows_[position];
            if (!row.revoked && accept(row))
            {
                row.revoked = true;
                ++revoked;
            }
        }
        return revoked;
    }

    static auto erase_entry(DigestIndex& index, std::size_t key, std::size_t position) -> void
    {
        auto const [first, last] = index.equal_range(key);
        for (auto entry = first; entry != last; ++entry)
        {
            if (entry->second == position)
            {
                index.erase(entry);
                return;
            }
        }
    }

    static auto erase_position(PositionsByKey& index, std::string_view key, std::size_t position) -> void
    {
        auto const found = index.find(key);
        if (found == index.end())
        {
            return;
        }
        std::erase(found->second, position);
        if (found->second.empty())
        {
            index.erase(found);
        }
    }

    auto index_row(std::size_t position) -> void
    {
        auto const& row = rows_[position];
        hash_index_.emplace(digest(row.token_hash), position);
        user_index_[row.user_id].push_back(position);
        device_index_[device_key(row.user_id, row.device_id)].push_back(position);
        if constexpr (kHasPredecessor)
        {
            if (!row.predecessor_hash.empty())
            {
                predecessor_index_.emplace(digest(row.predecessor_hash), position);
            }
        }
    }

    auto unindex_row(std::size_t position) -> void
    {
        auto const& row = rows_[position];
        erase_entry(hash_index_, digest(row.token_hash), position);
        erase_position(user_index_, row.user_id, position);
        erase_position(device_index_, device_key(row.user_id, row.device_id), position);
        if constexpr (kHasPredecessor)
        {
            if (!row.predecessor_hash.empty())
            {
                erase_entry(predecessor_index_, digest(row.predecessor_hash), position);
            }
        }
    }

    auto rebuild_indexes() -> void
    {
        hash_index_.clear();
        predecessor_index_.clear();
        device_index_.clear();
        user_index_.clear();
        for (auto position = std::size_t{0U}; position < rows_.size(); ++position)
        {
            index_row(position);
        }
    }

    std::vector<Row> rows_{};
    // digest(token_hash) -> position in rows_. Narrows only; a candidate is confirmed in constant time.
    DigestIndex hash_index_{};
    // digest(predecessor_hash) -> position in rows_, for rows with a predecessor. Same rules.
    DigestIndex predecessor_index_{};
    // device_key(user_id, device_id) -> positions in rows_.
    PositionsByKey device_index_{};
    // user_id -> positions in rows_.
    PositionsByKey user_index_{};
    ExaminedRows examined_{};
};

} // namespace merovingian::database
