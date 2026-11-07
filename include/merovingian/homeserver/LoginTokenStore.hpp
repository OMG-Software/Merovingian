// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace merovingian::homeserver
{

// The login tokens `POST /_matrix/client/v1/login/get_token` has minted and nobody has redeemed yet (CS8,
// ADR-0548). Held in memory only: a token lives two minutes and a restart simply drops the unredeemed ones, so no
// table and no schema change is needed.
//
// Only a hash of a token is held (BLAKE2b-256 of the token, which is 256 bits of libsodium randomness, so an
// unkeyed hash cannot be reversed by guessing). `redeem` compares the offered token's hash with every held hash
// with `crypto::constant_time_equal`, never exits early, and so does the same work whether or not a token matched.
// A token is single use: the first `redeem` that names it removes it, whether or not the login that follows
// succeeds, and whether or not the token had expired.
//
// Bounded: at most `per_user_cap` live tokens for one user and `total_cap` altogether. A refused `issue` never
// evicts another token (evicting the oldest would let a flood of requests for one account displace the tokens the
// owner just minted). Expired tokens are swept at the start of every `issue` and `redeem`, and the scan is at most
// `total_cap` entries.
//
// Not thread-safe: the runtime mutex serialises every use, as it does the UIA sessions beside it.
class LoginTokenStore final
{
public:
    enum class IssueOutcome : std::uint8_t
    {
        issued,
        user_cap_reached,
        total_cap_reached,
    };

    struct IssueResult final
    {
        IssueOutcome outcome{IssueOutcome::issued};
        // When refused: milliseconds until the soonest live token that blocks this request expires.
        std::uint64_t retry_after_ms{0U};
    };

    // Records `token_hash` for `user_id`, valid for `lifetime_ms` from `now_ms`.
    [[nodiscard]] auto issue(std::string_view user_id, std::string token_hash, std::uint64_t now_ms,
                             std::uint64_t lifetime_ms, std::size_t per_user_cap, std::size_t total_cap) -> IssueResult;

    // Consumes the token whose hash is `token_hash` and returns the user it was minted for, or nullopt when no live
    // token has that hash. A match is removed even when it had expired.
    [[nodiscard]] auto redeem(std::string_view token_hash, std::uint64_t now_ms) -> std::optional<std::string>;

    // Drops every token held for `user_id`.
    auto erase_user(std::string_view user_id) -> void;

    // Drops every token whose lifetime ended at or before `now_ms`.
    auto sweep(std::uint64_t now_ms) -> void;

    [[nodiscard]] auto size() const noexcept -> std::size_t;
    [[nodiscard]] auto count_for_user(std::string_view user_id) const noexcept -> std::size_t;

private:
    struct Entry final
    {
        std::string user_id{};
        std::string token_hash{};
        std::uint64_t expires_at_ms{0U};
    };

    std::vector<Entry> m_entries{};
};

} // namespace merovingian::homeserver
