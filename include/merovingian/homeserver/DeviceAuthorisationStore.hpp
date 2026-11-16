// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/StateGroupKeyHash.hpp"
#include "merovingian/homeserver/DeviceAuthorisation.hpp"
#include "merovingian/homeserver/HashedSecretTable.hpp"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <unordered_map>
#include <variant>
#include <vector>

namespace merovingian::homeserver
{

// The device authorisations of the device authorization grant (RFC 8628; plan P11; ADR-0804, ADR-0805). In memory
// only: an entry lives ten minutes, and a restart ends every one in progress and nothing else.
//
// An entry is held under the hash of its device code (`make_oauth_secret`, 256 bits), which `create` returns once to
// the device; the code itself is never kept. A second index maps the hash of the user code to the entry, for the
// link page. User codes are unique among the entries held.
//
// One browser at a time may sign in for an entry (ADR-0806): `attach` binds it to the browser's cookie for
// `attachment_lease_ms`, renewed by `renew` at each step that browser completes. While the lease runs another browser
// is told the code is busy; after it lapses the next browser takes the entry over, and the earlier browser's sign-in
// can no longer decide it. A user's answer (`decide`) counts only from the browser holding the latest attachment.
//
// Bounded: `max_entries` in all and `max_entries_per_address` per client address key. At a cap the expired entries are
// purged and, if it is still full, the creation is refused. A live entry is never evicted. Expired entries are removed
// at the start of every operation, soonest first, at the cost of the entries removed; an expired entry behaves as
// absent.
//
// Every operation takes the current time, so a test needs no clock. Not thread-safe: `runtime.mutex` serialises every
// use (the store is `HomeserverRuntime::oauth_device_authorisations`).
class DeviceAuthorisationStore final
{
public:
    // The source of the random bytes user codes are drawn from; `crypto::secure_random_bytes` unless a test passes
    // one that repeats itself. nullopt is a failure of the source.
    using RandomSource = std::function<std::optional<std::vector<std::uint8_t>>(std::size_t)>;

    // RFC 8628 section 3.2 leaves the lifetime to the server; ten minutes, as a pending authorisation, is long enough
    // to find a phone and sign in, and short enough that a code read off a screen is soon useless.
    static constexpr auto lifetime_ms = std::uint64_t{600'000U};
    // At most this many entries in all. An entry is a few hundred bytes, and the idle-client walk skips every client
    // an entry names, so this is part of `database::max_idle_client_rows_examined` (ADR-0805).
    static constexpr auto max_entries = std::size_t{4096U};
    // At most this many entries per client address key: one household has a few devices to sign in at once, and an
    // address cannot fill the store or crowd the user code space alone.
    static constexpr auto max_entries_per_address = std::size_t{8U};
    // The polling interval the device is told (RFC 8628 section 3.2 suggests five seconds), and what `slow_down` adds
    // to it (section 3.5: "increased by 5 seconds for this and all subsequent requests").
    static constexpr auto initial_interval_ms = std::uint64_t{5'000U};
    static constexpr auto slow_down_step_ms = std::uint64_t{5'000U};
    // How long one browser holds an entry after it typed the right code or completed a step (ADR-0806): two minutes to
    // type a password, after which another browser may take the entry over.
    static constexpr auto attachment_lease_ms = std::uint64_t{120'000U};
    // How many user codes `create` draws before it gives up on finding one not held. With every entry held, a draw
    // clashes with probability 4096 / 20^8 (about 1.6e-7), so a second draw is already rare.
    static constexpr auto max_user_code_draws = std::size_t{8U};
    // The random bytes one draw takes: eight are needed, and a byte is skipped with probability 1/16.
    static constexpr auto user_code_random_bytes = std::size_t{32U};

    explicit DeviceAuthorisationStore(RandomSource random = {});

    enum class Refusal : std::uint8_t
    {
        // `max_entries` live entries are held.
        store_full,
        // `max_entries_per_address` live entries are held for the client address key.
        address_full,
        // The random source or the hash failed, or no unused user code was drawn.
        secret_unavailable,
    };

    // What `create` hands the device, once.
    struct Started final
    {
        std::string device_code{};
        std::string user_code{};
        std::uint64_t expires_in_ms{0U};
        std::uint64_t interval_ms{0U};
    };

    // Takes a pending authorisation for `client_id`, granted `scope` naming `device_id`, asked from
    // `client_address_key`, valid for `lifetime_ms` from `now_ms`.
    [[nodiscard]] auto create(std::string_view client_id, std::string_view scope, std::string_view device_id,
                              std::string_view client_address_key, std::uint64_t now_ms)
        -> std::variant<Started, Refusal>;

    // The browser that typed the user code now holds the entry. `key` names the entry in the other operations.
    struct Attached final
    {
        std::string key{};
        std::uint64_t attachment{0U};
        DeviceAuthorisation authorisation{};
    };
    // Another browser holds the entry for this much longer.
    struct Busy final
    {
        std::uint64_t retry_after_ms{0U};
    };
    enum class NotFound : std::uint8_t
    {
        // No live pending entry has this user code: unknown, expired, or already answered.
        unknown,
    };

    // Attaches the browser `browser_token` names to the live pending entry `user_code` (stored form) names. The browser
    // already attached is attached again, under a fresh attachment that ends its earlier one.
    [[nodiscard]] auto attach(std::string_view user_code, std::string_view browser_token, std::uint64_t now_ms)
        -> std::variant<Attached, Busy, NotFound>;

    // A copy of the live pending entry `key` names while `attachment` is its latest; nullopt otherwise.
    [[nodiscard]] auto find_attached(std::string_view key, std::uint64_t attachment, std::uint64_t now_ms)
        -> std::optional<DeviceAuthorisation>;

    // Extends the lease of `attachment` to `attachment_lease_ms` from `now_ms`. False, changing nothing, when
    // `find_attached` would answer nullopt.
    [[nodiscard]] auto renew(std::string_view key, std::uint64_t attachment, std::uint64_t now_ms) -> bool;

    // Ends `attachment` when it is the entry's latest, so another browser need not wait for the lease.
    auto release(std::string_view key, std::uint64_t attachment) -> void;

    // Records `user_id`'s answer and ends the attachment. False, changing nothing, when `find_attached` would answer
    // nullopt: the entry ended, was answered, or another browser took it over.
    [[nodiscard]] auto decide(std::string_view key, std::uint64_t attachment, std::string_view user_id, bool approve,
                              std::uint64_t now_ms) -> bool;

    // RFC 8628 section 3.5, in the order the store judges a poll.
    enum class PollOutcome : std::uint8_t
    {
        // No live entry has this device code: never issued, expired, or already redeemed.
        expired_token,
        // The entry was issued to another client.
        wrong_client,
        // Answered no.
        access_denied,
        // Answered yes: the entry is removed and handed back in `PollResult::authorisation`.
        approved,
        // Polled sooner than the interval after the last poll: the interval grows by `slow_down_step_ms`.
        slow_down,
        authorization_pending,
    };
    struct PollResult final
    {
        PollOutcome outcome{PollOutcome::expired_token};
        // The interval in force after this poll.
        std::uint64_t interval_ms{0U};
        std::optional<DeviceAuthorisation> authorisation{};
    };

    // The device's poll with `device_code` as `client_id`. Only `authorization_pending` and `slow_down` record the
    // poll's time; the first poll is never `slow_down`.
    [[nodiscard]] auto poll(std::string_view device_code, std::string_view client_id, std::uint64_t now_ms)
        -> PollResult;

    // How many live entries name `client_id`, after removing the expired ones. No scan.
    [[nodiscard]] auto live_count_for_client(std::string_view client_id, std::uint64_t now_ms) -> std::size_t;
    // Whether a live entry names `client_id`, without changing the store. O(1).
    [[nodiscard]] auto holds_live_entry_for_client(std::string_view client_id, std::uint64_t now_ms) const -> bool;

    // Removes every entry whose lifetime ended at or before `now_ms`.
    auto erase_expired(std::uint64_t now_ms) -> void;

    // Entries held, expired ones not yet removed included.
    [[nodiscard]] auto size() const noexcept -> std::size_t;

private:
    struct Attachment final
    {
        std::uint64_t id{0U};
        std::string browser_token_hash{};
        std::uint64_t lease_until_ms{0U};
    };

    struct Entry final
    {
        DeviceAuthorisation authorisation{};
        std::string user_code_hash{};
        std::optional<Attachment> attachment{};
    };

    template <typename Value>
    using KeyedBy = std::unordered_map<std::string, Value, database::detail::StateGroupKeyHash, std::equal_to<>>;

    // A user code not held now, or nullopt after `max_user_code_draws` clashes or a failure of the source.
    [[nodiscard]] auto draw_user_code() -> std::optional<std::string>;
    // The live pending entry `key` names whose latest attachment is `attachment`, or nullptr.
    [[nodiscard]] auto attached_entry(std::string_view key, std::uint64_t attachment, std::uint64_t now_ms) -> Entry*;
    auto forget(Entry const& entry) -> void;

    RandomSource m_random{};
    HashedSecretTable<Entry> m_entries{};
    // The hash of a user code -> the hash of its entry's device code.
    KeyedBy<std::string> m_by_user_code{};
    KeyedBy<std::size_t> m_count_by_address{};
    KeyedBy<std::multiset<std::uint64_t>> m_expiries_by_client{};
    std::uint64_t m_next_attachment{0U};
};

} // namespace merovingian::homeserver
