// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <list>
#include <optional>
#include <string_view>
#include <unordered_map>

namespace merovingian::auth
{

// AUTH-10 (security-audit-report-2026-09-29.md). Upper bound on the number of
// counters one FailureWindowTable keeps. A counter is a few dozen bytes, so the
// bound is a few megabytes per table whatever an unauthenticated client sends.
inline constexpr auto max_failure_window_entries = std::size_t{100000U};

// Fixed-size identity of a counted subject: an unkeyed BLAKE2b-256 digest of the
// subject kind and its parts. Fixed size means a client-chosen 60 KiB user ID
// costs the same as a short one. Unkeyed is enough: the table lives in process
// memory, and a 256-bit collision-resistant digest means a client cannot choose
// a name that lands on somebody else's counter.
struct FailureKey final
{
    std::array<std::uint8_t, 32U> digest{};

    [[nodiscard]] friend auto operator==(FailureKey const&, FailureKey const&) noexcept -> bool = default;
};

// Builds the key for `kind` (a short fixed label, e.g. "source") applied to
// `account` and `qualifier` (a client source, or a device ID). The account is
// length-prefixed, so ("ab", "c") and ("a", "bc") can never share a key even
// though both parts are client-controlled. Returns std::nullopt only if
// libsodium fails; callers must then fail closed.
[[nodiscard]] auto make_failure_key(std::string_view kind, std::string_view account, std::string_view qualifier)
    -> std::optional<FailureKey>;

// A bounded table of failure counters with a time window.
//
// Each key counts failures inside a fixed window that opens at its first
// failure. When the count reaches the caller's threshold the window is restarted
// at that failure, so the key stays refused for one full window from the failure
// that tripped it. A key whose window has elapsed no longer counts and is
// dropped.
//
// Entries are kept in a list ordered by window start, which is also expiry
// order. Expiry therefore only ever pops the front: each operation is amortised
// O(1) with no scan of the table. When the table is full a new key evicts the
// oldest entry (the one nearest to expiry anyway).
//
// Not thread-safe: the caller serialises access. The runtime holds
// HomeserverRuntime::mutex around every call.
class FailureWindowTable final
{
public:
    using Clock = std::chrono::steady_clock;

    explicit FailureWindowTable(std::size_t capacity = max_failure_window_entries) noexcept;

    // Time left before `key` may try again, or zero when it is not refused. A key
    // is refused once it has `threshold` failures inside `window`.
    [[nodiscard]] auto lockout_remaining(FailureKey const& key, Clock::time_point now, Clock::duration window,
                                         std::uint32_t threshold) -> Clock::duration;

    // Counts one failure for `key`.
    auto record_failure(FailureKey const& key, Clock::time_point now, Clock::duration window, std::uint32_t threshold)
        -> void;

    // Forgets `key`.
    auto clear(FailureKey const& key) -> void;

    // Failures counted for `key` inside `window` (zero when none).
    [[nodiscard]] auto failures(FailureKey const& key, Clock::time_point now, Clock::duration window) -> std::uint32_t;

    [[nodiscard]] auto size() const noexcept -> std::size_t;
    [[nodiscard]] auto capacity() const noexcept -> std::size_t;

private:
    struct Entry final
    {
        FailureKey key{};
        std::uint32_t count{0U};
        Clock::time_point window_start{};
    };

    struct KeyHash final
    {
        [[nodiscard]] auto operator()(FailureKey const& key) const noexcept -> std::size_t;
    };

    using Order = std::list<Entry>;

    auto expire(Clock::time_point now, Clock::duration window) -> void;

    std::size_t capacity_;
    Order order_{};
    std::unordered_map<FailureKey, Order::iterator, KeyHash> index_{};
};

} // namespace merovingian::auth
