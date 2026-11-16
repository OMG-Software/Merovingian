// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/StateGroupKeyHash.hpp"

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

// The wrong user codes typed on the link page, counted per client address key (RFC 8628 section 5.1; plan P11;
// ADR-0805). A user code has about 34.5 bits; five wrong codes in ten minutes per address keeps a guesser's chance
// of hitting any of the `DeviceAuthorisationStore::max_entries` live codes in a window below 1 in 10^6.
//
// A window starts at an address's first wrong code and lasts `window_ms`. Once `max_wrong_codes` were wrong in it, the
// address is blocked until the window ends: the page is not looked up at all, so the right code is refused too.
//
// Bounded: at most `max_addresses` windows. At the cap the ended windows are removed; if every window is still live an
// address with no window is blocked until the soonest one ends (it fails closed, ADR-0805), so a flood of addresses
// cannot lift the limit for itself. Every operation takes the current time. Not thread-safe: `runtime.mutex`
// serialises every use (`HomeserverRuntime::oauth_user_code_attempts`).
class UserCodeAttemptThrottle final
{
public:
    static constexpr auto window_ms = std::uint64_t{600'000U};
    static constexpr auto max_wrong_codes = std::uint32_t{5U};
    // Each window is a key and two integers; 8192 is far more addresses than type codes in ten minutes, and the table
    // stays well under a MiB.
    static constexpr auto max_addresses = std::size_t{8192U};

    // How long `client_key` must still wait before a code it types is looked up, or nullopt when it may try now.
    [[nodiscard]] auto blocked_for_ms(std::string_view client_key, std::uint64_t now_ms)
        -> std::optional<std::uint64_t>;

    // Counts one wrong code for `client_key`. True when this one reached `max_wrong_codes`, so the caller logs the
    // block once. An address the table has no room for is not counted (it is already blocked by `blocked_for_ms`).
    [[nodiscard]] auto record_wrong(std::string_view client_key, std::uint64_t now_ms) -> bool;

    // Windows held, ended ones not yet removed included.
    [[nodiscard]] auto size() const noexcept -> std::size_t;

private:
    struct Window final
    {
        std::uint64_t ends_at_ms{0U};
        std::uint64_t sequence{0U};
        std::uint32_t wrong{0U};
    };
    using Order = std::pair<std::uint64_t, std::uint64_t>;

    auto erase_ended(std::uint64_t now_ms) -> void;

    std::unordered_map<std::string, Window, database::detail::StateGroupKeyHash, std::equal_to<>> m_windows{};
    // (ends_at_ms, sequence) -> client key, soonest end first.
    std::map<Order, std::string> m_by_end{};
    std::uint64_t m_next_sequence{0U};
};

} // namespace merovingian::homeserver
