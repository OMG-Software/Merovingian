// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace merovingian::homeserver
{

struct HomeserverRuntime;

// Password reset by email (ADR-0481). The emailed code is 8 characters of this alphabet (40 bits, no 0/O/1/I): it
// is typed by a person, so it is short, and it is guarded by a cap on tries per session instead of by length.
inline constexpr auto password_reset_token_alphabet = std::string_view{"ABCDEFGHJKLMNPQRSTUVWXYZ23456789"};
inline constexpr auto password_reset_token_length = std::size_t{8U};
// Wrong codes a session accepts before it is dropped.
inline constexpr auto password_reset_max_token_attempts = std::uint8_t{5U};
// Reset emails being sent at once (counted by HomeserverRuntime::password_reset_sends_in_flight_, nothing else);
// one more is dropped (the user asks again) rather than queued.
inline constexpr auto password_reset_max_sends_in_flight = std::size_t{8U};
// One reset email per address per this long, across every session (ADR-0481): requestToken is unauthenticated and
// mails an address the caller names, so a new client_secret or a higher send_attempt must not mean another email.
inline constexpr auto password_reset_address_interval_ms = std::uint64_t{60'000U};
// And at most this many per address in any password_reset_address_window_ms (a day), whoever asks (C17, ADR-0685). Past
// it a request is answered like a throttled one, and the code already mailed stays valid for every session of the
// address.
inline constexpr auto password_reset_address_daily_cap = std::size_t{10U};
inline constexpr auto password_reset_address_window_ms = std::uint64_t{86'400'000U};

[[nodiscard]] auto make_password_reset_token() -> std::optional<std::string>;

// The code as typed, made comparable: upper case, the way make_password_reset_token writes it. The Identity Service
// API lets a validator match a token case-insensitively.
[[nodiscard]] auto normalize_password_reset_token(std::string_view typed) -> std::string;

// Sends the code to `recipient` from a background task, so the SMTP exchange (the slow part: a connection, TLS,
// several round trips) is never on the request thread, whether or not there was anyone to send to. Building the
// message and starting the task still happen only for an address with an account, a small local difference that
// the rate limit on requestToken bounds. The caller holds runtime.mutex; the task reads nothing from the runtime
// (it takes a copy of the relay settings) and sends with no lock. Returns false when the code was not queued: no
// relay configured, a build failure, or password_reset_max_sends_in_flight sends already running.
auto send_password_reset_email(HomeserverRuntime& runtime, std::string recipient, std::string token) -> bool;

} // namespace merovingian::homeserver
