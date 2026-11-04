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
// Sends in flight at once; one more is dropped (the user asks again) rather than queued.
inline constexpr auto password_reset_max_sends_in_flight = std::size_t{8U};

[[nodiscard]] auto make_password_reset_token() -> std::optional<std::string>;

// The code as typed, made comparable: upper case, the way make_password_reset_token writes it. The Identity Service
// API lets a validator match a token case-insensitively.
[[nodiscard]] auto normalize_password_reset_token(std::string_view typed) -> std::string;

// Sends the code to `recipient` from a background task, so the request that asked for it answers at the same speed
// whether or not there was anyone to send to (no account-enumeration timing oracle). The caller holds
// runtime.mutex; the task reads nothing from the runtime (it takes a copy of the relay settings) and sends with no
// lock. Returns false when the code was not queued: no relay configured, a build failure, or the cap reached.
auto send_password_reset_email(HomeserverRuntime& runtime, std::string recipient, std::string token) -> bool;

} // namespace merovingian::homeserver
