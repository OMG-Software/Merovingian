// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>
#include <string_view>

namespace merovingian::http
{

// The prefix length used to group IPv6 clients when none is configured. One
// IPv6 end site is routinely handed a whole /64, so a per-address limit would
// let one client rotate through 2^64 addresses.
inline constexpr std::uint8_t default_ipv6_client_prefix_length = 64U;

// The key under which a client address is counted by per-client limits (the
// per-IP connection cap and the rate limiter).
//   - An IPv4 literal is its own key, in dotted-quad form.
//   - An IPv4-mapped IPv6 literal (::ffff:a.b.c.d) is keyed as the IPv4
//     address it carries, so a dual-stack listener cannot count one client
//     twice.
//   - Any other IPv6 literal is masked to `ipv6_prefix_length` bits and keyed
//     as "<network>/<length>" (1..128; out-of-range values are clamped).
//   - Anything that is not an IP literal is returned unchanged, so it still
//     gets a bucket of its own rather than bypassing the limit.
[[nodiscard]] auto client_address_key(std::string_view address, std::uint8_t ipv6_prefix_length) -> std::string;

} // namespace merovingian::http
