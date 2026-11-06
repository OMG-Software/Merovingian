// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>

namespace merovingian::config
{

// ADR-0246 (refines ADR-0090): how many Argon2id hashes (password logins, registrations,
// user-interactive password checks, registration-token checks) the process runs at once. A
// request past it is answered 429 M_LIMIT_EXCEEDED before any hash work. 1 to
// max_password_hashing_concurrency; taken at start-up.
inline constexpr std::uint32_t max_password_hashing_concurrency = 128U;
struct PasswordHashingConfig final
{
    std::uint32_t max_concurrent{4U};
};

} // namespace merovingian::config
