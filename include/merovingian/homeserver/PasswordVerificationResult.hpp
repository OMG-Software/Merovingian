// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>

namespace merovingian::homeserver
{

// Result of verifying a password during re-authentication (UIA). `ok` is true
// only when the password is correct AND the account is not currently locked
// out. `retry_after_ms` is non-zero when this device's UIA password-failure
// budget is spent (its own counter, keyed (account, device): /login failures never
// touch it); callers MUST return 429 M_LIMIT_EXCEEDED in that case rather than
// 401 UIA, because further guesses are pointless until the window expires.
// It is also non-zero when the Argon2id admission budget has no free slot (AUTH-4):
// the password was not checked, nothing was counted, and the same 429 applies.
// `ok` is false, with no delay, when the password changed or the session ended
// while it was being verified.
struct PasswordVerificationResult final
{
    bool ok{false};
    std::uint64_t retry_after_ms{0U};
};

} // namespace merovingian::homeserver
