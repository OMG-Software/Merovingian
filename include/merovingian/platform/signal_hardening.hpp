// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/platform/runtime_hardening.hpp"

namespace merovingian::platform
{

// Sets the process-wide disposition of SIGPIPE to SIG_IGN with sigaction(2)
// (HTTP-5, security-audit-report-2026-09-29.md).
//
// With the default disposition, a write() to a socket or pipe whose peer has
// gone terminates the whole process. OpenSSL's socket BIO writes with plain
// write(), without MSG_NOSIGNAL, so a TLS client that completes the handshake
// and then resets the connection would otherwise kill the server on the
// error response the server sends back. With SIGPIPE ignored the same write
// fails with EPIPE, which every caller already handles.
//
// Every executable's main() must call this before it starts any thread, and
// must exit non-zero when the returned decision is not accepted: continuing
// with the default disposition leaves the process one hostile connection away
// from a crash (fail closed). The call is idempotent. sigaction() is invoked
// before any seccomp filter is installed, so rt_sigaction need not be on any
// allowlist for this to succeed.
//
// A failed decision has fail_closed = true and a reason naming the errno.
[[nodiscard]] auto ignore_sigpipe() noexcept -> HardeningPlanDecision;

} // namespace merovingian::platform
