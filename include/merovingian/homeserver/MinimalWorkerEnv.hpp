// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>
#include <vector>

namespace merovingian::homeserver
{

// Minimal environment allowlist for the federation worker child (issue #330).
// Passing the full parent environment to posix_spawn would let the worker
// inherit every parent env var, which may include secrets (database URLs, API
// tokens, the master-key passphrase). The worker reads its config and
// master-key file from explicit paths, so it only needs PATH to resolve helper
// binaries (getaddrinfo/NSS lookups, TLS helpers on some hosts). Everything
// else is dropped.
//
// The returned struct owns the "KEY=VALUE" string storage; `argv` is a
// null-terminated array of pointers into `entries`, suitable for the envp
// argument of posix_spawn. Both vectors must outlive the spawn call.
struct MinimalWorkerEnv final
{
    std::vector<std::string> entries{};
    // NOLINTNEXTLINE(*-avoid-c-arrays) — posix_spawn requires char* const*
    std::vector<char const*> argv{};
};

// Builds the minimal PATH-only environment for a worker child. When the
// parent has no PATH (unusual but possible under hardened systemd units), a
// sensible default PATH is provided so the child can still resolve NSS/TLS
// helpers.
[[nodiscard]] auto build_minimal_worker_env() -> MinimalWorkerEnv;

} // namespace merovingian::homeserver