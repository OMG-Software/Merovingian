// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/core/secret_buffer.hpp"
#include "merovingian/crypto/secret_box.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace merovingian::crypto
{

// Load operator-supplied master key material from the configured file.
//
// The file is read in binary mode and capped at 4096 bytes. Returns nullopt if
// the path is empty, the file cannot be opened, is empty, or exceeds the cap.
// The returned buffer is mlocked and zeroised on destruction (core::SecretBuffer)
// — this is the root secret every derived key (access-token HMAC, secret-box,
// IPC auth) is derived from, so it must not survive past its scope in
// ordinary, unwiped process memory.
//
// This loader is shared between the main process and the federation worker
// process so both can independently derive the same keys (e.g. the v4
// access-token HMAC key and the IPC channel auth key) from the same master
// key file without ever transmitting the material across the IPC boundary.
[[nodiscard]] auto load_master_key_material(std::string_view path) -> std::optional<core::SecretBuffer>;

// Fail-closed policy for the loaded root secret.
//
// 0.12.5 security audit, finding 2: a failed sodium_mlock used to be warn-only,
// so a server that had exhausted RLIMIT_MEMLOCK silently continued with the key
// every other key is derived from sitting in swappable, core-dumpable memory.
// Refusing to load is the fail-closed answer: an unlocked root secret is a
// crypto-boundary failure, and the remedy (raise RLIMIT_MEMLOCK, or grant
// CAP_IPC_LOCK) is a one-line deployment change.
//
// Split out as a pure predicate so the policy is directly testable without
// having to provoke an mlock failure inside the test process.
[[nodiscard]] auto master_key_material_is_acceptable(bool locked) noexcept -> bool;

// Cheap identity of the master key file, used to invalidate derived-key caches
// without re-reading the root secret.
//
// Identity, not a digest: callers use it precisely to avoid reading the key, so
// it must not read it. (path, size, mtime) alone is not enough — replacing a
// fixed-length key with `cp -p`, with reproducible secret-deployment tooling, or
// on a filesystem with coarse timestamps preserves all three. st_dev/st_ino
// catch a replace-by-rename (how atomic secret rotation is normally done) and
// st_ctime catches an in-place overwrite, since the inode change time is updated
// on any write and, unlike st_mtime, cannot be set backwards with utimes(2).
//
// Returns an empty string if the file cannot be stat()-ed. An empty identity
// never compares equal to a cached one, so an unreadable file falls through to a
// fresh (and failing) load rather than serving keys for a file that has since
// gone away.
[[nodiscard]] auto master_key_file_identity(std::string_view path) -> std::string;

// The secret-box key used to encrypt server signing secrets at rest, derived
// from the master key file and cached against that file's identity.
//
// 0.12.5 security audit, finding 3: the signing-secret encrypt and decrypt paths
// each re-read the master key file and re-derived this key on every call, which
// re-materialised the root secret and churned a 4 KiB sodium_mlock/munlock pair
// per operation — the same problem #487 fixed for the access-token HMAC keys.
// Caching on the file identity keeps the steady-state cost at one stat(), while
// still picking up a rotated master key file without a restart.
[[nodiscard]] auto signing_secret_box_key(std::string_view path) -> std::optional<SecretBoxKey>;

} // namespace merovingian::crypto