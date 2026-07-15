// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/core/secret_buffer.hpp"

#include <cstdint>
#include <optional>
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

} // namespace merovingian::crypto