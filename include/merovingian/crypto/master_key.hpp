// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <optional>
#include <string_view>
#include <vector>

namespace merovingian::crypto
{

// Load operator-supplied master key material from the configured file.
//
// The file is read in binary mode and capped at 4096 bytes. Returns nullopt if
// the path is empty, the file cannot be opened, is empty, or exceeds the cap.
//
// This loader is shared between the main process and the federation worker
// process so both can independently derive the same keys (e.g. the v4
// access-token HMAC key and the IPC channel auth key) from the same master
// key file without ever transmitting the material across the IPC boundary.
[[nodiscard]] auto load_master_key_material(std::string_view path) -> std::optional<std::vector<std::uint8_t>>;

} // namespace merovingian::crypto