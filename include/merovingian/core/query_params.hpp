// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace merovingian::core
{

struct SyncRequest final
{
    std::optional<std::string> since{};
    std::optional<std::uint64_t> timeout{};
    std::optional<bool> full_state{};
    std::optional<std::string> filter{};
};

[[nodiscard]] auto parse_query_params(std::string_view target) -> SyncRequest;

[[nodiscard]] auto percent_decode(std::string_view encoded) -> std::string;

// Detect literal NUL or a NUL produced by one percent-decoding pass. This is
// allocation-free and does not reject a literal "%00" encoded as "%2500".
[[nodiscard]] auto path_component_contains_nul(std::string_view encoded) noexcept -> bool;

[[nodiscard]] auto percent_decode_path_component(std::string_view encoded) -> std::string;

[[nodiscard]] auto percent_encode_path_component(std::string_view decoded) -> std::string;

} // namespace merovingian::core
