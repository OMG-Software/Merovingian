// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include "merovingian/core/SyncRequest.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace merovingian::core
{

[[nodiscard]] auto parse_query_params(std::string_view target) -> SyncRequest;

[[nodiscard]] auto percent_decode(std::string_view encoded) -> std::string;

// The percent-decoded value of the first `name` parameter in the query string of `target`, or "" when it is absent or
// has no `=`. The one reader of a single named parameter: the federation handlers and the worker relay binding
// (ADR-0595) read through it, so a relay's argument and the handler's cannot differ.
[[nodiscard]] auto query_parameter(std::string_view target, std::string_view name) -> std::string;

// Detect literal NUL or a NUL produced by one percent-decoding pass. This is
// allocation-free and does not reject a literal "%00" encoded as "%2500".
[[nodiscard]] auto path_component_contains_nul(std::string_view encoded) noexcept -> bool;

[[nodiscard]] auto percent_decode_path_component(std::string_view encoded) -> std::string;

[[nodiscard]] auto percent_encode_path_component(std::string_view decoded) -> std::string;

} // namespace merovingian::core
