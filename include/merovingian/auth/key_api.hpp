// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/auth/KeyApiBoundaryPlan.hpp"
#include "merovingian/auth/KeyApiEndpoint.hpp"
#include "merovingian/auth/KeyApiRoute.hpp"
#include "merovingian/auth/KeyApiRouteMatch.hpp"
#include "merovingian/database/PreparedStatement.hpp"

#include <string>
#include <string_view>
#include <vector>

namespace merovingian::auth
{

[[nodiscard]] auto key_api_endpoint_name(KeyApiEndpoint endpoint) noexcept -> char const*;
[[nodiscard]] auto key_api_routes() -> std::vector<KeyApiRoute>;
[[nodiscard]] auto match_key_api_route(std::string_view method, std::string_view target) -> KeyApiRouteMatch;
[[nodiscard]] auto key_api_database_statements(KeyApiEndpoint endpoint, std::string_view user_id,
                                               std::string_view device_id) -> std::vector<database::PreparedStatement>;
[[nodiscard]] auto make_key_api_boundary_plan(KeyApiRoute const& route, std::string_view user_id,
                                              std::string_view device_id) -> KeyApiBoundaryPlan;
[[nodiscard]] auto key_payload_is_loggable(std::string_view payload) noexcept -> bool;
[[nodiscard]] auto redacted_key_payload_summary(std::string_view payload) -> std::string;

} // namespace merovingian::auth
