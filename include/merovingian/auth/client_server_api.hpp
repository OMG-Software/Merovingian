// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/auth/session.hpp"
#include "merovingian/auth/token.hpp"
#include "merovingian/database/statement.hpp"
#include "merovingian/http/rate_limit.hpp"

#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

namespace merovingian::auth
{

struct ClientAuthRoute final
{
    std::string method{};
    std::string path_template{};
    ClientAuthEndpoint endpoint{ClientAuthEndpoint::login};
    bool requires_access_token{false};
    bool emits_audit_event{true};
    http::RateLimitPolicy rate_limit{};
};

struct ClientAuthRouteMatch final
{
    bool matched{false};
    ClientAuthRoute route{};
    std::string reason{};
};

struct ClientAuthTokenHashingPlan final
{
    bool issues_token{false};
    bool requires_crypto_random{false};
    bool requires_external_hashing{false};
    bool persists_plaintext_token{false};
    std::size_t token_secret_bytes{0U};
    std::string hash_algorithm{};
};

struct ClientAuthBoundaryPlan final
{
    ClientAuthRoute route{};
    std::vector<database::PreparedStatement> database_statements{};
    ClientAuthTokenHashingPlan token_hashing{};
    ClientAuthAuditEvent audit_event{};
};

[[nodiscard]] auto client_auth_routes() -> std::vector<ClientAuthRoute>;
[[nodiscard]] auto match_client_auth_route(std::string_view method, std::string_view target) -> ClientAuthRouteMatch;
[[nodiscard]] auto client_auth_token_hashing_plan(ClientAuthEndpoint endpoint) -> ClientAuthTokenHashingPlan;
[[nodiscard]] auto client_auth_database_statements(
    ClientAuthEndpoint endpoint,
    std::string_view user_id,
    std::string_view device_id,
    TokenHash const& token_hash
) -> std::vector<database::PreparedStatement>;
[[nodiscard]] auto make_client_auth_boundary_plan(
    ClientAuthRoute const& route,
    std::string_view user_id,
    std::string_view device_id,
    TokenHash const& token_hash,
    bool allowed,
    std::string_view reason
) -> ClientAuthBoundaryPlan;

} // namespace merovingian::auth
