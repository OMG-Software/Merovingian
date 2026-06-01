// SPDX-License-Identifier: GPL-3.0-or-later
//
// Matrix Server-Server API v1.18 conformance for:
//   GET /_matrix/key/v2/server

#include "../support/registration_token.hpp"
#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/homeserver/client_server.hpp"
#include "merovingian/homeserver/http_server.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

namespace
{

[[nodiscard]] auto key_publication_config() -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    merovingian::tests::enable_token_registration(security);

    auto server = merovingian::config::ServerConfig{};
    server.server_name = "example.org";

    return {
        server,
        merovingian::config::ListenersConfig{},
        merovingian::config::DatabaseConfig{},
        security,
    };
}

[[nodiscard]] auto json_get(merovingian::canonicaljson::Object const& obj, std::string const& key)
    -> merovingian::canonicaljson::Value const*
{
    for (auto const& member : obj)
    {
        if (member.key == key)
        {
            return member.value.get();
        }
    }
    return nullptr;
}

} // namespace

// Spec: Matrix Server-Server API v1.18
// Endpoint: GET /_matrix/key/v2/server
// https://spec.matrix.org/v1.18/server-server-api/#get_matrixkeyv2server
SCENARIO("GET /_matrix/key/v2/server returns the spec-required published signing fields",
         "[federation][conformance][key_publishing]")
{
    GIVEN("a started runtime serving the federation HTTP surface")
    {
        auto started = merovingian::homeserver::start_client_server(key_publication_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        WHEN("the local federation router serves GET /_matrix/key/v2/server")
        {
            auto const response = merovingian::homeserver::dispatch_local_http_request(
                runtime, {"GET", "/_matrix/key/v2/server", {}, {}},
                merovingian::homeserver::HttpDispatchMode::federation);

            THEN("the response is 200 with server_name, valid_until_ts, verify_keys, old_verify_keys, and signatures")
            {
                REQUIRE(response.status == 200U);

                auto const parsed = merovingian::canonicaljson::parse_lossless(response.body);
                REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
                auto const* root = std::get_if<merovingian::canonicaljson::Object>(&parsed.value.storage());
                REQUIRE(root != nullptr);

                auto const* server_name_value = json_get(*root, "server_name");
                REQUIRE(server_name_value != nullptr);
                auto const* server_name = std::get_if<std::string>(&server_name_value->storage());
                REQUIRE(server_name != nullptr);
                REQUIRE(*server_name == runtime.homeserver.config.server().server_name);

                auto const* valid_until_value = json_get(*root, "valid_until_ts");
                REQUIRE(valid_until_value != nullptr);
                REQUIRE(std::get_if<std::int64_t>(&valid_until_value->storage()) != nullptr);

                auto const* verify_keys_value = json_get(*root, "verify_keys");
                REQUIRE(verify_keys_value != nullptr);
                auto const* verify_keys =
                    std::get_if<merovingian::canonicaljson::Object>(&verify_keys_value->storage());
                REQUIRE(verify_keys != nullptr);
                REQUIRE_FALSE(verify_keys->empty());
                auto const* verify_key_object =
                    std::get_if<merovingian::canonicaljson::Object>(&verify_keys->front().value->storage());
                REQUIRE(verify_key_object != nullptr);
                REQUIRE(json_get(*verify_key_object, "key") != nullptr);

                auto const* old_verify_keys_value = json_get(*root, "old_verify_keys");
                REQUIRE(old_verify_keys_value != nullptr);
                REQUIRE(std::get_if<merovingian::canonicaljson::Object>(&old_verify_keys_value->storage()) != nullptr);

                auto const* signatures_value = json_get(*root, "signatures");
                REQUIRE(signatures_value != nullptr);
                auto const* signatures = std::get_if<merovingian::canonicaljson::Object>(&signatures_value->storage());
                REQUIRE(signatures != nullptr);
                auto const* local_server_signatures =
                    json_get(*signatures, runtime.homeserver.config.server().server_name);
                REQUIRE(local_server_signatures != nullptr);
                REQUIRE(std::get_if<merovingian::canonicaljson::Object>(&local_server_signatures->storage()) !=
                        nullptr);
            }
        }
    }
}
