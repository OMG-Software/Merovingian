// SPDX-License-Identifier: GPL-3.0-or-later
#include "../support/in_memory_database_config.hpp"
//
// +-------------------------------------------------------------------------+
// |          THIRD-PARTY LOOKUPS — END-TO-END APPSERVICE INTEGRATION        |
// |                                                                         |
// |  Spec: Matrix Client-Server API v1.19 "Third-party Lookups"            |
// |  URL:  ../../docs/matrix-v1.19-spec/client-server-api.md                |
// |  Spec: Matrix Application Service API v1.19 "Third-party networks"     |
// |  URL:  ../../docs/matrix-v1.19-spec/application-service-api.md          |
// |                                                                         |
// |  Drives GET /_matrix/client/v3/thirdparty/* against a real local mock  |
// |  appservice (plain HTTP — appservice traffic is cleartext by design,   |
// |  see AppserviceClient.hpp's allow_cleartext_http doc comment, so no   |
// |  TLS handshake is needed here unlike tests/support/tls_mock_server.hpp |
// |  push/identity-server mocks; accept_loopback/json_http_response/       |
// |  ScopedThreadJoin are reused from there since they are not actually    |
// |  TLS-specific). Proves: instance_id minting on /protocol and           |
// |  /protocols, alias/userid aggregation, hs_token Bearer auth reaching   |
// |  the appservice, and — the resilience guarantee this whole feature     |
// |  depends on — an unreachable appservice degrading to "no results"      |
// |  rather than failing or hanging the request when other appservices     |
// |  can still answer.                                                     |
// +-------------------------------------------------------------------------+

#include "../support/MockAppservice.hpp"
#include "../support/ScopedThreadJoin.hpp"
#include "../support/appservice_test_config.hpp"
#include "../support/json_test_support.hpp"
#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "../support/tls_mock_server.hpp"
#include "merovingian/config/ClientRateLimitsConfig.hpp"
#include "merovingian/config/Config.hpp"
#include "merovingian/config/ListenersConfig.hpp"
#include "merovingian/config/LogModulesConfig.hpp"
#include "merovingian/config/SecurityConfig.hpp"
#include "merovingian/config/ServerConfig.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"
#include "merovingian/homeserver/client_outbound_proxy.hpp"
#include "merovingian/net/TcpAcceptor.hpp"

#include <catch2/catch_test_macros.hpp>
#include <poll.h>
#include <unistd.h>

#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>
#include <thread>
#include <tuple>
#include <variant>
#include <vector>

namespace
{

using namespace merovingian::tests;

// One-shot plain-HTTP mock appservice: accepts a single connection, reads
// until the header terminator, writes the configured response, and closes.
// Reuses tls_mock::accept_loopback for the bounded-timeout accept (it is a
// plain POSIX accept()/poll() wrapper with nothing TLS-specific about it).
auto run_one_shot_appservice_server(merovingian::net::TcpAcceptor& acceptor, std::string const& http_response,
                                    std::string* captured_request = nullptr) noexcept -> void
{
    auto const client_fd = merovingian::tests::tls_mock::accept_loopback(acceptor, 5000);
    if (client_fd < 0)
    {
        return;
    }
    auto buffer = std::array<char, 8192>{};
    auto request_bytes = std::string{};
    while (request_bytes.find("\r\n\r\n") == std::string::npos)
    {
        auto const bytes_read = ::read(client_fd, buffer.data(), buffer.size());
        if (bytes_read <= 0)
        {
            break;
        }
        request_bytes.append(buffer.data(), static_cast<std::size_t>(bytes_read));
        if (static_cast<std::size_t>(bytes_read) < buffer.size())
        {
            break;
        }
    }
    if (captured_request != nullptr)
    {
        *captured_request = request_bytes;
    }
    std::ignore = ::write(client_fd, http_response.data(), http_response.size());
    ::close(client_fd);
}

[[nodiscard]] auto thirdparty_test_config() -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    // A runtime refuses to mint a signing secret it cannot encrypt at rest
    // (0.12.5 audit, finding 1), so every fixture needs a master key.
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    merovingian::tests::enable_token_registration(security);
    return {
        merovingian::config::ServerConfig{},
        merovingian::config::ListenersConfig{},
        merovingian::tests::in_memory_database_config(),
        security,
        merovingian::config::ClientRateLimitsConfig{},
        merovingian::config::LogModulesConfig{},
    };
}

[[nodiscard]] auto register_and_login(merovingian::homeserver::ClientServerRuntime& runtime,
                                      std::string const& localpart) -> std::string
{
    auto const reg = merovingian::homeserver::handle_client_server_request(
        runtime, {"POST", "/_matrix/client/v3/register", {}, registration_json(localpart, "CorrectHorse7!")});
    REQUIRE(reg.response.status == 200U);
    auto const body = parse_object(reg.response.body);
    auto const* token = string_member(body, "access_token");
    REQUIRE(token != nullptr);
    return *token;
}

// Writes a registration file declaring `protocols` and pointing `url` at a
// loopback mock appservice, and returns a Config wired to load it.
[[nodiscard]] auto config_with_appservice(std::filesystem::path const& registration_path, std::string const& id,
                                          std::string const& as_token, std::string const& hs_token,
                                          std::uint16_t mock_port, std::vector<std::string> const& protocols)
    -> merovingian::config::Config
{
    auto protocols_json = std::string{"["};
    for (auto index = std::size_t{0U}; index < protocols.size(); ++index)
    {
        if (index != 0U)
        {
            protocols_json += ",";
        }
        protocols_json += "\"" + protocols[index] + "\"";
    }
    protocols_json += "]";

    {
        auto out = std::ofstream{registration_path, std::ios::binary};
        out << R"({
            "id": ")"
            << id << R"(",
            "url": "http://127.0.0.1:)"
            << mock_port << R"(",
            "as_token": ")"
            << as_token << R"(",
            "hs_token": ")"
            << hs_token << R"(",
            "sender_localpart": "_)"
            << id << R"(_bot",
            "namespaces": {"users": [], "aliases": [], "rooms": []},
            "protocols": )"
            << protocols_json << R"(
        })";
    }
    auto config = thirdparty_test_config();
    config.appservice().registration_files = {registration_path.string()};
    return config;
}

} // namespace

// Spec: AS API "GET /_matrix/app/v1/thirdparty/protocol/{protocol}" is
// "modified by the homeserver ... to include an instance_id"; CS API
// "GET /_matrix/client/v3/thirdparty/protocol/{protocol}" returns that
// modified Protocol object.
SCENARIO("GET /thirdparty/protocol/{protocol} returns the appservice's Protocol object with a minted instance_id",
         "[appservice][integration][thirdparty]")
{
    GIVEN("an appservice registered for 'irc' and a mock server that answers its protocol query")
    {
        auto const path = std::filesystem::temp_directory_path() / "merovingian-thirdparty-protocol.json";
        auto acceptor = merovingian::net::TcpAcceptor{};
        REQUIRE(acceptor.bind("127.0.0.1", 0U).ok);
        auto const port = acceptor.bound_port();
        REQUIRE(port > 0U);

        auto const config = config_with_appservice(path, "irc-bridge", "irc-as-token", "irc-hs-token", port, {"irc"});
        auto started = merovingian::homeserver::start_client_server(config);
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const token = register_and_login(runtime, "alice");

        auto const protocol_body = R"({
            "field_types": {"network": {"placeholder": "irc.example.org", "regexp": "([a-z0-9]+\\.)*[a-z0-9]+"}},
            "icon": "mxc://example.org/aBcDeFgH",
            "instances": [{"desc": "Freenode", "fields": {"network": "freenode"}, "network_id": "freenode"}],
            "location_fields": ["network", "channel"],
            "user_fields": ["network", "nickname"]
        })";
        auto captured_request = std::string{};
        auto server_thread = std::thread{[&] {
            run_one_shot_appservice_server(
                acceptor, merovingian::tests::tls_mock::json_http_response("200 OK", protocol_body), &captured_request);
        }};
        auto const join = merovingian::tests::tls_mock::ScopedThreadJoin{server_thread};

        WHEN("GET /_matrix/client/v3/thirdparty/protocol/irc is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/thirdparty/protocol/irc", token, {}});
            if (server_thread.joinable())
            {
                server_thread.join();
            }

            THEN("it returns 200 with the appservice's fields plus a homeserver-minted instance_id")
            {
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);
                auto const* icon = string_member(body, "icon");
                REQUIRE(icon != nullptr);
                CHECK(*icon == "mxc://example.org/aBcDeFgH");
                auto const* instances = object_member_as_array(body, "instances");
                REQUIRE(instances != nullptr);
                REQUIRE(instances->size() == 1U);
                auto const* instance_object =
                    std::get_if<merovingian::canonicaljson::Object>(&(*instances)[0].storage());
                REQUIRE(instance_object != nullptr);
                auto const* instance_id = string_member(*instance_object, "instance_id");
                // Spec: instance_id is added BY THE HOMESERVER — the mock
                // appservice's response above never set it.
                REQUIRE(instance_id != nullptr);
                CHECK_FALSE(instance_id->empty());
                CHECK(instance_id->find("irc-bridge") != std::string::npos);
            }

            AND_THEN("the outbound request carried the hs_token as a Bearer credential")
            {
                CHECK(captured_request.find("GET /_matrix/app/v1/thirdparty/protocol/irc") != std::string::npos);
                CHECK(captured_request.find("Authorization: Bearer irc-hs-token") != std::string::npos);
            }
        }

        std::filesystem::remove(path);
    }
}

// Spec: "/protocols ... Dictionary of supported third-party protocols" —
// aggregated from every registered appservice's declared `protocols` list.
SCENARIO("GET /thirdparty/protocols aggregates protocols across every registered appservice",
         "[appservice][integration][thirdparty]")
{
    GIVEN("one appservice registered for 'irc' with a mock server behind it")
    {
        auto const path = std::filesystem::temp_directory_path() / "merovingian-thirdparty-protocols.json";
        auto acceptor = merovingian::net::TcpAcceptor{};
        REQUIRE(acceptor.bind("127.0.0.1", 0U).ok);
        auto const port = acceptor.bound_port();
        REQUIRE(port > 0U);

        auto const config = config_with_appservice(path, "irc-bridge", "irc-as-token", "irc-hs-token", port, {"irc"});
        auto started = merovingian::homeserver::start_client_server(config);
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const token = register_and_login(runtime, "bob");

        auto const protocol_body = R"({
            "field_types": {}, "icon": "mxc://example.org/x",
            "instances": [], "location_fields": [], "user_fields": []
        })";
        auto server_thread = std::thread{[&] {
            run_one_shot_appservice_server(acceptor,
                                           merovingian::tests::tls_mock::json_http_response("200 OK", protocol_body));
        }};
        auto const join = merovingian::tests::tls_mock::ScopedThreadJoin{server_thread};

        WHEN("GET /_matrix/client/v3/thirdparty/protocols is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/thirdparty/protocols", token, {}});
            if (server_thread.joinable())
            {
                server_thread.join();
            }

            THEN("the response's top-level dictionary carries an 'irc' key")
            {
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);
                auto const* irc = object_member_as_object(body, "irc");
                REQUIRE(irc != nullptr);
            }
        }

        std::filesystem::remove(path);
    }
}

// Spec: "GET /thirdparty/location ... alias: The Matrix room alias to look
// up ... 200 | All found third-party locations."
SCENARIO("GET /thirdparty/location aggregates Location results for a room alias",
         "[appservice][integration][thirdparty]")
{
    GIVEN("an appservice whose mock server answers an alias lookup")
    {
        auto const path = std::filesystem::temp_directory_path() / "merovingian-thirdparty-location-alias.json";
        auto acceptor = merovingian::net::TcpAcceptor{};
        REQUIRE(acceptor.bind("127.0.0.1", 0U).ok);
        auto const port = acceptor.bound_port();
        REQUIRE(port > 0U);

        auto const config = config_with_appservice(path, "irc-bridge", "irc-as-token", "irc-hs-token", port, {"irc"});
        auto started = merovingian::homeserver::start_client_server(config);
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const token = register_and_login(runtime, "carol");

        auto const location_body = R"([
            {"alias": "#freenode_#matrix:example.org", "fields": {"channel": "#matrix", "network": "freenode"}, "protocol": "irc"}
        ])";
        auto captured_request = std::string{};
        auto server_thread = std::thread{[&] {
            run_one_shot_appservice_server(
                acceptor, merovingian::tests::tls_mock::json_http_response("200 OK", location_body), &captured_request);
        }};
        auto const join = merovingian::tests::tls_mock::ScopedThreadJoin{server_thread};

        WHEN("GET /_matrix/client/v3/thirdparty/location?alias=... is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime,
                {"GET", "/_matrix/client/v3/thirdparty/location?alias=%23freenode_%23matrix%3Aexample.org", token, {}});
            if (server_thread.joinable())
            {
                server_thread.join();
            }

            THEN("it returns 200 with the appservice's Location array")
            {
                REQUIRE(response.response.status == 200U);
                CHECK(response.response.body.find("#freenode_#matrix:example.org") != std::string::npos);
                CHECK(response.response.body.find("\"protocol\":\"irc\"") != std::string::npos);
            }

            AND_THEN("the outbound request carried the alias as a query parameter")
            {
                CHECK(captured_request.find("GET /_matrix/app/v1/thirdparty/location?alias=") != std::string::npos);
            }
        }

        std::filesystem::remove(path);
    }
}

// This is the resilience guarantee the aggregation design depends on: an
// unreachable appservice must degrade to "no results" for the routes it
// would have contributed to, not fail or hang the whole client request.
// Mirrors test_push_delivery_flow.cpp's "message sending succeeds even when
// the recipient's push gateway is unreachable" scenario.
SCENARIO("an unreachable appservice degrades to 404 instead of failing or hanging the request",
         "[appservice][integration][thirdparty]")
{
    GIVEN("an appservice registered for 'irc' whose URL points at a closed local port")
    {
        auto const path = std::filesystem::temp_directory_path() / "merovingian-thirdparty-unreachable.json";
        // Reserve a loopback port, then let the acceptor close before any
        // client connects — the port refuses connections, standing in for
        // an unreachable appservice.
        auto closed_port = std::uint16_t{0U};
        {
            auto reservation = merovingian::net::TcpAcceptor{};
            REQUIRE(reservation.bind("127.0.0.1", 0U).ok);
            closed_port = reservation.bound_port();
            REQUIRE(closed_port > 0U);
        }

        auto const config =
            config_with_appservice(path, "irc-bridge", "irc-as-token", "irc-hs-token", closed_port, {"irc"});
        auto started = merovingian::homeserver::start_client_server(config);
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const token = register_and_login(runtime, "dave");

        WHEN("GET /_matrix/client/v3/thirdparty/protocol/irc is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/thirdparty/protocol/irc", token, {}});

            THEN("the request completes (does not hang) and reports 404 rather than a transport error")
            {
                REQUIRE(response.response.status == 404U);
                CHECK(response.response.body.find("M_NOT_FOUND") != std::string::npos);
            }
        }

        WHEN("GET /_matrix/client/v3/thirdparty/protocols is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/thirdparty/protocols", token, {}});

            THEN("the aggregate response degrades to an empty object rather than failing the whole request")
            {
                REQUIRE(response.response.status == 200U);
                CHECK(response.response.body == "{}");
            }
        }

        std::filesystem::remove(path);
    }
}

// Two appservices declare the SAME protocol name; one is unreachable and one
// answers. The unreachable one must not prevent the reachable one's answer
// from being served — "degrade to the results you have" per the task this
// route exists for.
SCENARIO("one appservice being unreachable does not suppress another appservice's answer for the same protocol",
         "[appservice][integration][thirdparty]")
{
    GIVEN("two appservices both declaring 'irc': one unreachable, one backed by a real mock server")
    {
        auto const unreachable_path = std::filesystem::temp_directory_path() / "merovingian-thirdparty-multi-a.json";
        auto const reachable_path = std::filesystem::temp_directory_path() / "merovingian-thirdparty-multi-b.json";

        auto closed_port = std::uint16_t{0U};
        {
            auto reservation = merovingian::net::TcpAcceptor{};
            REQUIRE(reservation.bind("127.0.0.1", 0U).ok);
            closed_port = reservation.bound_port();
            REQUIRE(closed_port > 0U);
        }
        auto acceptor = merovingian::net::TcpAcceptor{};
        REQUIRE(acceptor.bind("127.0.0.1", 0U).ok);
        auto const reachable_port = acceptor.bound_port();
        REQUIRE(reachable_port > 0U);

        // Two separate registration files, both declaring the 'irc' protocol.
        {
            auto out = std::ofstream{unreachable_path, std::ios::binary};
            out << R"({"id":"irc-a","url":"http://127.0.0.1:)" << closed_port
                << R"(","as_token":"irc-a-as-token","hs_token":"irc-a-hs-token",)"
                << R"("sender_localpart":"_irc_a_bot","namespaces":{"users":[],"aliases":[],"rooms":[]},)"
                << R"("protocols":["irc"]})";
        }
        {
            auto out = std::ofstream{reachable_path, std::ios::binary};
            out << R"({"id":"irc-b","url":"http://127.0.0.1:)" << reachable_port
                << R"(","as_token":"irc-b-as-token","hs_token":"irc-b-hs-token",)"
                << R"("sender_localpart":"_irc_b_bot","namespaces":{"users":[],"aliases":[],"rooms":[]},)"
                << R"("protocols":["irc"]})";
        }
        auto config = thirdparty_test_config();
        config.appservice().registration_files = {unreachable_path.string(), reachable_path.string()};
        auto started = merovingian::homeserver::start_client_server(config);
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const token = register_and_login(runtime, "erin");

        auto const location_body = R"([
            {"alias": "#reachable:example.org", "fields": {}, "protocol": "irc"}
        ])";
        auto server_thread = std::thread{[&] {
            run_one_shot_appservice_server(acceptor,
                                           merovingian::tests::tls_mock::json_http_response("200 OK", location_body));
        }};
        auto const join = merovingian::tests::tls_mock::ScopedThreadJoin{server_thread};

        WHEN("GET /_matrix/client/v3/thirdparty/location/irc?channel=%23x is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/thirdparty/location/irc?channel=%23x", token, {}});
            if (server_thread.joinable())
            {
                server_thread.join();
            }

            THEN("the reachable appservice's location is still returned")
            {
                REQUIRE(response.response.status == 200U);
                CHECK(response.response.body.find("#reachable:example.org") != std::string::npos);
            }
        }

        std::filesystem::remove(unreachable_path);
        std::filesystem::remove(reachable_path);
    }
}

// Security audit run-1 (sp02.thirdparty-no-proxy-slot): every client request that makes this server
// call another one takes a slot of the client outbound proxy budget first (ADR-0079), so lookups
// that wait on a slow peer cannot hold every request thread. The /thirdparty/* routes call the
// registered appservices and took no slot. A route that would call an appservice is now refused with
// 429 M_LIMIT_EXCEEDED, before any outbound call, when no slot is free.
SCENARIO("Third-party lookups that call an appservice take a client outbound proxy slot",
         "[appservice][integration][thirdparty][security][sp02]")
{
    GIVEN("a registered appservice and a client outbound budget whose only slot another client holds")
    {
        auto const path = std::filesystem::temp_directory_path() / "merovingian-thirdparty-budget.json";
        auto acceptor = merovingian::net::TcpAcceptor{};
        REQUIRE(acceptor.bind("127.0.0.1", 0U).ok);
        auto const port = acceptor.bound_port();
        REQUIRE(port > 0U);

        auto const config = config_with_appservice(path, "irc-bridge", "irc-as-token", "irc-hs-token", port, {"irc"});
        auto started = merovingian::homeserver::start_client_server(config);
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const token = register_and_login(runtime, "erin");
        runtime.homeserver.client_outbound_proxy_policy.global_cap = 1U;
        auto const held = merovingian::homeserver::admit_client_outbound_proxy(runtime.homeserver, "another-client");
        REQUIRE(held.has_value());

        WHEN("each third-party route that would call the appservice is requested")
        {
            auto const targets = std::vector<std::string>{
                "/_matrix/client/v3/thirdparty/protocols",
                "/_matrix/client/v3/thirdparty/protocol/irc",
                "/_matrix/client/v3/thirdparty/location/irc",
                "/_matrix/client/v3/thirdparty/user/irc",
                "/_matrix/client/v3/thirdparty/location?alias=%23chan%3Aexample.org",
                "/_matrix/client/v3/thirdparty/user?userid=%40someone%3Aexample.org",
            };

            THEN("every one is refused with 429 M_LIMIT_EXCEEDED and nothing is sent to the appservice")
            {
                for (auto const& target : targets)
                {
                    CAPTURE(target);
                    auto const response =
                        merovingian::homeserver::handle_client_server_request(runtime, {"GET", target, token, {}});
                    REQUIRE(response.response.status == 429U);
                    REQUIRE(response.response.body.find("M_LIMIT_EXCEEDED") != std::string::npos);
                }
                REQUIRE(runtime.homeserver.client_outbound_budget->active() == 1U);
                // No connection reached the appservice's listening socket.
                auto pending = pollfd{acceptor.fd(), POLLIN, 0};
                REQUIRE(::poll(&pending, 1, 0) == 0);
            }
        }

        std::filesystem::remove(path);
    }

    GIVEN("no registered appservice and an exhausted client outbound budget")
    {
        auto started = merovingian::homeserver::start_client_server(thirdparty_test_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const token = register_and_login(runtime, "frank");
        runtime.homeserver.client_outbound_proxy_policy.global_cap = 1U;
        auto const held = merovingian::homeserver::admit_client_outbound_proxy(runtime.homeserver, "another-client");
        REQUIRE(held.has_value());

        WHEN("the protocols list is requested")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/thirdparty/protocols", token, {}});

            THEN("it answers without needing a slot, since no appservice is called")
            {
                REQUIRE(response.response.status == 200U);
            }
        }
    }
}

// Security audit run 2 (F-68, ADR-0417). GET /profile/{userId} and GET /directory/room/{roomAlias} are
// served without authentication and ask a matching appservice about an identifier this server does not
// know. Each query holds the request thread until the appservice answers, so the loop takes one slot of
// the client outbound budget (ADR-0079, ADR-0181), only when a registration will be asked.
SCENARIO("An unknown user or alias in an appservice namespace is looked up under a client outbound proxy slot",
         "[appservice][integration][security][http-2][out-7][f68]")
{
    GIVEN("an appservice owning @bridge_ users and #bridge_ aliases, and a budget whose only slot is taken")
    {
        auto bridge = merovingian::tests::MockAppservice{};
        bridge.set_status(404U);
        auto const config = merovingian::tests::appservice_test_config({
            {.id = "bridge",
             .url = bridge.url(),
             .users_regex = "@bridge_.*:example.org",
             .aliases_regex = "#bridge_.*:example.org"}
        });
        auto started = merovingian::homeserver::start_client_server(config);
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        runtime.homeserver.client_outbound_proxy_policy.global_cap = 1U;
        auto held = merovingian::homeserver::admit_client_outbound_proxy(runtime.homeserver, "another-client");
        REQUIRE(held.has_value());

        WHEN("an unauthenticated client asks for a profile and an alias inside the namespaces")
        {
            auto const profile = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/profile/%40bridge_one%3Aexample.org", {}, {}});
            auto const alias = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/directory/room/%23bridge_one%3Aexample.org", {}, {}});

            THEN("both are refused with 429 M_LIMIT_EXCEEDED and the appservice is not called")
            {
                REQUIRE(profile.response.status == 429U);
                REQUIRE(profile.response.body.find("M_LIMIT_EXCEEDED") != std::string::npos);
                REQUIRE(alias.response.status == 429U);
                REQUIRE(alias.response.body.find("M_LIMIT_EXCEEDED") != std::string::npos);
                REQUIRE(bridge.requests().empty());
                REQUIRE(runtime.homeserver.client_outbound_budget->active() == 1U);
            }
        }

        WHEN("the same client asks for a profile and an alias outside every namespace")
        {
            auto const profile = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/profile/%40nobody%3Aexample.org", {}, {}});
            auto const alias = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/directory/room/%23nowhere%3Aexample.org", {}, {}});

            THEN("they are answered 404 without needing a slot, since no appservice is asked")
            {
                REQUIRE(profile.response.status == 404U);
                REQUIRE(alias.response.status == 404U);
                REQUIRE(bridge.requests().empty());
            }
        }

        WHEN("the slot is free and the client asks for a profile and an alias inside the namespaces")
        {
            held.reset();
            auto const profile = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/profile/%40bridge_one%3Aexample.org", {}, {}});
            auto const after_profile = runtime.homeserver.client_outbound_budget->active();
            auto const alias = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/directory/room/%23bridge_one%3Aexample.org", {}, {}});
            auto const after_alias = runtime.homeserver.client_outbound_budget->active();

            THEN("the appservice is asked about each, a decline is a 404, and each slot is returned")
            {
                REQUIRE(profile.response.status == 404U);
                REQUIRE(alias.response.status == 404U);
                REQUIRE(bridge.requests_to("/_matrix/app/v1/users/").size() == 1U);
                REQUIRE(bridge.requests_to("/_matrix/app/v1/rooms/").size() == 1U);
                REQUIRE(after_profile == 0U);
                REQUIRE(after_alias == 0U);
            }
        }
    }
}
