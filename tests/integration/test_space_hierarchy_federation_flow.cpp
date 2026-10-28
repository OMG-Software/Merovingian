// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#include "../support/in_memory_database_config.hpp"
//
// The space hierarchy across federation, end to end.
//
// A space can link to rooms this server holds no state for. The client
// hierarchy must ask the servers named in the link's `via` for them
// (`GET /_matrix/federation/v1/hierarchy/{roomId}`), keep what that server says
// only for what the requesting user may see, and never let the remote answer
// widen what a local user is shown.
//
// Spec: Matrix Client-Server API v1.19, GET /_matrix/client/v1/rooms/{roomId}/hierarchy
// URL:  ../../docs/matrix-v1.19-spec/client-server-api.md#get_matrixclientv1roomsroomidhierarchy
//       ("In the case where the server does not have access to the state of a child room, it can
//       request the information over federation with the GET /hierarchy API.")
// Spec: Matrix Server-Server API v1.19, GET /_matrix/federation/v1/hierarchy/{roomId}
// URL:  ../../docs/matrix-v1.19-spec/server-server-api.md#get_matrixfederationv1hierarchyroomid

#include "../support/json_test_support.hpp"
#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "../support/tls_mock_server.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/core/query_params.hpp"
#include "merovingian/homeserver/client_outbound_proxy.hpp"
#include "merovingian/homeserver/client_server.hpp"
#include "merovingian/homeserver/local_http_router.hpp"
#include "merovingian/homeserver/runtime.hpp"
#include "merovingian/homeserver/tls.hpp"
#include "merovingian/net/tcp_acceptor.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstdint>
#include <string>
#include <string_view>
#include <thread>
#include <tuple>
#include <utility>
#include <variant>
#include <vector>

#include <sodium.h>

using namespace merovingian::tests;

namespace
{

using merovingian::homeserver::ClientServerRuntime;

constexpr auto remote_server = std::string_view{"remote.example.org"};
constexpr auto client_address = std::string_view{"198.51.100.9"};

[[nodiscard]] auto test_config() -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
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

[[nodiscard]] auto request(ClientServerRuntime& runtime, std::string method, std::string target,
                           std::string const& token, std::string body = {})
    -> merovingian::homeserver::LocalHttpResponse
{
    auto http_request = merovingian::homeserver::LocalHttpRequest{};
    http_request.method = std::move(method);
    http_request.target = std::move(target);
    http_request.access_token = token;
    http_request.body = std::move(body);
    http_request.remote_addr = std::string{client_address};
    return merovingian::homeserver::handle_client_server_request(runtime, http_request).response;
}

[[nodiscard]] auto register_user(ClientServerRuntime& runtime, std::string_view localpart) -> std::string
{
    auto const registration = merovingian::homeserver::handle_client_server_request(
        runtime, {"POST",
                  "/_matrix/client/v3/register",
                  {},
                  merovingian::tests::registration_json(localpart, "CorrectHorse7!")});
    REQUIRE(registration.response.status == 200U);
    auto const body = parse_object(registration.response.body);
    auto const* token = string_member(body, "access_token");
    REQUIRE(token != nullptr);
    return *token;
}

[[nodiscard]] auto create_space(ClientServerRuntime& runtime, std::string const& token) -> std::string
{
    auto const response = request(runtime, "POST", "/_matrix/client/v3/createRoom", token,
                                  R"({"preset":"public_chat","creation_content":{"type":"m.space"},"name":"Space"})");
    REQUIRE(response.status == 200U);
    auto const body = parse_object(response.body);
    auto const* room_id = string_member(body, "room_id");
    REQUIRE(room_id != nullptr);
    return *room_id;
}

auto link_child(ClientServerRuntime& runtime, std::string const& token, std::string const& space,
                std::string_view child, bool suggested = false) -> void
{
    auto const target = "/_matrix/client/v3/rooms/" + merovingian::core::percent_encode_path_component(space) +
                        "/state/m.space.child/" + merovingian::core::percent_encode_path_component(child);
    auto const body = std::string{R"({"via":[")"} + std::string{remote_server} + R"("],"suggested":)" +
                      (suggested ? "true" : "false") + "}";
    auto const response = request(runtime, "PUT", target, token, body);
    REQUIRE(response.status == 200U);
}

[[nodiscard]] auto hierarchy(ClientServerRuntime& runtime, std::string const& token, std::string const& space,
                             std::string const& query = {}) -> merovingian::homeserver::LocalHttpResponse
{
    return request(runtime, "GET",
                   "/_matrix/client/v1/rooms/" + merovingian::core::percent_encode_path_component(space) +
                       "/hierarchy" + query,
                   token);
}

[[nodiscard]] auto room_ids(merovingian::homeserver::LocalHttpResponse const& response) -> std::vector<std::string>
{
    REQUIRE(response.status == 200U);
    auto const body = parse_object(response.body);
    auto const* rooms = object_member_as_array(body, "rooms");
    REQUIRE(rooms != nullptr);
    auto ids = std::vector<std::string>{};
    for (auto const& room : *rooms)
    {
        auto const* object = std::get_if<merovingian::canonicaljson::Object>(&room.storage());
        REQUIRE(object != nullptr);
        ids.push_back(*string_member(*object, "room_id"));
    }
    return ids;
}

[[nodiscard]] auto contains(std::vector<std::string> const& ids, std::string_view wanted) -> bool
{
    return std::ranges::find(ids, wanted) != ids.end();
}

// What a remote server says about one room, in the federation hierarchy's chunk shape.
[[nodiscard]] auto summary_json(std::string_view room_id, std::string_view join_rule, bool world_readable,
                                std::string_view extra = {}) -> std::string
{
    return std::string{R"({"room_id":")"} + std::string{room_id} +
           R"(","num_joined_members":3,"guest_can_join":false,"world_readable":)" +
           (world_readable ? "true" : "false") + R"(,"join_rule":")" + std::string{join_rule} +
           R"(","name":"Remote Room")" + (extra.empty() ? "" : "," + std::string{extra}) + "}";
}

[[nodiscard]] auto hierarchy_response(std::string const& room, std::string const& children = "[]",
                                      std::string const& inaccessible = "[]") -> std::string
{
    return tls_mock::json_http_response("200 OK", R"({"room":)" + room + R"(,"children":)" + children +
                                                      R"(,"inaccessible_children":)" + inaccessible + "}");
}

[[nodiscard]] auto not_found_response() -> std::string
{
    return tls_mock::json_http_response("404 Not Found", R"({"errcode":"M_NOT_FOUND","error":"Room not found"})");
}

// A federation peer answering `GET /hierarchy/{roomId}`, one connection per
// response, the response chosen by a substring of the request line. Built and
// asserted on the test's own thread; only the serving runs on another.
class RemoteServer final
{
public:
    RemoteServer(ClientServerRuntime& runtime, std::vector<std::pair<std::string, std::string>> responses)
        : m_responses{std::move(responses)}
        , m_certificate{tls_mock::write_test_tls_certificate()}
        , m_tls{merovingian::homeserver::make_tls_server_context(m_certificate.certificate_file,
                                                                 m_certificate.private_key_file)}
    {
        REQUIRE(m_tls.ok());
        REQUIRE(m_acceptor.bind("127.0.0.1", 0U).ok);
        runtime.homeserver.test_forced_outbound_resolution[std::string{remote_server}] =
            merovingian::homeserver::TestOnlyForcedOutboundResolution{
                "localhost", m_acceptor.bound_port(), {"127.0.0.1"}, m_certificate.certificate_pem};
        m_thread = std::thread{[this]() {
            tls_mock::run_path_dispatch_tls_server(m_acceptor, *m_tls.context, m_responses, &m_captured);
        }};
    }

    ~RemoteServer()
    {
        std::ignore = finish();
    }

    RemoteServer(RemoteServer const&) = delete;
    auto operator=(RemoteServer const&) -> RemoteServer& = delete;
    RemoteServer(RemoteServer&&) = delete;
    auto operator=(RemoteServer&&) -> RemoteServer& = delete;

    // Joins the serving thread; the requests it saw are readable afterwards.
    [[nodiscard]] auto finish() -> std::vector<std::string> const&
    {
        if (m_thread.joinable())
        {
            m_thread.join();
        }
        return m_captured;
    }

private:
    std::vector<std::pair<std::string, std::string>> m_responses;
    tls_mock::TlsTestCertificate m_certificate;
    merovingian::homeserver::TlsServerContextResult m_tls;
    merovingian::net::TcpAcceptor m_acceptor{};
    std::vector<std::string> m_captured{};
    std::thread m_thread{};
};

} // namespace

SCENARIO("A child room on another server appears in the hierarchy", "[integration][space-hierarchy][federation]")
{
    GIVEN("alice's space links to a public room that lives on another server")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_client_server(test_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const alice = register_user(runtime, "alice");
        auto const space = create_space(runtime, alice);
        link_child(runtime, alice, space, "!remoteroom:remote.example.org");

        WHEN("alice asks for the hierarchy")
        {
            auto remote = RemoteServer{
                runtime,
                {{"remoteroom", hierarchy_response(summary_json("!remoteroom:remote.example.org", "public", false))}}};
            auto const response = hierarchy(runtime, alice, space);
            auto const& seen = remote.finish();

            THEN("the remote room is listed with the details its server gave")
            {
                auto const ids = room_ids(response);
                REQUIRE(contains(ids, space));
                REQUIRE(contains(ids, "!remoteroom:remote.example.org"));
                REQUIRE(response.body.find("Remote Room") != std::string::npos);
            }

            AND_THEN("exactly one federation request was made, to the hierarchy endpoint, without suggested_only")
            {
                REQUIRE(seen.size() == 1U);
                REQUIRE(seen.front().find("GET /_matrix/federation/v1/hierarchy/") == 0U);
                REQUIRE(seen.front().find("suggested_only") == std::string::npos);
            }
        }

        WHEN("alice asks for the suggested rooms only and the link is not suggested")
        {
            auto remote = RemoteServer{runtime, {}};
            auto const response = hierarchy(runtime, alice, space, "?suggested_only=true");
            auto const& seen = remote.finish();

            THEN("the remote room is neither listed nor asked for")
            {
                auto const ids = room_ids(response);
                REQUIRE_FALSE(contains(ids, "!remoteroom:remote.example.org"));
                REQUIRE(seen.empty());
            }
        }
    }

    GIVEN("a suggested link to a room on another server")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_client_server(test_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const alice = register_user(runtime, "alice");
        auto const space = create_space(runtime, alice);
        link_child(runtime, alice, space, "!remoteroom:remote.example.org", true);

        WHEN("alice asks for the suggested rooms only")
        {
            auto remote = RemoteServer{
                runtime,
                {{"remoteroom", hierarchy_response(summary_json("!remoteroom:remote.example.org", "public", false))}}};
            auto const response = hierarchy(runtime, alice, space, "?suggested_only=true");
            auto const& seen = remote.finish();

            THEN("the remote server is asked for suggested rooms only, and the room is listed")
            {
                REQUIRE(contains(room_ids(response), "!remoteroom:remote.example.org"));
                REQUIRE(seen.size() == 1U);
                REQUIRE(seen.front().find("suggested_only=true") != std::string::npos);
            }
        }
    }
}

SCENARIO("A remote answer never widens what the requesting user may see",
         "[integration][space-hierarchy][federation][restricted]")
{
    GIVEN("a space linked to a restricted room on another server, and a user who is not in the space")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_client_server(test_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const alice = register_user(runtime, "alice");
        auto const bob = register_user(runtime, "bob");
        auto const space = create_space(runtime, alice);
        link_child(runtime, alice, space, "!remoteroom:remote.example.org");
        auto const restricted = summary_json("!remoteroom:remote.example.org", "restricted", false,
                                             R"("allowed_room_ids":[")" + space + R"("])");

        WHEN("alice, who is joined to the space, asks for the hierarchy")
        {
            auto remote = RemoteServer{runtime, {{"remoteroom", hierarchy_response(restricted)}}};
            auto const response = hierarchy(runtime, alice, space);
            std::ignore = remote.finish();

            THEN("the restricted room is listed, since she meets its condition")
            {
                // Spec: restricted rooms are returned "provided the user meets one of the specified conditions".
                REQUIRE(contains(room_ids(response), "!remoteroom:remote.example.org"));
            }
        }

        WHEN("bob, who is not in the space, asks for the hierarchy")
        {
            auto remote = RemoteServer{runtime, {{"remoteroom", hierarchy_response(restricted)}}};
            auto const response = hierarchy(runtime, bob, space);
            std::ignore = remote.finish();

            THEN("the restricted room is not listed, though the remote server returned it")
            {
                auto const ids = room_ids(response);
                REQUIRE(contains(ids, space));
                REQUIRE_FALSE(contains(ids, "!remoteroom:remote.example.org"));
            }
        }
    }

    GIVEN("a space linked to an invite-only room that a misbehaving remote server returns anyway")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_client_server(test_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const alice = register_user(runtime, "alice");
        auto const space = create_space(runtime, alice);
        link_child(runtime, alice, space, "!remoteroom:remote.example.org");

        WHEN("alice asks for the hierarchy")
        {
            auto remote = RemoteServer{
                runtime,
                {{"remoteroom", hierarchy_response(summary_json("!remoteroom:remote.example.org", "invite", false))}}};
            auto const response = hierarchy(runtime, alice, space);
            std::ignore = remote.finish();

            THEN("the private room is not listed")
            {
                REQUIRE_FALSE(contains(room_ids(response), "!remoteroom:remote.example.org"));
            }
        }
    }

    GIVEN("a space linked to a room that the remote server answers with another room's summary")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_client_server(test_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const alice = register_user(runtime, "alice");
        auto const space = create_space(runtime, alice);
        link_child(runtime, alice, space, "!remoteroom:remote.example.org");

        WHEN("alice asks for the hierarchy")
        {
            auto remote = RemoteServer{
                runtime,
                {{"remoteroom", hierarchy_response(summary_json("!someother:remote.example.org", "public", true))}}};
            auto const response = hierarchy(runtime, alice, space);
            std::ignore = remote.finish();

            THEN("neither room is listed")
            {
                auto const ids = room_ids(response);
                REQUIRE_FALSE(contains(ids, "!remoteroom:remote.example.org"));
                REQUIRE_FALSE(contains(ids, "!someother:remote.example.org"));
            }
        }
    }
}

SCENARIO("A remote server that cannot or will not answer leaves the rest of the hierarchy intact",
         "[integration][space-hierarchy][federation]")
{
    GIVEN("a space linked to a room on another server that answers 404")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_client_server(test_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const alice = register_user(runtime, "alice");
        auto const space = create_space(runtime, alice);
        link_child(runtime, alice, space, "!remoteroom:remote.example.org");

        WHEN("alice asks for the hierarchy")
        {
            auto remote = RemoteServer{runtime, {{"remoteroom", not_found_response()}}};
            auto const response = hierarchy(runtime, alice, space);
            std::ignore = remote.finish();

            THEN("the request succeeds with the space alone")
            {
                auto const ids = room_ids(response);
                REQUIRE(ids.size() == 1U);
                REQUIRE(ids.front() == space);
            }
        }
    }

    GIVEN("a space linked to a room on another server, with the client's outbound budget already in use")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_client_server(test_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const alice = register_user(runtime, "alice");
        auto const space = create_space(runtime, alice);
        link_child(runtime, alice, space, "!remoteroom:remote.example.org");
        auto const held =
            merovingian::homeserver::admit_client_outbound_proxy(runtime.homeserver, std::string{client_address});
        REQUIRE(held.has_value());

        WHEN("alice asks for the hierarchy")
        {
            auto const response = hierarchy(runtime, alice, space);

            THEN("it is refused with 429 M_LIMIT_EXCEEDED and no outbound call is made")
            {
                // ADR-0079: a client request that calls another server takes a slot first.
                REQUIRE(response.status == 429U);
                auto const body = parse_object(response.body);
                REQUIRE(*string_member(body, "errcode") == "M_LIMIT_EXCEEDED");
            }
        }
    }
}

SCENARIO("A space on another server is walked and its children are not asked for again",
         "[integration][space-hierarchy][federation]")
{
    GIVEN("alice's space links to a space on another server, which links to a room on that server")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_client_server(test_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const alice = register_user(runtime, "alice");
        auto const space = create_space(runtime, alice);
        link_child(runtime, alice, space, "!remotespace:remote.example.org");

        auto const child_link = std::string{
            R"([{"content":{"via":["remote.example.org"]},"origin_server_ts":1,"sender":"@r:remote.example.org",)"
            R"("state_key":"!remotechild:remote.example.org","type":"m.space.child"}])"};
        auto const remote_space = summary_json("!remotespace:remote.example.org", "public", false,
                                               R"("room_type":"m.space","children_state":)" + child_link);
        // The remote server also lists a room nothing links to; it must not appear.
        auto const children = "[" + summary_json("!remotechild:remote.example.org", "public", false) + "," +
                              summary_json("!smuggled:remote.example.org", "public", true) + "]";

        WHEN("alice asks for the hierarchy")
        {
            auto remote = RemoteServer{runtime, {{"remotespace", hierarchy_response(remote_space, children)}}};
            auto const response = hierarchy(runtime, alice, space);
            auto const& seen = remote.finish();

            THEN("both remote rooms are listed, from one federation request")
            {
                auto const ids = room_ids(response);
                REQUIRE(contains(ids, "!remotespace:remote.example.org"));
                REQUIRE(contains(ids, "!remotechild:remote.example.org"));
                REQUIRE(seen.size() == 1U);
            }

            AND_THEN("a room the remote server listed but no space links to is not shown")
            {
                REQUIRE_FALSE(contains(room_ids(response), "!smuggled:remote.example.org"));
            }
        }
    }
}
