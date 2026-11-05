// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// +-------------------------------------------------------------------------+
// |      MATRIX FEDERATION PUBLISHED ROOM DIRECTORY CONFORMANCE TESTS       |
// |                                                                         |
// |  Spec: Matrix Server-Server API v1.19, "Published Room Directory"       |
// |  URL:  ../../docs/matrix-v1.19-spec/server-server-api.md                |
// |        #published-room-directory                                        |
// |                                                                         |
// |  Every request but the refused ones carries a real X-Matrix signature   |
// |  and goes through the same entry point as a request from the network.   |
// +-------------------------------------------------------------------------+

#include "../federation_signing_test_support.hpp"
#include "../support/in_memory_database_config.hpp"
#include "../support/json_test_support.hpp"
#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/core/folded_substring.hpp"
#include "merovingian/federation/inbound_request.hpp"
#include "merovingian/federation/runtime_federation.hpp"
#include "merovingian/federation/security.hpp"
#include "merovingian/homeserver/client_server.hpp"
#include "merovingian/homeserver/local_http_router.hpp"
#include "merovingian/homeserver/runtime.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstddef>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace
{

using merovingian::homeserver::ClientServerRuntime;
using merovingian::homeserver::LocalHttpResponse;
using merovingian::tests::object_member;
using merovingian::tests::object_member_as_array;
using merovingian::tests::parse_object;
using merovingian::tests::string_member;

auto constexpr remote_origin = "remote.example.org";
auto constexpr remote_key_id = "ed25519:auto";
auto constexpr remote_key_seed = "public-rooms-conformance-seed";
auto constexpr public_rooms_path = "/_matrix/federation/v1/publicRooms";

[[nodiscard]] auto federation_config() -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    merovingian::tests::enable_token_registration(security);
    security.federation.enabled = true;
    security.federation.default_policy = "allow";
    return {
        merovingian::config::ServerConfig{},
        merovingian::config::ListenersConfig{},
        merovingian::tests::in_memory_database_config(),
        security,
        merovingian::config::ClientRateLimitsConfig{},
        merovingian::config::LogModulesConfig{},
    };
}

[[nodiscard]] auto trusted_remote() -> merovingian::federation::FederationRemoteRuntime
{
    auto remote = merovingian::federation::FederationRemoteRuntime{};
    remote.server_name = remote_origin;
    remote.signing_key = {remote_origin, remote_key_id, 0U,
                          merovingian::federation::test::keypair_from_seed(remote_key_seed).public_key};
    remote.discovery.server_name = remote_origin;
    remote.discovery.well_known_host = remote_origin;
    remote.discovery.resolved_host = remote_origin;
    remote.discovery.resolved_addresses = {"203.0.113.10"};
    remote.discovery.tls_required = true;
    remote.trust.reputation_score = 100U;
    return remote;
}

[[nodiscard]] auto x_matrix_header(std::string_view method, std::string_view target, std::string_view body)
    -> std::string
{
    auto const signature = merovingian::federation::make_federation_signature(
        remote_origin, "example.org", method, target, body,
        merovingian::federation::test::keypair_from_seed(remote_key_seed).secret_key);
    return std::string{"X-Matrix origin=\""} + remote_origin + "\",key=\"" + remote_key_id + "\",sig=\"" + signature +
           "\",destination=\"example.org\"";
}

// A signed request from the remote server, through the entry point a request from the network uses.
[[nodiscard]] auto signed_call(ClientServerRuntime& runtime, std::string method, std::string target,
                               std::string body = {}) -> LocalHttpResponse
{
    auto const header = x_matrix_header(method, target, body);
    return merovingian::homeserver::handle_federation_http_request(
        runtime.homeserver, {std::move(method), std::move(target), header, std::move(body)});
}

[[nodiscard]] auto register_alice(ClientServerRuntime& runtime) -> std::string
{
    auto const registered = merovingian::homeserver::handle_client_server_request(
        runtime,
        {"POST", "/_matrix/client/v3/register", {}, merovingian::tests::registration_json("alice", "CorrectHorse7!")});
    REQUIRE(registered.response.status == 200U);
    auto const login = merovingian::homeserver::handle_client_server_request(
        runtime,
        {"POST",
         "/_matrix/client/v3/login",
         {},
         R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"DEVICE1"})"});
    REQUIRE(login.response.status == 200U);
    auto const body = parse_object(login.response.body);
    auto const* token = string_member(body, "access_token");
    REQUIRE(token != nullptr);
    return *token;
}

[[nodiscard]] auto create_room(ClientServerRuntime& runtime, std::string const& token, std::string const& body)
    -> std::string
{
    auto const created = merovingian::homeserver::handle_client_server_request(
        runtime, {"POST", "/_matrix/client/v3/createRoom", token, body});
    REQUIRE(created.response.status == 200U);
    auto const parsed = parse_object(created.response.body);
    auto const* room_id = string_member(parsed, "room_id");
    REQUIRE(room_id != nullptr);
    return *room_id;
}

// The rooms a directory answer lists, by room_id, in the order they were listed.
[[nodiscard]] auto listed_room_ids(merovingian::canonicaljson::Object const& answer) -> std::vector<std::string>
{
    auto rooms = std::vector<std::string>{};
    auto const* chunk = object_member_as_array(answer, "chunk");
    REQUIRE(chunk != nullptr);
    for (auto const& entry : *chunk)
    {
        auto const* room = std::get_if<merovingian::canonicaljson::Object>(&entry.storage());
        REQUIRE(room != nullptr);
        auto const* room_id = string_member(*room, "room_id");
        REQUIRE(room_id != nullptr);
        rooms.push_back(*room_id);
    }
    return rooms;
}

[[nodiscard]] auto listed_room_ids(LocalHttpResponse const& response) -> std::vector<std::string>
{
    REQUIRE(response.status == 200U);
    return listed_room_ids(parse_object(response.body));
}

[[nodiscard]] auto lists(std::vector<std::string> const& rooms, std::string const& room_id) -> bool
{
    return std::ranges::find(rooms, room_id) != rooms.end();
}

[[nodiscard]] auto entry_for(merovingian::canonicaljson::Object const& answer, std::string const& room_id)
    -> merovingian::canonicaljson::Object const*
{
    auto const* chunk = object_member_as_array(answer, "chunk");
    REQUIRE(chunk != nullptr);
    for (auto const& entry : *chunk)
    {
        auto const* room = std::get_if<merovingian::canonicaljson::Object>(&entry.storage());
        auto const* id = room == nullptr ? nullptr : string_member(*room, "room_id");
        if (id != nullptr && *id == room_id)
        {
            return room;
        }
    }
    return nullptr;
}

// Three published rooms and one that was never published.
struct DirectoryFixture final
{
    merovingian::homeserver::ClientServerStartResult started;
    std::string cheese{};
    std::string wine{};
    std::string space{};
    std::string unpublished{};

    explicit DirectoryFixture(merovingian::config::Config const& config)
        : started{merovingian::homeserver::start_client_server(config)}
    {
        REQUIRE(started.started);
        merovingian::federation::upsert_remote(started.runtime.homeserver.federation, trusted_remote());
        auto const token = register_alice(started.runtime);
        cheese = create_room(
            started.runtime, token,
            R"({"preset":"public_chat","visibility":"public","name":"Cheese","topic":"Tasty tasty cheese"})");
        wine = create_room(started.runtime, token, R"({"preset":"public_chat","visibility":"public","name":"Wine"})");
        space = create_room(
            started.runtime, token,
            R"({"preset":"public_chat","visibility":"public","name":"Cellar","creation_content":{"type":"m.space"}})");
        unpublished = create_room(started.runtime, token,
                                  R"({"preset":"public_chat","visibility":"private","name":"Unpublished Cheese"})");
    }

    [[nodiscard]] auto rooms() const -> std::vector<std::string>
    {
        return {cheese, wine, space};
    }
};

} // namespace

// Spec: Matrix Server-Server API v1.19, "Published Room Directory"
// Endpoint: GET /_matrix/federation/v1/publicRooms
// URL: ../../docs/matrix-v1.19-spec/server-server-api.md#get_matrixfederationv1publicrooms
//
// "Lists the server's published room directory." `chunk` is required, and each PublishedRoomsChunk
// requires `guest_can_join`, `num_joined_members`, `room_id` and `world_readable`; `room_type` is
// "The `type` of room (from `m.room.create`), if any."
SCENARIO("GET /publicRooms lists a published room and leaves out an unpublished one",
         "[federation][conformance][public_rooms]")
{
    GIVEN("a server with published rooms and an unpublished room")
    {
        auto fixture = DirectoryFixture{federation_config()};

        WHEN("a remote server asks for the directory with a signed request")
        {
            auto const response = signed_call(fixture.started.runtime, "GET", public_rooms_path);

            THEN("the published room is listed with every required field")
            {
                REQUIRE(response.status == 200U);
                auto const answer = parse_object(response.body);
                auto const* room = entry_for(answer, fixture.cheese);
                REQUIRE(room != nullptr);
                REQUIRE(std::get_if<bool>(&object_member(*room, "guest_can_join")->storage()) != nullptr);
                REQUIRE(std::get_if<bool>(&object_member(*room, "world_readable")->storage()) != nullptr);
                auto const* const joined_members = merovingian::tests::int_member(*room, "num_joined_members");
                REQUIRE(joined_members != nullptr);
                REQUIRE(*joined_members == 1);
                REQUIRE(*string_member(*room, "name") == "Cheese");
                REQUIRE(*string_member(*room, "topic") == "Tasty tasty cheese");
                REQUIRE(*string_member(*room, "join_rule") == "public");
                REQUIRE(string_member(*room, "room_type") == nullptr);
            }

            THEN("a room created with a type reports it")
            {
                auto const answer = parse_object(response.body);
                auto const* room = entry_for(answer, fixture.space);
                REQUIRE(room != nullptr);
                REQUIRE(*string_member(*room, "room_type") == "m.space");
            }

            THEN("the room that was never published is not listed")
            {
                REQUIRE_FALSE(lists(listed_room_ids(response), fixture.unpublished));
                REQUIRE(response.body.find("Unpublished Cheese") == std::string::npos);
            }

            THEN("the whole directory fits one batch, so neither paging token is present")
            {
                auto const answer = parse_object(response.body);
                REQUIRE(listed_room_ids(answer).size() == 3U);
                REQUIRE(string_member(answer, "next_batch") == nullptr);
                REQUIRE(string_member(answer, "prev_batch") == nullptr);
                auto const* const estimate = merovingian::tests::int_member(answer, "total_room_count_estimate");
                REQUIRE(estimate != nullptr);
                REQUIRE(*estimate == 3);
            }
        }
    }
}

// Spec: Matrix Server-Server API v1.19, "Published Room Directory": "Requires authentication: Yes",
// on both methods.
// URL: ../../docs/matrix-v1.19-spec/server-server-api.md#request-authentication
SCENARIO("GET and POST /publicRooms refuse a request that is not authenticated",
         "[federation][conformance][public_rooms][auth]")
{
    GIVEN("a server with a published room")
    {
        auto fixture = DirectoryFixture{federation_config()};
        auto& homeserver = fixture.started.runtime.homeserver;

        WHEN("a GET carries no Authorization header")
        {
            auto const response =
                merovingian::homeserver::handle_federation_http_request(homeserver, {"GET", public_rooms_path, {}, {}});
            THEN("it is refused and lists no room")
            {
                REQUIRE(response.status >= 400U);
                REQUIRE(response.body.find(fixture.cheese) == std::string::npos);
            }
        }

        WHEN("a POST carries no Authorization header")
        {
            auto const response = merovingian::homeserver::handle_federation_http_request(
                homeserver, {"POST", public_rooms_path, {}, "{}"});
            THEN("it is refused and lists no room")
            {
                REQUIRE(response.status >= 400U);
                REQUIRE(response.body.find(fixture.cheese) == std::string::npos);
            }
        }

        // The spec requires the signature and names 401 only for a wrong `destination`, so a signature that
        // does not verify takes the 403 M_FORBIDDEN every other federation endpoint gives it.
        WHEN("a GET is signed for a different target")
        {
            auto const header = x_matrix_header("GET", "/_matrix/federation/v1/version", {});
            auto const response = merovingian::homeserver::handle_federation_http_request(
                homeserver, {"GET", public_rooms_path, header, {}});
            THEN("the signature does not verify: 403, and no room is listed")
            {
                REQUIRE(response.status == 403U);
                REQUIRE(response.body.find(fixture.cheese) == std::string::npos);
            }
        }

        WHEN("a POST's body is changed after it was signed")
        {
            auto const header = x_matrix_header("POST", public_rooms_path, R"({"limit":1})");
            auto const response = merovingian::homeserver::handle_federation_http_request(
                homeserver, {"POST", public_rooms_path, header, R"({"limit":2})"});
            THEN("the signature does not verify: 403, and no room is listed")
            {
                REQUIRE(response.status == 403U);
                REQUIRE(response.body.find(fixture.cheese) == std::string::npos);
            }
        }
    }
}

// Spec: Matrix Server-Server API v1.19, "API standards": an unsupported method on a known path is
// 405 M_UNRECOGNIZED.
// URL: ../../docs/matrix-v1.19-spec/server-server-api.md#api-standards
SCENARIO("A method /publicRooms does not serve is 405", "[federation][conformance][public_rooms]")
{
    GIVEN("a running server")
    {
        auto fixture = DirectoryFixture{federation_config()};

        WHEN("a PUT is sent")
        {
            auto const response = signed_call(fixture.started.runtime, "PUT", public_rooms_path, "{}");
            THEN("it is 405 M_UNRECOGNIZED")
            {
                REQUIRE(response.status == 405U);
                REQUIRE(response.body.find("M_UNRECOGNIZED") != std::string::npos);
            }
        }
    }
}

// Spec: Matrix Server-Server API v1.19, GET /publicRooms: `limit` is "The maximum number of rooms to
// return. Defaults to 0 (no limit)." `next_batch`: "The absence of this token means there are no more
// results to fetch". `prev_batch`: "The absence of this token means there are no results before this
// batch, i.e. this is the first batch."
// URL: ../../docs/matrix-v1.19-spec/server-server-api.md#get_matrixfederationv1publicrooms
SCENARIO("GET /publicRooms pages with limit and since", "[federation][conformance][public_rooms][paging]")
{
    GIVEN("a directory of three published rooms")
    {
        auto fixture = DirectoryFixture{federation_config()};
        auto& runtime = fixture.started.runtime;
        auto const path = std::string{public_rooms_path};

        WHEN("the first batch is asked for with limit=2")
        {
            auto const first = signed_call(runtime, "GET", path + "?limit=2");
            REQUIRE(first.status == 200U);
            auto const first_answer = parse_object(first.body);

            THEN("it holds two rooms and a next_batch, and no prev_batch because it is the first")
            {
                REQUIRE(listed_room_ids(first_answer).size() == 2U);
                // Spec: "The absence of this token means there are no more results to fetch", and a third room remains.
                REQUIRE(string_member(first_answer, "next_batch") != nullptr);
                // Spec: "The absence of this token means there are no results before this batch, i.e. this is the first
                // batch."
                REQUIRE(string_member(first_answer, "prev_batch") == nullptr);
            }

            AND_WHEN("next_batch is passed back as since")
            {
                auto const* next_batch = string_member(first_answer, "next_batch");
                REQUIRE(next_batch != nullptr);
                auto const second = signed_call(runtime, "GET", path + "?limit=2&since=" + *next_batch);
                REQUIRE(second.status == 200U);
                auto const second_answer = parse_object(second.body);

                THEN("the last room arrives, every room has been seen once, and paging stops")
                {
                    auto seen = listed_room_ids(first_answer);
                    auto const rest = listed_room_ids(second_answer);
                    REQUIRE(rest.size() == 1U);
                    seen.insert(seen.end(), rest.begin(), rest.end());
                    std::ranges::sort(seen);
                    auto expected = fixture.rooms();
                    std::ranges::sort(expected);
                    REQUIRE(seen == expected);
                    // Spec: no next_batch means "the client should stop paginating", and nothing is left to fetch.
                    REQUIRE(string_member(second_answer, "next_batch") == nullptr);
                }

                THEN("its prev_batch leads back to the first batch")
                {
                    auto const* prev_batch = string_member(second_answer, "prev_batch");
                    REQUIRE(prev_batch != nullptr);
                    auto const again = signed_call(runtime, "GET", path + "?limit=2&since=" + *prev_batch);
                    // Spec: prev_batch is "A pagination token that allows fetching previous results".
                    REQUIRE(listed_room_ids(again) == listed_room_ids(first_answer));
                }
            }
        }

        WHEN("limit=0 is sent, which the spec defines as no limit")
        {
            auto const response = signed_call(runtime, "GET", path + "?limit=0");
            THEN("every room is listed")
            {
                // Spec: `limit` "Defaults to 0 (no limit)", so the three rooms fit one batch under the default page
                // size.
                REQUIRE(listed_room_ids(response).size() == 3U);
            }
        }

        WHEN("since is past the end of the directory")
        {
            auto const response = signed_call(runtime, "GET", path + "?since=18446744073709551615");
            THEN("the batch is empty and paging stops")
            {
                REQUIRE(response.status == 200U);
                auto const answer = parse_object(response.body);
                REQUIRE(listed_room_ids(answer).empty());
                REQUIRE(string_member(answer, "next_batch") == nullptr);
            }
        }

        WHEN("limit or since is not a number this server could have issued or accepted")
        {
            auto const bad_limit = signed_call(runtime, "GET", path + "?limit=ten");
            auto const negative_limit = signed_call(runtime, "GET", path + "?limit=-1");
            auto const huge_limit = signed_call(runtime, "GET", path + "?limit=99999999999999999999999");
            auto const bad_since = signed_call(runtime, "GET", path + "?since=not-a-token");
            auto const huge_since = signed_call(runtime, "GET", path + "?since=99999999999999999999999");

            THEN("each is refused with 400 M_INVALID_PARAM rather than restarting from the beginning")
            {
                // The spec names no status here. Restarting from the first page would loop a paginating server
                // (ADR-0460).
                for (auto const& response : {bad_limit, negative_limit, huge_limit, bad_since, huge_since})
                {
                    REQUIRE(response.status == 400U);
                    REQUIRE(response.body.find("M_INVALID_PARAM") != std::string::npos);
                }
            }
        }
    }

    GIVEN("an operator page size of two")
    {
        auto config = federation_config();
        config.server().client_api.max_public_rooms_page_size = 2U;
        auto fixture = DirectoryFixture{config};
        auto const path = std::string{public_rooms_path};

        WHEN("a request asks for more than that, or for no limit at all")
        {
            auto const huge = signed_call(fixture.started.runtime, "GET", path + "?limit=100000");
            auto const none = signed_call(fixture.started.runtime, "GET", path);

            THEN("no batch is larger than the page size, and next_batch reaches the rest")
            {
                REQUIRE(listed_room_ids(huge).size() == 2U);
                REQUIRE(listed_room_ids(none).size() == 2U);
                // A server may answer in batches: the rest stays reachable, so "no limit" still lists every room.
                REQUIRE(string_member(parse_object(huge.body), "next_batch") != nullptr);
                REQUIRE(string_member(parse_object(none.body), "next_batch") != nullptr);
            }
        }
    }
}

// Spec: Matrix Server-Server API v1.19, POST /publicRooms: `filter` holds `generic_search_term` ("An
// optional string to search for in the room metadata, e.g. name, topic, canonical alias, etc.") and
// `room_types` ("To include rooms without a room type, specify `null` within this list. When not
// specified, all applicable rooms (regardless of type) are returned.").
// URL: ../../docs/matrix-v1.19-spec/server-server-api.md#post_matrixfederationv1publicrooms
SCENARIO("POST /publicRooms applies the filter", "[federation][conformance][public_rooms][filter]")
{
    GIVEN("a directory of three published rooms and an unpublished room whose name matches the search")
    {
        auto fixture = DirectoryFixture{federation_config()};
        auto& runtime = fixture.started.runtime;

        WHEN("generic_search_term is the name of one room, in another case")
        {
            auto const response =
                signed_call(runtime, "POST", public_rooms_path, R"({"filter":{"generic_search_term":"cHeEsE"}})");
            THEN("only that room is listed, and the matching unpublished room still is not")
            {
                REQUIRE(listed_room_ids(response) == std::vector{fixture.cheese});
            }
        }

        WHEN("generic_search_term appears only in a topic")
        {
            auto const response =
                signed_call(runtime, "POST", public_rooms_path, R"({"filter":{"generic_search_term":"tasty"}})");
            THEN("the room with that topic is listed")
            {
                REQUIRE(listed_room_ids(response) == std::vector{fixture.cheese});
            }
        }

        WHEN("room_types names a type")
        {
            auto const response =
                signed_call(runtime, "POST", public_rooms_path, R"({"filter":{"room_types":["m.space"]}})");
            THEN("only rooms of that type are listed")
            {
                // Spec: `room_types` is "An optional list of room types to search for".
                REQUIRE(listed_room_ids(response) == std::vector{fixture.space});
            }
        }

        WHEN("room_types holds null")
        {
            auto const response =
                signed_call(runtime, "POST", public_rooms_path, R"({"filter":{"room_types":[null]}})");
            THEN("only rooms without a type are listed")
            {
                // Spec: "To include rooms without a room type, specify `null` within this list."
                auto const rooms = listed_room_ids(response);
                REQUIRE(rooms.size() == 2U);
                REQUIRE(lists(rooms, fixture.cheese));
                REQUIRE(lists(rooms, fixture.wine));
            }
        }

        WHEN("room_types holds both null and a type, as the spec's request example does")
        {
            auto const response =
                signed_call(runtime, "POST", public_rooms_path, R"({"filter":{"room_types":[null,"m.space"]}})");
            THEN("all three rooms are listed")
            {
                REQUIRE(listed_room_ids(response).size() == 3U);
            }
        }

        WHEN("room_types is an empty list")
        {
            auto const response = signed_call(runtime, "POST", public_rooms_path, R"({"filter":{"room_types":[]}})");
            THEN("no type was searched for, so no room is listed")
            {
                // Spec: only "When not specified" are all rooms returned. An empty list is specified and names no type.
                REQUIRE(listed_room_ids(response).empty());
            }
        }

        WHEN("the filter is paged with limit and since in the body")
        {
            auto const body = std::string{R"({"filter":{"room_types":[null]},"limit":1)"};
            auto const first = signed_call(runtime, "POST", public_rooms_path, body + "}");
            REQUIRE(first.status == 200U);
            auto const first_answer = parse_object(first.body);
            auto const* next_batch = string_member(first_answer, "next_batch");
            REQUIRE(next_batch != nullptr);
            auto const second =
                signed_call(runtime, "POST", public_rooms_path, body + R"(,"since":")" + *next_batch + "\"}");

            THEN("the two batches hold the two matching rooms, and the count is of matching rooms")
            {
                auto seen = listed_room_ids(first_answer);
                auto const rest = listed_room_ids(second);
                seen.insert(seen.end(), rest.begin(), rest.end());
                REQUIRE(seen.size() == 2U);
                REQUIRE(lists(seen, fixture.cheese));
                REQUIRE(lists(seen, fixture.wine));
                // The estimate counts what this filter selects, in or out of the batch, so it matches what paging will
                // find.
                auto const* const estimate = merovingian::tests::int_member(first_answer, "total_room_count_estimate");
                REQUIRE(estimate != nullptr);
                REQUIRE(*estimate == 2);
                REQUIRE(string_member(parse_object(second.body), "next_batch") == nullptr);
            }
        }

        WHEN("the body is empty, since no field is required")
        {
            auto const response = signed_call(runtime, "POST", public_rooms_path, {});
            THEN("the whole directory is listed")
            {
                // Spec: every field of the body is optional, and without a filter all applicable rooms are returned.
                REQUIRE(listed_room_ids(response).size() == 3U);
            }
        }

        WHEN("a search term is over the cap")
        {
            auto const term = std::string(merovingian::core::max_search_term_bytes + 1U, 'a');
            auto const response = signed_call(runtime, "POST", public_rooms_path,
                                              R"({"filter":{"generic_search_term":")" + term + "\"}}");
            THEN("it is refused rather than truncated")
            {
                REQUIRE(response.status == 400U);
                // A cut term would return the wrong rooms, so it is refused (ADR-0330).
                REQUIRE(response.body.find("M_TOO_LARGE") != std::string::npos);
            }
        }

        WHEN("a field has the wrong type, or the body is not a JSON object")
        {
            auto const bodies = std::vector<std::string>{
                R"({"filter":"cheese"})",
                R"({"filter":{"generic_search_term":1}})",
                R"({"filter":{"room_types":"m.space"}})",
                R"({"filter":{"room_types":[1]}})",
                R"({"limit":"2"})",
                R"({"limit":-1})",
                R"({"since":2})",
                R"({"since":"not-a-token"})",
                R"({"include_all_networks":"yes"})",
                R"({"third_party_instance_id":1})",
                R"([])",
            };
            THEN("each is refused with 400, never answered as if it had not been sent")
            {
                for (auto const& body : bodies)
                {
                    INFO("body: " << body);
                    REQUIRE(signed_call(runtime, "POST", public_rooms_path, body).status == 400U);
                }
            }
            // The signature covers the body as JSON, so one that is not JSON fails authentication first.
            THEN("a body that is not JSON is refused and lists no room")
            {
                auto const response = signed_call(runtime, "POST", public_rooms_path, "not json");
                REQUIRE(response.status >= 400U);
                REQUIRE(response.body.find(fixture.cheese) == std::string::npos);
            }
        }
    }
}

// Spec: Matrix Server-Server API v1.19, "Published Room Directory": `third_party_instance_id` "Can
// only be used if include_all_networks is false."
// URL: ../../docs/matrix-v1.19-spec/server-server-api.md#post_matrixfederationv1publicrooms
SCENARIO("GET and POST /publicRooms handle the third-party network parameters",
         "[federation][conformance][public_rooms][networks]")
{
    GIVEN("a directory of three published rooms and no application service")
    {
        auto fixture = DirectoryFixture{federation_config()};
        auto& runtime = fixture.started.runtime;
        auto const path = std::string{public_rooms_path};

        WHEN("both parameters are used together")
        {
            auto const by_post = signed_call(runtime, "POST", public_rooms_path,
                                             R"({"include_all_networks":true,"third_party_instance_id":"irc"})");
            auto const by_get =
                signed_call(runtime, "GET", path + "?include_all_networks=true&third_party_instance_id=irc");
            THEN("each is refused with 400 M_INVALID_PARAM")
            {
                REQUIRE(by_post.status == 400U);
                REQUIRE(by_post.body.find("M_INVALID_PARAM") != std::string::npos);
                REQUIRE(by_get.status == 400U);
                REQUIRE(by_get.body.find("M_INVALID_PARAM") != std::string::npos);
            }
        }

        WHEN("an instance ID names no network")
        {
            auto const response =
                signed_call(runtime, "POST", public_rooms_path, R"({"third_party_instance_id":"no-such-network"})");
            THEN("nothing is listed, rather than the directory that was not asked for")
            {
                REQUIRE(listed_room_ids(response).empty());
            }
        }

        WHEN("include_all_networks is true")
        {
            auto const response = signed_call(runtime, "GET", path + "?include_all_networks=true");
            THEN("the server's own directory is still listed")
            {
                REQUIRE(listed_room_ids(response).size() == 3U);
            }
        }

        WHEN("include_all_networks is not a boolean")
        {
            auto const response = signed_call(runtime, "GET", path + "?include_all_networks=maybe");
            THEN("it is refused with 400 M_INVALID_PARAM")
            {
                REQUIRE(response.status == 400U);
                REQUIRE(response.body.find("M_INVALID_PARAM") != std::string::npos);
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19, POST /publicRooms: the same PublishedRoomsChunk and `room_types`
// filter, which this server's listing shares with the federation endpoint.
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#post_matrixclientv3publicrooms
SCENARIO("The client directory listing reports and filters by room type, and carries prev_batch",
         "[conformance][client-server][public_rooms]")
{
    GIVEN("a directory of three published rooms")
    {
        auto fixture = DirectoryFixture{federation_config()};
        auto& runtime = fixture.started.runtime;

        WHEN("the unauthenticated GET lists the rooms")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/publicRooms", {}, {}});
            THEN("the typed room reports its type")
            {
                REQUIRE(response.response.status == 200U);
                auto const answer = parse_object(response.response.body);
                auto const* room = entry_for(answer, fixture.space);
                REQUIRE(room != nullptr);
                REQUIRE(*string_member(*room, "room_type") == "m.space");
            }
        }

        WHEN("the second page is asked for")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/publicRooms?limit=1&since=1", {}, {}});
            THEN("prev_batch says there are results before it")
            {
                REQUIRE(response.response.status == 200U);
                auto const answer = parse_object(response.response.body);
                REQUIRE(string_member(answer, "prev_batch") != nullptr);
            }
        }
    }
}
