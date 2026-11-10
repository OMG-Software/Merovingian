// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
// Security audit run-2, F-12 (ADR-0339). PUT .../rooms/{roomId}/tags/{tag} read-modified-wrote one
// m.tag account-data row with no bound on tag count, tag name or row size, so the row outgrew any
// request body and every later tag request and /sync parsed it whole under runtime.mutex.
//
// Spec: client-server-api.md, "Room Tagging": "The name of a tag MUST NOT exceed 255 bytes." The
// spec states no count or row limit; those are ADR-0339 decisions, enforced for rows the server
// writes itself as well as for a client's account-data PUT.

#include "../support/e2ee_caps_support.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstddef>
#include <string>
#include <string_view>

namespace
{

[[nodiscard]] auto create_room(merovingian::homeserver::ClientServerRuntime& runtime, std::string const& token)
    -> std::string
{
    auto const created = merovingian::homeserver::handle_client_server_request(
        runtime, {"POST", "/_matrix/client/v3/createRoom", token, R"({"preset":"public_chat"})"});
    REQUIRE(created.response.status == 200U);
    return merovingian::tests::string_field(created.response.body, "room_id");
}

[[nodiscard]] auto put_tag(merovingian::homeserver::ClientServerRuntime& runtime, std::string const& token,
                           std::string const& room_id, std::string_view tag, std::string body)
    -> merovingian::homeserver::LocalHttpResponse
{
    return merovingian::homeserver::handle_client_server_request(
               runtime,
               {"PUT", "/_matrix/client/v3/user/%40alice%3Aexample.org/rooms/" + room_id + "/tags/" + std::string{tag},
                token, std::move(body)})
        .response;
}

[[nodiscard]] auto tag_row(merovingian::homeserver::ClientServerRuntime const& runtime, std::string const& room_id)
    -> std::string
{
    for (auto const& row : runtime.homeserver.database.persistent_store.account_data)
    {
        if (row.user_id == "@alice:example.org" && row.room_id == room_id && row.event_type == "m.tag")
        {
            return row.content_json;
        }
    }
    return {};
}

} // namespace

SCENARIO("a tag name over 255 bytes is refused", "[homeserver][client-server][room-tags][security][run2][f12]")
{
    GIVEN("alice in a room")
    {
        auto started = merovingian::homeserver::start_client_server(merovingian::tests::caps_config(100U, 100U, 100U));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const token = merovingian::tests::register_and_login_alice(runtime);
        auto const room_id = create_room(runtime, token);

        WHEN("she tags the room with a name of 256 bytes")
        {
            auto const refused = put_tag(runtime, token, room_id, "u." + std::string(254U, 'a'), R"({"order":0.5})");

            THEN("it is refused and nothing is stored")
            {
                REQUIRE(refused.status == 400U);
                REQUIRE(refused.body.find("M_INVALID_PARAM") != std::string::npos);
                REQUIRE(tag_row(runtime, room_id).empty());
            }
        }

        WHEN("she tags the room with a name of exactly 255 bytes")
        {
            auto const accepted = put_tag(runtime, token, room_id, "u." + std::string(253U, 'a'), R"({"order":0.5})");

            THEN("it is stored")
            {
                REQUIRE(accepted.status == 200U);
                REQUIRE_FALSE(tag_row(runtime, room_id).empty());
            }
        }
    }
}

SCENARIO("the tags of one room are bounded in count and size, and ordinary tagging still works",
         "[homeserver][client-server][room-tags][security][run2][f12]")
{
    GIVEN("alice in a room, tagged up to the per-room tag limit")
    {
        auto started = merovingian::homeserver::start_client_server(merovingian::tests::caps_config(100U, 100U, 100U));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const token = merovingian::tests::register_and_login_alice(runtime);
        auto const room_id = create_room(runtime, token);
        auto constexpr limit = std::size_t{merovingian::homeserver::max_tags_per_room};
        for (auto ordinal = std::size_t{0U}; ordinal < limit; ++ordinal)
        {
            REQUIRE(put_tag(runtime, token, room_id, "u.tag" + std::to_string(ordinal), R"({"order":0.5})").status ==
                    200U);
        }
        auto const row_before = tag_row(runtime, room_id);

        WHEN("she adds one more tag")
        {
            auto const refused = put_tag(runtime, token, room_id, "u.one-too-many", R"({"order":0.5})");

            THEN("it is refused with M_TOO_LARGE and the stored row is unchanged")
            {
                REQUIRE(refused.status == 400U);
                REQUIRE(refused.body.find("M_TOO_LARGE") != std::string::npos);
                REQUIRE(tag_row(runtime, room_id) == row_before);
            }
        }

        WHEN("she changes the order of a tag she already has")
        {
            auto const updated = put_tag(runtime, token, room_id, "u.tag0", R"({"order":0.25})");

            THEN("it is stored, because the tag count does not grow")
            {
                REQUIRE(updated.status == 200U);
                REQUIRE(tag_row(runtime, room_id).find("0.25") != std::string::npos);
            }
        }

        WHEN("she deletes a tag and adds another")
        {
            auto const deleted = merovingian::homeserver::handle_client_server_request(
                runtime, {"DELETE",
                          "/_matrix/client/v3/user/%40alice%3Aexample.org/rooms/" + room_id + "/tags/u.tag1",
                          token,
                          {}});
            auto const added = put_tag(runtime, token, room_id, "u.replacement", R"({"order":0.5})");

            THEN("both succeed")
            {
                REQUIRE(deleted.response.status == 200U);
                REQUIRE(added.status == 200U);
            }
        }
    }

    GIVEN("alice in a room")
    {
        auto started = merovingian::homeserver::start_client_server(merovingian::tests::caps_config(100U, 100U, 100U));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const token = merovingian::tests::register_and_login_alice(runtime);
        auto const room_id = create_room(runtime, token);

        WHEN("she tags the room with a value far larger than a tag's order information")
        {
            auto const body = std::string{R"({"order":0.5,"pad":")"} +
                              std::string(merovingian::homeserver::max_tag_value_bytes, 'x') + R"("})";
            auto const refused = put_tag(runtime, token, room_id, "u.heavy", body);

            THEN("it is refused with M_TOO_LARGE and nothing is stored")
            {
                REQUIRE(refused.status == 400U);
                REQUIRE(refused.body.find("M_TOO_LARGE") != std::string::npos);
                REQUIRE(tag_row(runtime, room_id).empty());
            }
        }

        WHEN("she tags the room the way Element does")
        {
            auto const favourite = put_tag(runtime, token, room_id, "m.favourite", R"({"order":0.5})");
            auto const low = put_tag(runtime, token, room_id, "m.lowpriority", "{}");
            auto const custom = put_tag(runtime, token, room_id, "u.Work", R"({"order":0.1})");

            THEN("all three are stored")
            {
                REQUIRE(favourite.status == 200U);
                REQUIRE(low.status == 200U);
                REQUIRE(custom.status == 200U);
                auto const row = tag_row(runtime, room_id);
                REQUIRE(row.find("m.favourite") != std::string::npos);
                REQUIRE(row.find("u.Work") != std::string::npos);
            }
        }
    }
}
