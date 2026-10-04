// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/database/persistent_store.hpp"
#include "merovingian/database/postgresql_store.hpp"
#include "merovingian/federation/server_acl.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace
{

[[nodiscard]] auto postgresql_uri_from_environment() -> std::string_view
{
    auto const* value = std::getenv("MEROVINGIAN_TEST_POSTGRESQL_URI");
    return value == nullptr ? std::string_view{} : std::string_view{value};
}

[[nodiscard]] auto unique_test_suffix() -> std::string
{
    static auto const base = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::system_clock::now().time_since_epoch())
            .count());
    static auto counter = std::uint64_t{0U};
    return std::to_string(base) + "-" + std::to_string(counter++);
}

[[nodiscard]] auto event_signature(std::string_view suffix) -> std::vector<merovingian::events::EventSignature>
{
    return {
        {"example.org", "ed25519:db2-test", "signature-" + std::string{suffix}}
    };
}

[[nodiscard]] auto acl_event_json(std::string_view event_id, std::string_view room_id, std::string_view user_id,
                                  std::string_view deny_server) -> std::string
{
    auto const deny = deny_server.empty() ? std::string{"[]"} : "[\"" + std::string{deny_server} + "\"]";
    return "{\"event_id\":\"" + std::string{event_id} + "\",\"room_id\":\"" + std::string{room_id} +
           "\",\"sender\":\"" + std::string{user_id} +
           "\",\"type\":\"m.room.server_acl\",\"state_key\":\"\",\"content\":{\"allow\":[\"*\"],\"deny\":" + deny +
           ",\"allow_ip_literals\":true}}";
}

[[nodiscard]] auto event_json(std::string_view event_id, std::string_view room_id, std::string_view user_id,
                              std::uint64_t index) -> std::string
{
    return "{\"event_id\":\"" + std::string{event_id} + "\",\"room_id\":\"" + std::string{room_id} +
           "\",\"sender\":\"" + std::string{user_id} +
           "\",\"type\":\"org.example.db2.filler\",\"content\":{\"index\":" + std::to_string(index) + "}}";
}

} // namespace

SCENARIO("PostgreSQL reload_room hydrates room event relations beyond the prepared-query parameter limit",
         "[security_audit_postgresql_reload][database][postgresql][integration]")
{
    GIVEN("two independent PostgreSQL store handles and a room whose ACL initially allows an origin")
    {
        auto const uri = postgresql_uri_from_environment();
        if (uri.empty())
        {
            SUCCEED("skipped: MEROVINGIAN_TEST_POSTGRESQL_URI is not set");
            return;
        }

        auto opened_a = merovingian::database::open_postgresql_persistent_store(uri);
        auto opened_b = merovingian::database::open_postgresql_persistent_store(uri);
        REQUIRE(opened_a.ok);
        REQUIRE(opened_b.ok);

        auto const suffix = unique_test_suffix();
        auto const user_id = "@db2-reload-" + suffix + ":example.org";
        auto const room_id = "!db2-reload-" + suffix + ":example.org";
        auto const origin = "denied-" + suffix + ".example.org";
        auto const initial_acl_id = "$db2-initial-acl-" + suffix + ":example.org";
        auto const event_total = std::size_t{202U};
        auto event_ids = std::vector<std::string>{};
        event_ids.reserve(event_total);

        WHEN("handle B stores the initial ACL and handle A reloads the small room snapshot")
        {
            REQUIRE(merovingian::database::store_room(opened_b.store, {room_id, user_id}));
            REQUIRE(merovingian::database::store_membership(opened_b.store, {room_id, user_id, "join", 1U}) ==
                    merovingian::database::MembershipStoreResult::stored);
            REQUIRE(merovingian::database::store_event_with_state(
                opened_b.store,
                {initial_acl_id,
                 room_id,
                 user_id,
                 acl_event_json(initial_acl_id, room_id, user_id, {}),
                 1U,
                 1U,
                 {},
                 {},
                 event_signature("initial")},
                merovingian::database::PersistentStateEvent{room_id, "m.room.server_acl", "", initial_acl_id}));
            REQUIRE(merovingian::database::reload_room(opened_a.store, room_id));

            THEN("the reloaded snapshot currently allows that origin")
            {
                REQUIRE(merovingian::federation::room_server_acl_allows(opened_a.store, room_id, origin));

                AND_WHEN("handle B commits more than 128 room events and changes the current ACL to deny the origin")
                {
                    auto previous_event_id = initial_acl_id;
                    auto const filler_count = event_total - 2U;
                    for (auto index = std::size_t{0U}; index < filler_count; ++index)
                    {
                        auto const event_id = "$db2-event-" + suffix + "-" + std::to_string(index) + ":example.org";
                        auto event = merovingian::database::PersistentEvent{
                            event_id,
                            room_id,
                            user_id,
                            event_json(event_id, room_id, user_id, static_cast<std::uint64_t>(index)),
                            static_cast<std::uint64_t>(index + 2U),
                            static_cast<std::uint64_t>(index + 2U),
                            {previous_event_id},
                            {initial_acl_id},
                            event_signature(std::to_string(index))};
                        REQUIRE(merovingian::database::store_event_with_state(opened_b.store, std::move(event),
                                                                              std::nullopt));
                        event_ids.push_back(event_id);
                        previous_event_id = event_id;
                    }

                    auto const final_acl_id = "$db2-final-acl-" + suffix + ":example.org";
                    auto final_acl =
                        merovingian::database::PersistentEvent{final_acl_id,
                                                               room_id,
                                                               user_id,
                                                               acl_event_json(final_acl_id, room_id, user_id, origin),
                                                               static_cast<std::uint64_t>(event_total),
                                                               static_cast<std::uint64_t>(event_total),
                                                               {previous_event_id},
                                                               {initial_acl_id},
                                                               event_signature("final-acl")};
                    REQUIRE(merovingian::database::store_event_with_state(
                        opened_b.store, std::move(final_acl),
                        merovingian::database::PersistentStateEvent{room_id, "m.room.server_acl", "", final_acl_id}));
                    event_ids.push_back(final_acl_id);

                    THEN("handle A reloads the full event graph and applies the current denying ACL")
                    {
                        REQUIRE(merovingian::database::reload_room(opened_a.store, room_id));
                        REQUIRE_FALSE(merovingian::federation::room_server_acl_allows(opened_a.store, room_id, origin));

                        auto const room_events = std::ranges::count_if(
                            opened_a.store.events, [&room_id](merovingian::database::PersistentEvent const& event) {
                                return event.room_id == room_id;
                            });
                        REQUIRE(room_events == event_total);

                        auto const room_event_edges = std::ranges::count_if(
                            opened_a.store.event_edges,
                            [&event_ids](merovingian::database::PersistentEventEdge const& edge) {
                                return std::ranges::find(event_ids, edge.event_id) != event_ids.end();
                            });
                        auto const room_event_auth = std::ranges::count_if(
                            opened_a.store.event_auth,
                            [&event_ids](merovingian::database::PersistentEventAuth const& auth) {
                                return std::ranges::find(event_ids, auth.event_id) != event_ids.end();
                            });
                        auto const room_event_signatures = std::ranges::count_if(
                            opened_a.store.event_signatures,
                            [&event_ids](merovingian::database::PersistentEventSignature const& signature) {
                                return std::ranges::find(event_ids, signature.event_id) != event_ids.end();
                            });
                        REQUIRE(room_event_edges == event_total - 1U);
                        REQUIRE(room_event_auth == event_total - 1U);
                        REQUIRE(room_event_signatures == event_total - 1U);
                        REQUIRE(std::ranges::all_of(event_ids, [&opened_a](std::string const& event_id) {
                            auto const event = std::ranges::find_if(
                                opened_a.store.events, [&event_id](merovingian::database::PersistentEvent const& row) {
                                    return row.event_id == event_id;
                                });
                            return event != opened_a.store.events.end() && event->prev_event_ids.size() == 1U &&
                                   event->auth_event_ids.size() == 1U && event->signatures.size() == 1U &&
                                   event->signatures.front().server_name == "example.org" &&
                                   event->signatures.front().key_id == "ed25519:db2-test" &&
                                   !event->signatures.front().signature.empty();
                        }));

                        auto const final_acl_row =
                            std::ranges::find_if(opened_a.store.events,
                                                 [&final_acl_id](merovingian::database::PersistentEvent const& event) {
                                                     return event.event_id == final_acl_id;
                                                 });
                        REQUIRE(final_acl_row != opened_a.store.events.end());
                        REQUIRE(final_acl_row->prev_event_ids == std::vector<std::string>{previous_event_id});
                        REQUIRE(final_acl_row->auth_event_ids == std::vector<std::string>{initial_acl_id});
                        REQUIRE(final_acl_row->signatures.size() == 1U);
                        REQUIRE(final_acl_row->signatures.front().server_name == "example.org");
                        REQUIRE(final_acl_row->signatures.front().key_id == "ed25519:db2-test");
                        REQUIRE(final_acl_row->signatures.front().signature == "signature-final-acl");
                    }
                }
            }
        }
    }
}
