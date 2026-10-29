// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// +-------------------------------------------------------------------------+
// |        FEDERATION HISTORY-VISIBILITY (SERVER-LEVEL) CONFORMANCE TESTS    |
// |                                                                         |
// |  Spec: Matrix Client-Server API v1.19, "Room History Visibility"        |
// |  URL:  ../../docs/matrix-v1.19-spec/client-server-api.md                |
// |        #room-history-visibility                                         |
// |                                                                         |
// |  The Server-Server API says nothing about history visibility between    |
// |  servers. The project rule (owner decision 2026-10-29, ADR proposed in  |
// |  the change description) applies the four client settings to the        |
// |  REQUESTING SERVER: an event none of that server's users could see is   |
// |  sent redacted, never dropped. The tests below fix that behaviour.      |
// |                                                                         |
// |  !! IMPORTANT - FOR HUMANS AND LLMs ALIKE !!                            |
// |  If a test fails, fix the IMPLEMENTATION. Do NOT weaken, comment out,   |
// |  or remove assertions to make CI pass.                                  |
// +-------------------------------------------------------------------------+

#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/events/event_id.hpp"
#include "merovingian/federation/event_query.hpp"
#include "merovingian/rooms/room_version_policy.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace
{

namespace db = merovingian::database;
namespace fed = merovingian::federation;
namespace cj = merovingian::canonicaljson;

constexpr auto room_id = std::string_view{"!room:local.example"};
constexpr auto local_server = std::string_view{"local.example"};
constexpr auto remote_server = std::string_view{"remote.example"};
constexpr auto alice = std::string_view{"@alice:local.example"};
constexpr auto bob = std::string_view{"@bob:remote.example"};
constexpr auto carol = std::string_view{"@carol:remote.example"};

// A room history written straight into a PersistentStore, one event at a time, with the state
// group (ADR-0064) recorded for each event: the room's state immediately after it. Each event
// carries hashes, signatures, prev_events, auth_events and an `unsigned` block, so a redacted
// copy can be compared with the original.
class RoomHistory final
{
public:
    RoomHistory()
    {
        add_state("$create", "m.room.create", "", alice, R"({"room_version":"10","creator":"@alice:local.example"})");
        add_state("$alice_join", "m.room.member", alice, alice,
                  R"({"membership":"join","displayname":"Alice Secret Name"})");
    }

    auto add_state(std::string event_id, std::string type, std::string_view state_key, std::string_view sender,
                   std::string_view content_json) -> void
    {
        push(event_id, type, std::optional<std::string>{std::string{state_key}}, sender, content_json);
        state_[{type, std::string{state_key}}] = event_id;
        record_group(event_id);
    }

    auto add_message(std::string event_id, std::string_view sender = alice) -> void
    {
        push(event_id, "m.room.message", std::nullopt, sender, R"({"msgtype":"m.text","body":"secret body"})");
        record_group(event_id);
    }

    auto set_visibility(std::string event_id, std::string_view visibility) -> void
    {
        add_state(std::move(event_id), "m.room.history_visibility", "", alice,
                  R"({"history_visibility":")" + std::string{visibility} + R"("})");
    }

    auto set_membership(std::string event_id, std::string_view user, std::string_view membership) -> void
    {
        add_state(std::move(event_id), "m.room.member", user, user == bob || user == carol ? alice : user,
                  R"({"membership":")" + std::string{membership} + R"(","displayname":"Secret Name"})");
    }

    // An event stored with no state group at all (an outlier, or history from before ADR-0064).
    auto add_message_without_state_group(std::string event_id) -> void
    {
        push(event_id, "m.room.message", std::nullopt, alice, R"({"msgtype":"m.text","body":"secret body"})");
    }

    // Writes the room's current state rows from the history so far. Call once, after the last event.
    auto finish() -> db::PersistentStore&
    {
        for (auto const& [key, event_id] : state_)
        {
            store_.state.push_back({std::string{room_id}, key.first, key.second, event_id});
        }
        return store_;
    }

    [[nodiscard]] auto last_event_id() const -> std::string const&
    {
        return last_;
    }

private:
    auto push(std::string const& event_id, std::string const& type, std::optional<std::string> const& state_key,
              std::string_view sender, std::string_view content_json) -> void
    {
        ++counter_;
        auto event = db::PersistentEvent{};
        event.event_id = event_id;
        event.room_id = std::string{room_id};
        event.sender_user_id = std::string{sender};
        event.depth = counter_;
        event.stream_ordering = counter_;
        if (!last_.empty())
        {
            event.prev_event_ids.push_back(last_);
        }
        if (event_id != "$create")
        {
            event.auth_event_ids.push_back("$create");
        }
        auto json = std::string{R"({"type":")"} + type + R"(","room_id":")" + std::string{room_id} + R"(","sender":")" +
                    std::string{sender} + R"(")";
        if (state_key.has_value())
        {
            json += R"(,"state_key":")" + *state_key + R"(")";
        }
        json += R"(,"content":)" + std::string{content_json};
        json += R"(,"origin_server_ts":)" + std::to_string(1000U + counter_);
        json += R"(,"depth":)" + std::to_string(counter_);
        json += R"(,"prev_events":[)" + (last_.empty() ? std::string{} : "\"" + last_ + "\"") + "]";
        json += R"(,"auth_events":[)" + (event_id == "$create" ? std::string{} : std::string{"\"$create\""}) + "]";
        json += R"(,"hashes":{"sha256":"hash-)" + event_id + R"("})";
        json += R"(,"signatures":{"local.example":{"ed25519:a":"sig-)" + event_id + R"("}})";
        json += R"(,"unsigned":{"age":5,"private":"unsigned-secret"}})";
        event.json = std::move(json);
        store_.events.push_back(std::move(event));
        last_ = event_id;
    }

    auto record_group(std::string const& event_id) -> void
    {
        auto entries = std::vector<db::PersistentStateGroupStateEntry>{};
        for (auto const& [key, state_event_id] : state_)
        {
            entries.push_back({std::string{}, key.first, key.second, state_event_id});
        }
        auto const group = db::create_or_reuse_state_group(store_, room_id, "sg:" + event_id, std::nullopt, entries);
        REQUIRE(group.has_value());
        REQUIRE(db::set_event_state_group(store_, event_id, *group));
    }

    db::PersistentStore store_{};
    std::map<std::pair<std::string, std::string>, std::string> state_{};
    std::string last_{};
    std::uint64_t counter_{0U};
};

// The standard story. Bob's server joins part-way through:
//   create, alice joins, [visibility = V], m_before, bob invited, m_invited, bob joined, m_joined.
[[nodiscard]] auto standard_history(std::string_view visibility) -> RoomHistory
{
    auto history = RoomHistory{};
    history.set_visibility("$hv", visibility);
    history.add_message("$m_before");
    history.set_membership("$bob_invite", bob, "invite");
    history.add_message("$m_invited");
    history.set_membership("$bob_join", bob, "join");
    history.add_message("$m_joined");
    return history;
}

[[nodiscard]] auto parse_object(std::string_view json) -> cj::Object
{
    auto parsed = cj::parse_lossless(json);
    REQUIRE(parsed.error == cj::ParseError::none);
    auto const* object = std::get_if<cj::Object>(&parsed.value.storage());
    REQUIRE(object != nullptr);
    return *object;
}

[[nodiscard]] auto member_of(cj::Object const& object, std::string_view key) -> cj::Value const*
{
    for (auto const& member : object)
    {
        if (member.key == key)
        {
            return member.value.get();
        }
    }
    return nullptr;
}

[[nodiscard]] auto object_of(cj::Object const& object, std::string_view key) -> cj::Object const*
{
    auto const* value = member_of(object, key);
    return value == nullptr ? nullptr : std::get_if<cj::Object>(&value->storage());
}

[[nodiscard]] auto array_of(cj::Object const& object, std::string_view key) -> cj::Array const*
{
    auto const* value = member_of(object, key);
    return value == nullptr ? nullptr : std::get_if<cj::Array>(&value->storage());
}

[[nodiscard]] auto string_of(cj::Object const& object, std::string_view key) -> std::string
{
    auto const* value = member_of(object, key);
    auto const* text = value == nullptr ? nullptr : std::get_if<std::string>(&value->storage());
    return text == nullptr ? std::string{} : *text;
}

// What one served PDU shows: whether it kept its content, and which stored event it is (the
// `hashes.sha256` of the fixture names the event).
struct ServedPdu final
{
    std::string event_id{};
    cj::Object object{};
};

[[nodiscard]] auto served_pdu(std::string_view json) -> ServedPdu
{
    auto object = parse_object(json);
    auto served = ServedPdu{};
    if (auto const* hashes = object_of(object, "hashes"); hashes != nullptr)
    {
        auto const hash = string_of(*hashes, "sha256");
        served.event_id = hash.substr(std::string_view{"hash-"}.size());
    }
    served.object = std::move(object);
    return served;
}

[[nodiscard]] auto serve_backfill(db::PersistentStore const& store, std::string_view origin,
                                  std::string_view from_event = "$m_joined") -> std::map<std::string, ServedPdu>
{
    auto request = fed::BackfillRequest{};
    request.room_id = std::string{room_id};
    request.event_ids = {std::string{from_event}};
    request.limit = 100U;
    request.origin = std::string{origin};
    auto const result = fed::build_backfill_response(store, request);
    REQUIRE(result.accepted);
    auto by_id = std::map<std::string, ServedPdu>{};
    for (auto const& pdu : result.pdus_json)
    {
        auto served = served_pdu(pdu);
        auto const id = served.event_id;
        by_id.emplace(id, std::move(served));
    }
    return by_id;
}

// Whether a served PDU still has the event's own content. A message keeps `body`; a membership
// event keeps `displayname`; both are stripped by redaction.
[[nodiscard]] auto shows_content(ServedPdu const& pdu) -> bool
{
    auto const* content = object_of(pdu.object, "content");
    return content != nullptr &&
           (member_of(*content, "body") != nullptr || member_of(*content, "displayname") != nullptr);
}

[[nodiscard]] auto ok_body(fed::RoomReadResult const& result) -> cj::Object
{
    REQUIRE(result.status == fed::RoomReadStatus::ok);
    return parse_object(result.body);
}

} // namespace

// Spec: Matrix Client-Server API v1.19, Room History Visibility.
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#room-history-visibility
//
// "shared" and "world_readable": every event is visible to the server whatever its users'
// membership was when the event was sent. The server of a user who joined LATER sees the
// whole history in full.
SCENARIO("A server reads shared and world_readable history in full, including before its user joined",
         "[federation][conformance][history-visibility][server-visibility]")
{
    for (auto const* visibility : {"shared", "world_readable"})
    {
        GIVEN("a room whose history visibility is " + std::string{visibility} + " and a server that joined late")
        {
            auto history = standard_history(visibility);
            auto const& store = history.finish();

            WHEN("the server backfills the room")
            {
                auto const served = serve_backfill(store, remote_server);

                THEN("every event is served, in full")
                {
                    REQUIRE(served.size() == 8U);
                    for (auto const* event_id :
                         {"$m_before", "$m_invited", "$m_joined", "$alice_join", "$bob_invite", "$bob_join"})
                    {
                        INFO(event_id);
                        // Project rule: shared and world_readable history is not hidden from a server.
                        REQUIRE(shows_content(served.at(event_id)));
                    }
                }
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19, Room History Visibility ("joined").
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#room-history-visibility
//
// "joined": events are visible only to users who were joined when they were sent. A server whose
// only user joined afterwards sees the earlier events redacted, and the later ones in full.
SCENARIO("A server whose only user joined after an event reads it redacted under joined visibility",
         "[federation][conformance][history-visibility][server-visibility]")
{
    GIVEN("a joined-visibility room in which the remote server's user was invited, then joined")
    {
        auto history = standard_history("joined");
        auto const& store = history.finish();

        WHEN("the remote server backfills the room")
        {
            auto const served = serve_backfill(store, remote_server);

            THEN("every event is still served: none is dropped from the graph")
            {
                // Project rule: a redacted event keeps its place in the DAG.
                REQUIRE(served.size() == 8U);
            }

            THEN("events sent before the server had a joined user are redacted")
            {
                REQUIRE_FALSE(shows_content(served.at("$m_before")));
                REQUIRE_FALSE(shows_content(served.at("$m_invited")));
            }

            THEN("events sent before the room was restricted fall under the default, shared, and are in full")
            {
                // The state at $alice_join has no m.room.history_visibility: shared.
                REQUIRE(shows_content(served.at("$alice_join")));
            }

            THEN("an invite is not enough under joined visibility")
            {
                REQUIRE_FALSE(shows_content(served.at("$bob_invite")));
            }

            THEN("events sent while the server had a joined user are served in full")
            {
                REQUIRE(shows_content(served.at("$m_joined")));
                // The user's own join event is the state in which the server is joined.
                REQUIRE(shows_content(served.at("$bob_join")));
            }
        }

        WHEN("a server with no user in the room backfills it")
        {
            THEN("it is still refused outright")
            {
                auto request = fed::BackfillRequest{};
                request.room_id = std::string{room_id};
                request.event_ids = {"$m_joined"};
                request.limit = 10U;
                request.origin = "stranger.example";
                auto const result = fed::build_backfill_response(store, request);
                // Existing gate (FED-2) stays in front of the visibility rule.
                REQUIRE_FALSE(result.accepted);
                REQUIRE(result.status == 403U);
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19, Room History Visibility ("invited").
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#room-history-visibility
//
// "invited": visible to users who were invited or joined when the event was sent.
SCENARIO("A server whose user was invited reads invited-visibility events, but not earlier ones",
         "[federation][conformance][history-visibility][server-visibility]")
{
    GIVEN("an invited-visibility room in which the remote server's user was invited, then joined")
    {
        auto history = standard_history("invited");
        auto const& store = history.finish();

        WHEN("the remote server backfills the room")
        {
            auto const served = serve_backfill(store, remote_server);

            THEN("events from before the invite are redacted")
            {
                REQUIRE_FALSE(shows_content(served.at("$m_before")));
            }

            THEN("events sent before the room was restricted fall under the default, shared, and are in full")
            {
                REQUIRE(shows_content(served.at("$alice_join")));
            }

            THEN("events from the invite on are served in full")
            {
                REQUIRE(shows_content(served.at("$bob_invite")));
                REQUIRE(shows_content(served.at("$m_invited")));
                REQUIRE(shows_content(served.at("$bob_join")));
                REQUIRE(shows_content(served.at("$m_joined")));
            }
        }
    }

    GIVEN("a joined-visibility room where the remote server has one invited user and another joined user")
    {
        auto history = RoomHistory{};
        history.set_visibility("$hv", "joined");
        history.set_membership("$bob_invite", bob, "invite");
        history.add_message("$m_invited_only");
        history.set_membership("$carol_join", carol, "join");
        history.add_message("$m_carol_joined");
        auto const& store = history.finish();

        WHEN("the remote server backfills the room")
        {
            auto const served = serve_backfill(store, remote_server, "$m_carol_joined");

            THEN("any one joined user of the server is enough to see events after that join")
            {
                REQUIRE(shows_content(served.at("$m_carol_joined")));
            }

            THEN("an invited user alone is not enough under joined visibility")
            {
                REQUIRE_FALSE(shows_content(served.at("$m_invited_only")));
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19, Room History Visibility: "the visibility ... at the time of
// the event", i.e. the m.room.history_visibility in the state at the event, not the current one.
SCENARIO("The history visibility in force at the event decides, not the room's current setting",
         "[federation][conformance][history-visibility][server-visibility]")
{
    GIVEN("a room that was joined-only, became shared after the remote server joined")
    {
        auto history = RoomHistory{};
        history.set_visibility("$hv_joined", "joined");
        history.add_message("$m_under_joined");
        history.set_membership("$bob_join", bob, "join");
        history.set_visibility("$hv_shared", "shared");
        history.add_message("$m_under_shared");
        auto const& store = history.finish();

        WHEN("the remote server backfills the room")
        {
            auto const served = serve_backfill(store, remote_server, "$m_under_shared");

            THEN("an event sent under joined, before the server's user joined, stays redacted")
            {
                // The room is shared NOW, but the event was sent under joined.
                REQUIRE_FALSE(shows_content(served.at("$m_under_joined")));
            }

            THEN("an event sent under shared is served in full")
            {
                REQUIRE(shows_content(served.at("$m_under_shared")));
            }
        }
    }

    GIVEN("a room that was shared, became joined-only after the remote server joined")
    {
        auto history = RoomHistory{};
        history.set_visibility("$hv_shared", "shared");
        history.add_message("$m_under_shared");
        history.set_membership("$bob_join", bob, "join");
        history.set_visibility("$hv_joined", "joined");
        history.add_message("$m_under_joined");
        auto const& store = history.finish();

        WHEN("the remote server backfills the room")
        {
            auto const served = serve_backfill(store, remote_server, "$m_under_joined");

            THEN("an event sent under shared stays visible although the room is joined-only now")
            {
                REQUIRE(shows_content(served.at("$m_under_shared")));
            }

            THEN("the event sent while the server was joined is visible under joined")
            {
                REQUIRE(shows_content(served.at("$m_under_joined")));
            }
        }
    }

    GIVEN("a room whose history_visibility event itself changes the setting")
    {
        auto history = RoomHistory{};
        history.set_membership("$bob_join", bob, "join");
        history.set_visibility("$hv_joined", "joined");
        auto const& store = history.finish();

        WHEN("the visibility of the m.room.history_visibility event is judged")
        {
            THEN("it is judged under the setting it carries, which the joined server satisfies")
            {
                REQUIRE(fed::event_visible_to_server(store, "$hv_joined", remote_server));
            }
        }
    }

    GIVEN("a room with no m.room.history_visibility event at all")
    {
        auto history = RoomHistory{};
        history.add_message("$m_default");
        history.set_membership("$bob_join", bob, "join");
        auto const& store = history.finish();

        WHEN("the remote server judges an event sent before its user joined")
        {
            THEN("the default, shared, applies and the event is visible")
            {
                REQUIRE(fed::event_visible_to_server(store, "$m_default", remote_server));
            }
        }
    }
}

// Project rule: a redacted event is the room version's redaction of the stored event with its
// signatures and hashes kept, so the receiver can still verify it and place it in the graph.
SCENARIO("A redacted event keeps its identity, hashes, signatures and place in the graph",
         "[federation][conformance][history-visibility][server-visibility]")
{
    GIVEN("a joined-visibility room and an event sent before the remote server joined")
    {
        auto history = standard_history("joined");
        auto const& store = history.finish();
        auto const* policy = merovingian::rooms::find_room_version_policy("10");
        REQUIRE(policy != nullptr);
        auto const* stored =
            store.events.find("$m_before") == store.events.end() ? nullptr : &*store.events.find("$m_before");
        REQUIRE(stored != nullptr);

        WHEN("the remote server reads it through /event")
        {
            auto const body = ok_body(fed::build_event_response(store, "$m_before", local_server, remote_server));
            auto const* pdus = array_of(body, "pdus");
            REQUIRE(pdus != nullptr);
            REQUIRE(pdus->size() == 1U);
            auto const* served = std::get_if<cj::Object>(&pdus->front().storage());
            REQUIRE(served != nullptr);
            auto const original = parse_object(stored->json);

            THEN("its content is stripped")
            {
                auto const* content = object_of(*served, "content");
                REQUIRE(content != nullptr);
                REQUIRE(content->empty());
            }

            THEN("its unsigned block is not sent")
            {
                REQUIRE(member_of(*served, "unsigned") == nullptr);
            }

            THEN("its hashes and signatures are exactly the original's")
            {
                auto const* original_hashes = object_of(original, "hashes");
                auto const* original_signatures = object_of(original, "signatures");
                auto const* hashes = object_of(*served, "hashes");
                auto const* signatures = object_of(*served, "signatures");
                REQUIRE(hashes != nullptr);
                REQUIRE(signatures != nullptr);
                REQUIRE(string_of(*hashes, "sha256") == string_of(*original_hashes, "sha256"));
                auto const* server_signatures = object_of(*signatures, "local.example");
                auto const* original_server_signatures = object_of(*original_signatures, "local.example");
                REQUIRE(server_signatures != nullptr);
                REQUIRE(string_of(*server_signatures, "ed25519:a") ==
                        string_of(*original_server_signatures, "ed25519:a"));
            }

            THEN("its prev_events, auth_events, depth and sender are unchanged")
            {
                auto const strings = [](cj::Object const& object, std::string_view key) {
                    auto out = std::vector<std::string>{};
                    if (auto const* array = array_of(object, key); array != nullptr)
                    {
                        for (auto const& element : *array)
                        {
                            if (auto const* text = std::get_if<std::string>(&element.storage()); text != nullptr)
                            {
                                out.push_back(*text);
                            }
                        }
                    }
                    return out;
                };
                REQUIRE(strings(*served, "prev_events") == strings(original, "prev_events"));
                REQUIRE_FALSE(strings(*served, "prev_events").empty());
                REQUIRE(strings(*served, "auth_events") == strings(original, "auth_events"));
                REQUIRE(string_of(*served, "sender") == string_of(original, "sender"));
                REQUIRE(string_of(*served, "type") == string_of(original, "type"));
                REQUIRE(string_of(*served, "room_id") == string_of(original, "room_id"));
            }

            THEN("its event ID, the reference hash of the redacted event, is unchanged")
            {
                auto const original_id =
                    merovingian::events::make_reference_hash_event_id(cj::Value{original}, *policy);
                auto const served_id = merovingian::events::make_reference_hash_event_id(cj::Value{*served}, *policy);
                REQUIRE(original_id.error.empty());
                REQUIRE(served_id.error.empty());
                REQUIRE(served_id.event_id == original_id.event_id);
            }
        }

        WHEN("the remote server reads it through /get_missing_events")
        {
            auto const body = ok_body(fed::build_get_missing_events_response(
                store, room_id, R"({"latest_events":["$m_joined"],"earliest_events":[],"limit":20})", remote_server));
            auto const* events = array_of(body, "events");
            REQUIRE(events != nullptr);

            THEN("the events before its join are present and redacted, the later one is full")
            {
                auto saw_before = false;
                for (auto const& element : *events)
                {
                    auto const* object = std::get_if<cj::Object>(&element.storage());
                    REQUIRE(object != nullptr);
                    auto served = ServedPdu{};
                    served.object = *object;
                    auto const* hashes = object_of(*object, "hashes");
                    REQUIRE(hashes != nullptr);
                    if (string_of(*hashes, "sha256") == "hash-$m_before")
                    {
                        saw_before = true;
                        REQUIRE_FALSE(shows_content(served));
                    }
                }
                REQUIRE(saw_before);
                REQUIRE(events->size() == 7U);
            }
        }
    }
}

// Project rule: the judgement runs on the state recorded for the event. An event whose state
// cannot be determined is not shown in full.
SCENARIO("An event with no recorded state is served redacted, never in full",
         "[federation][conformance][history-visibility][server-visibility]")
{
    GIVEN("a shared room holding one event that has no state group")
    {
        auto history = RoomHistory{};
        history.set_visibility("$hv", "shared");
        history.set_membership("$bob_join", bob, "join");
        history.add_message_without_state_group("$m_no_group");
        history.add_message("$m_grouped");
        auto const& store = history.finish();

        WHEN("the remote server judges both events")
        {
            THEN("the grouped event is visible and the group-less one is not")
            {
                REQUIRE(fed::event_visible_to_server(store, "$m_grouped", remote_server));
                REQUIRE_FALSE(fed::event_visible_to_server(store, "$m_no_group", remote_server));
            }
        }

        WHEN("the remote server backfills past it")
        {
            auto const served = serve_backfill(store, remote_server, "$m_grouped");

            THEN("the group-less event is still served, but redacted")
            {
                REQUIRE(served.contains("$m_no_group"));
                REQUIRE_FALSE(shows_content(served.at("$m_no_group")));
                REQUIRE(shows_content(served.at("$m_grouped")));
            }
        }
    }

    GIVEN("an unknown event")
    {
        auto history = standard_history("shared");
        auto const& store = history.finish();

        WHEN("it is judged")
        {
            THEN("it is not visible")
            {
                REQUIRE_FALSE(fed::event_visible_to_server(store, "$unknown", remote_server));
            }
        }
    }
}

// Project rule: state is part of the room's authorisation, so a server joining or catching up
// receives it in full whatever the history visibility says.
SCENARIO("State and auth chain answers are never redacted by history visibility",
         "[federation][conformance][history-visibility][server-visibility]")
{
    GIVEN("a joined-visibility room in which the remote server is joined now")
    {
        auto history = standard_history("joined");
        auto const& store = history.finish();

        WHEN("the remote server asks for the state before an event sent before it joined")
        {
            auto const body = ok_body(fed::build_state_response(store, room_id, "$m_before", remote_server));

            THEN("every state event is in full, displayname included")
            {
                auto const* pdus = array_of(body, "pdus");
                REQUIRE(pdus != nullptr);
                REQUIRE_FALSE(pdus->empty());
                auto saw_alice_join = false;
                for (auto const& element : *pdus)
                {
                    auto const* object = std::get_if<cj::Object>(&element.storage());
                    REQUIRE(object != nullptr);
                    if (string_of(*object, "type") == "m.room.member")
                    {
                        saw_alice_join = true;
                        auto const* content = object_of(*object, "content");
                        REQUIRE(content != nullptr);
                        // Project rule: /state is sent in full.
                        REQUIRE(string_of(*content, "displayname") == "Alice Secret Name");
                    }
                }
                REQUIRE(saw_alice_join);
            }
        }

        WHEN("the remote server asks for the state IDs before an event sent before it joined")
        {
            auto const body = ok_body(fed::build_state_ids_response(store, room_id, "$m_before", remote_server));

            THEN("the IDs of the state are all there")
            {
                auto const* ids = array_of(body, "pdu_ids");
                REQUIRE(ids != nullptr);
                REQUIRE(ids->size() == 3U); // create, alice's join, the history_visibility event
            }
        }

        WHEN("the remote server asks for the auth chain of its own join")
        {
            auto const body = ok_body(fed::build_event_auth_response(store, room_id, "$bob_join", remote_server));

            THEN("the chain's events are in full")
            {
                auto const* chain = array_of(body, "auth_chain");
                REQUIRE(chain != nullptr);
                REQUIRE_FALSE(chain->empty());
                for (auto const& element : *chain)
                {
                    auto const* object = std::get_if<cj::Object>(&element.storage());
                    REQUIRE(object != nullptr);
                    // The create event keeps its content under redaction too, so check that the
                    // unsigned block, which redaction removes, is still there.
                    REQUIRE(member_of(*object, "unsigned") != nullptr);
                }
            }
        }
    }
}
