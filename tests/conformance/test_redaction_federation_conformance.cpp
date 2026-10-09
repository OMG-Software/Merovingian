// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#include "../federation_signing_test_support.hpp"
#include "../support/remote_room_fixture.hpp"

// Conformance tests for CSAZ-11 over federation: a redaction arriving in a PDU is applied only when
// the room version's "Handling redactions" rule says so.
//
// Spec: rooms/v10.md "Handling redactions" (identical text in rooms/v3.md ... rooms/v12.md):
//   "While redactions are always accepted by the authorisation rules for events, they should not be
//   sent to clients until both the redaction event and the event the redaction affects have been
//   received, and can be validated. If both events are valid and have been seen by the server, then
//   the server applies the redaction if one of the following conditions is met:
//   1. The power level of the redaction event's `sender` is greater than or equal to the redact level.
//   2. The domain of the redaction event's `sender` matches that of the original event's `sender`.
//   If the server would apply a redaction, the redaction event is also sent to clients. Otherwise,
//   the server simply waits for a valid partner event to arrive where it can then re-check the above."
// URL: ../../docs/matrix-v1.19-spec/rooms/v10.md#handling-redactions

#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/serializer.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/federation/inbound_ingestion.hpp"
#include "merovingian/homeserver/local_http_router.hpp"
#include "merovingian/homeserver/room_service.hpp"
#include "merovingian/homeserver/runtime.hpp"
#include "merovingian/homeserver/state_bookkeeping.hpp"
#include "merovingian/sync/history_visibility.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace
{

using namespace merovingian::tests::remote_room;
using merovingian::federation::InboundPduEnvelope;
using merovingian::federation::PduIngestionStatus;
using merovingian::homeserver::HomeserverRuntime;

[[nodiscard]] auto object_string(merovingian::canonicaljson::Object const& object, std::string_view key)
    -> std::optional<std::string>
{
    for (auto const& member : object)
    {
        if (member.key == key)
        {
            if (auto const* text = std::get_if<std::string>(&member.value->storage()); text != nullptr)
            {
                return *text;
            }
        }
    }
    return std::nullopt;
}

[[nodiscard]] auto object_object(merovingian::canonicaljson::Object const& object, std::string_view key)
    -> merovingian::canonicaljson::Object const*
{
    for (auto const& member : object)
    {
        if (member.key == key)
        {
            return std::get_if<merovingian::canonicaljson::Object>(&member.value->storage());
        }
    }
    return nullptr;
}

[[nodiscard]] auto parse_stored(std::string const& json) -> merovingian::canonicaljson::Object
{
    auto const parsed = merovingian::canonicaljson::parse_lossless(json);
    auto const* object = std::get_if<merovingian::canonicaljson::Object>(&parsed.value.storage());
    REQUIRE(object != nullptr);
    return *object;
}

[[nodiscard]] auto find_stored(HomeserverRuntime& runtime, std::string const& event_id)
    -> merovingian::database::PersistentEvent const*
{
    for (auto const& event : runtime.database.persistent_store.events)
    {
        if (event.event_id == event_id)
        {
            return &event;
        }
    }
    return nullptr;
}

// A v10 redaction PDU from the remote server: `redacts` is a top-level property before room v11.
[[nodiscard]] auto make_remote_redaction(std::string const& room_id, std::string const& sender,
                                         std::string const& target_event_id,
                                         std::vector<std::string> const& prev_event_ids,
                                         std::vector<std::string> const& auth_event_ids, std::int64_t depth,
                                         std::int64_t ts) -> InboundPduEnvelope
{
    namespace cj = merovingian::canonicaljson;
    auto prev = cj::Array{};
    for (auto const& id : prev_event_ids)
    {
        prev.push_back(cj::Value{id});
    }
    auto auth = cj::Array{};
    for (auto const& id : auth_event_ids)
    {
        auth.push_back(cj::Value{id});
    }
    auto content = cj::Object{};
    content.push_back(cj::make_member("reason", cj::Value{std::string{"spam"}}));
    auto object = cj::Object{};
    object.push_back(cj::make_member("type", cj::Value{std::string{"m.room.redaction"}}));
    object.push_back(cj::make_member("room_id", cj::Value{room_id}));
    object.push_back(cj::make_member("sender", cj::Value{sender}));
    object.push_back(cj::make_member("redacts", cj::Value{target_event_id}));
    object.push_back(cj::make_member("content", cj::Value{std::move(content)}));
    object.push_back(cj::make_member("origin_server_ts", cj::Value{ts}));
    object.push_back(cj::make_member("depth", cj::Value{depth}));
    object.push_back(cj::make_member("prev_events", cj::Value{std::move(prev)}));
    object.push_back(cj::make_member("auth_events", cj::Value{std::move(auth)}));
    auto const serialized = cj::serialize_canonical(cj::Value{std::move(object)});
    REQUIRE(serialized.error == cj::CanonicalJsonError::none);
    auto const signed_json = merovingian::federation::test::make_signed_event_json(
        serialized.output, remote_server, remote_key_id, remote_key_seed, room_version);
    auto envelope = merovingian::federation::parse_inbound_pdu_envelope(signed_json, room_version);
    REQUIRE(envelope.has_value());
    envelope->origin = remote_server;
    return *envelope;
}

[[nodiscard]] auto make_remote_message(std::string const& room_id, std::vector<std::string> const& prev_event_ids,
                                       std::vector<std::string> const& auth_event_ids, std::int64_t depth,
                                       std::int64_t ts) -> InboundPduEnvelope
{
    auto const signed_json = make_remote_message_json(room_id, prev_event_ids, auth_event_ids, depth, ts);
    auto envelope = merovingian::federation::parse_inbound_pdu_envelope(signed_json, room_version);
    REQUIRE(envelope.has_value());
    envelope->origin = remote_server;
    return *envelope;
}

// Stores a message from the LOCAL admin as already-accepted history. The local server's own events are
// signed with its runtime key, which this fixture does not need: the event is a redaction target only.
auto seed_admin_message(HomeserverRuntime& runtime, std::string const& room_id, std::string const& event_id) -> void
{
    namespace cj = merovingian::canonicaljson;
    auto content = cj::Object{};
    content.push_back(cj::make_member("msgtype", cj::Value{std::string{"m.text"}}));
    content.push_back(cj::make_member("body", cj::Value{std::string{"admin secret"}}));
    auto hashes = cj::Object{};
    hashes.push_back(cj::make_member("sha256", cj::Value{std::string{"hash"}}));
    auto object = cj::Object{};
    object.push_back(cj::make_member("auth_events", cj::Value{cj::Array{}}));
    object.push_back(cj::make_member("content", cj::Value{std::move(content)}));
    object.push_back(cj::make_member("depth", cj::Value{std::int64_t{4}}));
    object.push_back(cj::make_member("event_id", cj::Value{event_id}));
    object.push_back(cj::make_member("hashes", cj::Value{std::move(hashes)}));
    object.push_back(cj::make_member("origin_server_ts", cj::Value{std::int64_t{5}}));
    object.push_back(cj::make_member("prev_events", cj::Value{cj::Array{}}));
    object.push_back(cj::make_member("room_id", cj::Value{room_id}));
    object.push_back(cj::make_member("sender", cj::Value{std::string{local_admin}}));
    object.push_back(cj::make_member("type", cj::Value{std::string{"m.room.message"}}));
    auto const serialized = cj::serialize_canonical(cj::Value{std::move(object)});
    REQUIRE(serialized.error == cj::CanonicalJsonError::none);

    auto& store = runtime.database.persistent_store;
    auto const member_id = room_id + ":member";
    auto event = merovingian::database::PersistentEvent{};
    event.event_id = event_id;
    event.room_id = room_id;
    event.sender_user_id = local_admin;
    event.json = serialized.output;
    event.depth = 4U;
    event.stream_ordering = 5U;
    event.prev_event_ids = {member_id};
    event.auth_event_ids = {room_id + ":create", room_id + ":pl", member_id};
    REQUIRE(merovingian::database::store_event_with_state(store, event, std::nullopt));

    auto const* policy = merovingian::rooms::find_room_version_policy(room_version);
    REQUIRE(policy != nullptr);
    auto const before = merovingian::homeserver::compute_state_before(store, room_id, *policy, {member_id});
    REQUIRE(before.ok);
    auto const after = merovingian::homeserver::compute_state_after(before.state, event_id, "m.room.message",
                                                                    std::optional<std::string>{});
    REQUIRE(
        merovingian::homeserver::record_event_state(store, room_id, event_id, {member_id}, after, true).has_value());
}

struct Fixture final
{
    std::filesystem::path path{unique_sqlite_path("merovingian-redaction-federation-")};
    merovingian::homeserver::RuntimeStartResult started{};
    std::string room_id{"!redact:local.example.org"};
    std::string create_id{};
    std::string pl_id{};
    std::string member_id{};
    std::string member_bob_id{};

    Fixture()
    {
        std::filesystem::remove(path);
        started = merovingian::homeserver::start_runtime(config_with_sqlite(path));
        REQUIRE(started.started);
        merovingian::homeserver::wire_federation_callbacks(started.runtime);
        started.runtime.federation.remote_key_resolver = genuine_key_resolver();
        seed_room_with_genesis_state_group(started.runtime, room_id);
        create_id = room_id + ":create";
        pl_id = room_id + ":pl";
        member_id = room_id + ":member";
        member_bob_id = room_id + ":member:bob";
    }

    Fixture(Fixture const&) = delete;
    auto operator=(Fixture const&) -> Fixture& = delete;
    Fixture(Fixture&&) = delete;
    auto operator=(Fixture&&) -> Fixture& = delete;

    ~Fixture()
    {
        std::filesystem::remove(path);
    }

    [[nodiscard]] auto auth_events() const -> std::vector<std::string>
    {
        return {create_id, pl_id, member_bob_id};
    }

    [[nodiscard]] auto runtime() -> HomeserverRuntime&
    {
        return started.runtime;
    }

    // Whether the local admin's clients may be sent this event (the read gate every /sync, /messages and
    // /context goes through).
    [[nodiscard]] auto admin_can_see(std::string const& event_id) -> bool
    {
        auto const* event = find_stored(runtime(), event_id);
        REQUIRE(event != nullptr);
        auto visibility = merovingian::sync::HistoryVisibility{runtime().database.persistent_store, local_admin};
        return visibility.can_see(*event);
    }

    // The client-facing form of a stored event, as every client read path builds it.
    [[nodiscard]] auto client_form(std::string const& event_id) -> merovingian::canonicaljson::Object
    {
        auto const* event = find_stored(runtime(), event_id);
        REQUIRE(event != nullptr);
        auto const value = merovingian::homeserver::client_event_with_id(runtime().database.persistent_store, *event);
        auto const* object = std::get_if<merovingian::canonicaljson::Object>(&value.storage());
        REQUIRE(object != nullptr);
        return *object;
    }

    [[nodiscard]] auto body_of(std::string const& event_id) -> std::optional<std::string>
    {
        auto const* event = find_stored(runtime(), event_id);
        REQUIRE(event != nullptr);
        auto const stored = parse_stored(event->json);
        auto const* content = object_object(stored, "content");
        return content == nullptr ? std::nullopt : object_string(*content, "body");
    }
};

} // namespace

// "The domain of the redaction event's `sender` matches that of the original event's `sender`."
SCENARIO("A federated redaction by the original sender's server is applied",
         "[csaz-11][redaction][conformance][federation]")
{
    GIVEN("a remote user's message in a room v10")
    {
        auto fixture = Fixture{};
        auto const message = make_remote_message(fixture.room_id, {fixture.member_id}, fixture.auth_events(), 4, 10);
        REQUIRE(merovingian::homeserver::ingest_pdu_event(fixture.runtime(), message).status ==
                PduIngestionStatus::accepted);
        REQUIRE(fixture.body_of(message.event_id).has_value());

        WHEN("the same remote user's server sends a redaction of it")
        {
            auto const redaction = make_remote_redaction(fixture.room_id, remote_member, message.event_id,
                                                         {message.event_id}, fixture.auth_events(), 5, 11);
            auto const result = merovingian::homeserver::ingest_pdu_event(fixture.runtime(), redaction);

            THEN("the redaction is accepted and the message is redacted")
            {
                REQUIRE(result.status == PduIngestionStatus::accepted);
                // Spec: rule 2 (matching domains) applies the redaction.
                REQUIRE(!fixture.body_of(message.event_id).has_value());
            }

            THEN("clients are served the redacted form with unsigned.redacted_because, and the redaction event")
            {
                auto const form = fixture.client_form(message.event_id);
                auto const* unsigned_data = object_object(form, "unsigned");
                REQUIRE(unsigned_data != nullptr);
                auto const* because = object_object(*unsigned_data, "redacted_because");
                REQUIRE(because != nullptr);
                REQUIRE(object_string(*because, "event_id") == std::optional<std::string>{redaction.event_id});
                // Spec: "If the server would apply a redaction, the redaction event is also sent to clients."
                REQUIRE(fixture.admin_can_see(redaction.event_id));
            }

            THEN("the redacted event's hashes and signatures are kept, so it still verifies over federation")
            {
                auto const* stored = find_stored(fixture.runtime(), message.event_id);
                REQUIRE(stored != nullptr);
                auto const object = parse_stored(stored->json);
                REQUIRE(object_object(object, "hashes") != nullptr);
                REQUIRE(object_object(object, "signatures") != nullptr);
            }
        }
    }
}

// Neither condition holds: the sender's level is below the redact level and the domains differ.
SCENARIO("A federated redaction without power over an event from another server is not applied",
         "[csaz-11][redaction][conformance][federation]")
{
    GIVEN("a message from the local admin, in a room where the remote user has level 0 and redact is 50")
    {
        auto fixture = Fixture{};
        auto const admin_message = fixture.room_id + ":admin-message";
        seed_admin_message(fixture.runtime(), fixture.room_id, admin_message);

        WHEN("the remote user's server sends a redaction of the admin's message")
        {
            auto const redaction = make_remote_redaction(fixture.room_id, remote_member, admin_message, {admin_message},
                                                         fixture.auth_events(), 5, 11);
            auto const result = merovingian::homeserver::ingest_pdu_event(fixture.runtime(), redaction);

            THEN("the message is unchanged")
            {
                // Spec: neither condition holds, so "the server simply waits for a valid partner event".
                REQUIRE(result.status == PduIngestionStatus::accepted);
                REQUIRE(fixture.body_of(admin_message) == std::optional<std::string>{"admin secret"});
                auto const form = fixture.client_form(admin_message);
                auto const* unsigned_data = object_object(form, "unsigned");
                REQUIRE((unsigned_data == nullptr || object_object(*unsigned_data, "redacted_because") == nullptr));
            }

            THEN("the redaction event is not sent to clients")
            {
                // Spec: only "if the server would apply a redaction" is the redaction event sent to clients.
                REQUIRE(!fixture.admin_can_see(redaction.event_id));
            }
        }
    }
}

// "...they should not be sent to clients until both the redaction event and the event the redaction
// affects have been received" and "the server simply waits for a valid partner event to arrive where
// it can then re-check the above."
SCENARIO("A federated redaction that arrives before its target is applied when the target arrives",
         "[csaz-11][redaction][conformance][federation]")
{
    GIVEN("a redaction of a message the server has not received yet")
    {
        auto fixture = Fixture{};
        auto const message = make_remote_message(fixture.room_id, {fixture.member_id}, fixture.auth_events(), 4, 10);
        auto const redaction = make_remote_redaction(fixture.room_id, remote_member, message.event_id,
                                                     {fixture.member_id}, fixture.auth_events(), 5, 11);
        REQUIRE(merovingian::homeserver::ingest_pdu_event(fixture.runtime(), redaction).status ==
                PduIngestionStatus::accepted);

        THEN("the redaction event is held back from clients until its target is known")
        {
            REQUIRE(!fixture.admin_can_see(redaction.event_id));
        }

        WHEN("the target message arrives")
        {
            REQUIRE(merovingian::homeserver::ingest_pdu_event(fixture.runtime(), message).status ==
                    PduIngestionStatus::accepted);

            THEN("the message is stored redacted and the redaction event is now sent to clients")
            {
                REQUIRE(!fixture.body_of(message.event_id).has_value());
                auto const form = fixture.client_form(message.event_id);
                auto const* unsigned_data = object_object(form, "unsigned");
                REQUIRE(unsigned_data != nullptr);
                REQUIRE(object_object(*unsigned_data, "redacted_because") != nullptr);
                REQUIRE(fixture.admin_can_see(redaction.event_id));
            }
        }
    }
}
