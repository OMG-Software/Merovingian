// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Sticky events (MSC4354, ADR-0856) over federation. Inbound: a PDU the main process accepted as a timeline event gets
// a `sticky_events` row whose received time is this process's clock; a rejected, soft-failed, expired or malformed one
// does not. Outbound: a server that newly joins a room is sent this server's own unexpired sticky events, and only
// those. No scenario sleeps: time is `PersistentStore::test_sticky_clock_ms` and `test_frozen_event_clock_ms`. The
// feature is not in the Matrix v1.19 specification, so there is no conformance scenario.

#include "../support/InMemoryDatabaseConfig.hpp"
#include "../support/JsonTestSupport.hpp"
#include "../support/MasterKey.hpp"
#include "../support/MembershipFixtureSupport.hpp"
#include "../support/RegistrationToken.hpp"
#include "merovingian/canonicaljson/CanonicalJsonError.hpp"
#include "merovingian/canonicaljson/Parser.hpp"
#include "merovingian/canonicaljson/Serializer.hpp"
#include "merovingian/canonicaljson/Value.hpp"
#include "merovingian/config/ClientRateLimitsConfig.hpp"
#include "merovingian/config/Config.hpp"
#include "merovingian/config/ListenersConfig.hpp"
#include "merovingian/config/LogModulesConfig.hpp"
#include "merovingian/config/SecurityConfig.hpp"
#include "merovingian/config/ServerConfig.hpp"
#include "merovingian/database/PersistentStickyEvent.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/database/StickyEventStore.hpp"
#include "merovingian/database/StickyEventTable.hpp"
#include "merovingian/events/EventId.hpp"
#include "merovingian/events/StickyEvent.hpp"
#include "merovingian/federation/DispatchWorker.hpp"
#include "merovingian/federation/DispatchWorkerConfig.hpp"
#include "merovingian/federation/FederationEndpoint.hpp"
#include "merovingian/federation/InboundPduEnvelope.hpp"
#include "merovingian/federation/MembershipAcceptResult.hpp"
#include "merovingian/federation/PduIngestionStatus.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"
#include "merovingian/homeserver/LocalHttpResponse.hpp"
#include "merovingian/homeserver/LocalHttpRouter.hpp"
#include "merovingian/homeserver/StickyEventPush.hpp"

#include <catch2/catch_test_macros.hpp>
#include <sodium.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace
{

namespace hs = merovingian::homeserver;
namespace cj = merovingian::canonicaljson;
namespace db = merovingian::database;
namespace fed = merovingian::federation;
using namespace merovingian::tests;

constexpr auto t0 = std::int64_t{1'700'000'000'000};
constexpr auto password = std::string_view{"CorrectHorse7!"};
constexpr auto server_c = std::string_view{"c.example.org"};
constexpr auto server_d = std::string_view{"d.example.org"};
constexpr auto carol = std::string_view{"@carol:c.example.org"};
constexpr auto dave = std::string_view{"@dave:d.example.org"};
constexpr auto erin = std::string_view{"@erin:d.example.org"};
constexpr auto one_minute = std::int64_t{60'000};
constexpr auto one_hour = std::int64_t{3'600'000};

[[nodiscard]] auto memory_config() -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    security.secrets.master_key_file = shared_master_key_file();
    enable_token_registration(security);
    return {
        merovingian::config::ServerConfig{},
        merovingian::config::ListenersConfig{},
        in_memory_database_config(),
        std::move(security),
        merovingian::config::ClientRateLimitsConfig{},
        merovingian::config::LogModulesConfig{},
    };
}

[[nodiscard]] auto request(hs::ClientServerRuntime& runtime, std::string method, std::string target,
                           std::string const& token = {}, std::string body = {}) -> hs::LocalHttpResponse
{
    return hs::handle_client_server_request(runtime, {std::move(method), std::move(target), token, std::move(body)})
        .response;
}

[[nodiscard]] auto canonical_form(std::string const& json) -> std::string
{
    auto const parsed = cj::parse_lossless(json);
    REQUIRE(parsed.error == cj::ParseError::none);
    auto const serialized = cj::serialize_canonical(parsed.value);
    REQUIRE(serialized.error == cj::CanonicalJsonError::none);
    return serialized.output;
}

[[nodiscard]] auto quoted_list(std::vector<std::string> const& ids) -> std::string
{
    auto out = std::string{"["};
    for (auto const& id : ids)
    {
        out += (out.size() == 1U ? "" : ",") + std::string{"\""} + id + "\"";
    }
    return out + "]";
}

// What a remote server sends: the fields a test varies.
struct RemotePdu final
{
    std::string sender{};
    std::string event_id{};
    std::int64_t origin_server_ts{t0};
    std::optional<std::int64_t> stable{};
    std::optional<std::int64_t> unstable{};
    std::string type{"m.test.sticky"};
    std::optional<std::string> redacts{};
};

// alice's public room on this server (room version 12), with an unstarted dispatch worker so every transaction stays in
// the durable queue for the test to read, and the clocks at t0.
class Fixture final
{
public:
    Fixture()
        : m_started{hs::start_client_server(memory_config())}
    {
        REQUIRE(sodium_init() >= 0);
        REQUIRE(m_started.started);
        auto config = fed::DispatchWorkerConfig{};
        config.origin = homeserver().config.server().server_name;
        config.key_id = "ed25519:test";
        REQUIRE(homeserver().outbound_client != nullptr);
        homeserver().dispatch_worker = std::make_unique<fed::DispatchWorker>(
            std::move(config), *homeserver().outbound_client,
            [](std::string_view) {
                return std::optional<fed::ServerDiscoveryResult>{};
            },
            fed::DispatchClock{}, fed::DispatchSleep{}, &homeserver().database.persistent_store);
        hs::wire_federation_callbacks(homeserver());
        REQUIRE(request(runtime(), "POST", "/_matrix/client/v3/register", {}, registration_json("alice", password))
                    .status == 200U);
        auto const login =
            request(runtime(), "POST", "/_matrix/client/v3/login", {},
                    R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},)"
                    R"("password":")" +
                        std::string{password} + R"(","device_id":"D1"})");
        REQUIRE(login.status == 200U);
        m_alice_token = *string_member(parse_object(login.body), "access_token");
        auto const created =
            request(runtime(), "POST", "/_matrix/client/v3/createRoom", m_alice_token, R"({"preset":"public_chat"})");
        REQUIRE(created.status == 200U);
        m_room_id = *string_member(parse_object(created.body), "room_id");
        set_time(t0);
    }

    [[nodiscard]] auto runtime() noexcept -> hs::ClientServerRuntime&
    {
        return m_started.runtime;
    }

    [[nodiscard]] auto homeserver() noexcept -> hs::HomeserverRuntime&
    {
        return m_started.runtime.homeserver;
    }

    [[nodiscard]] auto store() noexcept -> db::PersistentStore&
    {
        return homeserver().database.persistent_store;
    }

    auto set_time(std::int64_t now_ms) -> void
    {
        runtime().homeserver.test_frozen_event_clock_ms = now_ms;
        store().test_sticky_clock_ms = now_ms;
    }

    // alice sends a sticky m.test.sticky message of `duration_ms`; the event ID.
    [[nodiscard]] auto alice_sends_sticky(std::string const& txn, std::int64_t duration_ms) -> std::string
    {
        auto const response = request(runtime(), "PUT",
                                      "/_matrix/client/v3/rooms/" + m_room_id + "/send/m.test.sticky/" + txn +
                                          "?sticky_duration_ms=" + std::to_string(duration_ms),
                                      m_alice_token, R"({"body":"hello"})");
        REQUIRE(response.status == 200U);
        return *string_member(parse_object(response.body), "event_id");
    }

    [[nodiscard]] auto alice_sends_plain(std::string const& txn) -> std::string
    {
        auto const response =
            request(runtime(), "PUT", "/_matrix/client/v3/rooms/" + m_room_id + "/send/m.test.sticky/" + txn,
                    m_alice_token, R"({"body":"plain"})");
        REQUIRE(response.status == 200U);
        return *string_member(parse_object(response.body), "event_id");
    }

    // A membership PDU as a conformant peer would file it.
    [[nodiscard]] auto membership_envelope(std::string_view user_id, std::string_view membership,
                                           std::string const& event_id, std::uint64_t depth) -> fed::InboundPduEnvelope
    {
        auto envelope = fed::InboundPduEnvelope{};
        envelope.event_id = event_id;
        envelope.room_id = m_room_id;
        envelope.sender = std::string{user_id};
        envelope.event_type = "m.room.member";
        envelope.state_key = std::string{user_id};
        envelope.depth = depth;
        envelope.origin = std::string{user_id.substr(user_id.find(':') + 1U)};
        envelope.prev_event_ids = fixture_prev_event_ids(store(), m_room_id);
        envelope.auth_event_ids = fixture_auth_event_ids(store(), m_room_id, user_id, true);
        if (membership == "leave")
        {
            for (auto const& entry : store().state)
            {
                if (entry.room_id == m_room_id && entry.event_type == "m.room.join_rules")
                {
                    std::erase(envelope.auth_event_ids, entry.event_id);
                }
            }
        }
        envelope.json = "{\"auth_events\":" + quoted_list(envelope.auth_event_ids) + ",\"content\":{\"membership\":\"" +
                        std::string{membership} + "\"},\"depth\":" + std::to_string(depth) +
                        ",\"origin_server_ts\":1,\"prev_events\":" + quoted_list(envelope.prev_event_ids) +
                        ",\"room_id\":\"" + m_room_id + "\",\"sender\":\"" + std::string{user_id} +
                        "\",\"state_key\":\"" + std::string{user_id} + "\",\"type\":\"m.room.member\"}";
        return envelope;
    }

    // The remote user joins through send_join, as the resident accepts it.
    auto join(std::string_view user_id, std::string const& event_id) -> void
    {
        auto const result =
            homeserver().federation.membership_acceptor(fed::FederationEndpoint::send_join, m_room_id, event_id,
                                                        membership_envelope(user_id, "join", event_id, 10U));
        REQUIRE(result.accepted);
    }

    // `pdu` as its server would send it: hashed, naming the room's tips and the sender's auth events.
    [[nodiscard]] auto envelope_of(RemotePdu const& pdu, std::uint64_t depth = 50U) -> fed::InboundPduEnvelope
    {
        auto envelope = fed::InboundPduEnvelope{};
        envelope.event_id = pdu.event_id;
        envelope.room_id = m_room_id;
        envelope.sender = pdu.sender;
        envelope.event_type = pdu.type;
        envelope.depth = depth;
        envelope.origin = pdu.sender.substr(pdu.sender.find(':') + 1U);
        envelope.prev_event_ids = fixture_prev_event_ids(store(), m_room_id);
        envelope.auth_event_ids = fixture_auth_event_ids(store(), m_room_id, pdu.sender, true);
        // Spec, "Auth events selection": the join rules are named only by a join, invite or knock.
        for (auto const& entry : store().state)
        {
            if (entry.room_id == m_room_id && entry.event_type == "m.room.join_rules")
            {
                std::erase(envelope.auth_event_ids, entry.event_id);
            }
        }
        auto content = cj::Object{};
        if (pdu.redacts.has_value())
        {
            content.push_back(cj::make_member("redacts", cj::Value{*pdu.redacts}));
        }
        else
        {
            content.push_back(cj::make_member("body", cj::Value{std::string{"hi"}}));
        }
        auto object = cj::Object{};
        object.push_back(cj::make_member("type", cj::Value{pdu.type}));
        object.push_back(cj::make_member("room_id", cj::Value{m_room_id}));
        object.push_back(cj::make_member("sender", cj::Value{pdu.sender}));
        object.push_back(cj::make_member("content", cj::Value{std::move(content)}));
        object.push_back(cj::make_member("origin_server_ts", cj::Value{pdu.origin_server_ts}));
        object.push_back(cj::make_member("depth", cj::Value{static_cast<std::int64_t>(depth)}));
        auto prev = cj::Array{};
        for (auto const& id : envelope.prev_event_ids)
        {
            prev.push_back(cj::Value{id});
        }
        object.push_back(cj::make_member("prev_events", cj::Value{std::move(prev)}));
        auto auth = cj::Array{};
        for (auto const& id : envelope.auth_event_ids)
        {
            auth.push_back(cj::Value{id});
        }
        object.push_back(cj::make_member("auth_events", cj::Value{std::move(auth)}));
        if (pdu.stable.has_value())
        {
            object.push_back(cj::make_member(std::string{merovingian::events::sticky_field},
                                             merovingian::events::sticky_object(*pdu.stable)));
        }
        if (pdu.unstable.has_value())
        {
            object.push_back(cj::make_member(std::string{merovingian::events::unstable_sticky_field},
                                             merovingian::events::sticky_object(*pdu.unstable)));
        }
        auto const hash = merovingian::events::make_content_hash(cj::Value{object});
        REQUIRE(hash.error.empty());
        auto hashes = cj::Object{};
        hashes.push_back(cj::make_member("sha256", cj::Value{hash.sha256}));
        object.push_back(cj::make_member("hashes", cj::Value{std::move(hashes)}));
        auto const serialized = cj::serialize_canonical(cj::Value{std::move(object)});
        REQUIRE(serialized.error == cj::CanonicalJsonError::none);
        envelope.json = serialized.output;
        return envelope;
    }

    [[nodiscard]] auto ingest(fed::InboundPduEnvelope const& envelope) -> fed::PduIngestionResult
    {
        return hs::ingest_pdu_event(homeserver(), envelope);
    }

    // Every PDU queued in a transaction for `server`, as canonical JSON.
    [[nodiscard]] auto queued_pdus_for(std::string_view server) -> std::vector<std::string>
    {
        auto queued = std::vector<std::string>{};
        auto const lock = std::lock_guard{homeserver().mutex};
        for (auto const& transaction : store().federation_transactions)
        {
            if (transaction.server_name != server)
            {
                continue;
            }
            auto const parsed = cj::parse_lossless(transaction.body);
            auto const* root = std::get_if<cj::Object>(&parsed.value.storage());
            auto const* pdus = root == nullptr ? nullptr : object_member_as_array(*root, "pdus");
            if (pdus == nullptr)
            {
                continue;
            }
            for (auto const& pdu : *pdus)
            {
                auto const serialized = cj::serialize_canonical(pdu);
                REQUIRE(serialized.error == cj::CanonicalJsonError::none);
                queued.push_back(serialized.output);
            }
        }
        return queued;
    }

    // The canonical form of the stored PDU of `event_id`.
    [[nodiscard]] auto stored_form(std::string const& event_id) -> std::string
    {
        auto const found = store().events.find(event_id);
        REQUIRE(found != store().events.end());
        return canonical_form(found->json);
    }

    [[nodiscard]] auto row(std::string const& event_id) -> db::PersistentStickyEvent const*
    {
        return store().sticky_events.find(event_id, t0 - 10 * one_hour);
    }

    [[nodiscard]] auto alice_token() const noexcept -> std::string const&
    {
        return m_alice_token;
    }

    [[nodiscard]] auto room_id() const noexcept -> std::string const&
    {
        return m_room_id;
    }

    // Pushes this server's sticky events in the room to `destination`, as a join of a new server does, under
    // `runtime.mutex`; how many were queued.
    [[nodiscard]] auto push_to(std::string_view destination) -> std::size_t
    {
        auto const lock = std::lock_guard{homeserver().mutex};
        return hs::push_local_sticky_events_to_server(homeserver(), m_room_id, destination);
    }

private:
    std::string m_alice_token{};
    std::string m_room_id{};

    hs::ClientServerStartResult m_started;
};

[[nodiscard]] auto count_of(std::vector<std::string> const& haystack, std::string const& needle) -> std::ptrdiff_t
{
    return std::ranges::count(haystack, needle);
}

} // namespace

SCENARIO("A sticky PDU a remote server sent and this server accepted is recorded with this server's clock",
         "[sticky-events][federation][integration][inbound]")
{
    GIVEN("a room with a remote user from server C joined to it")
    {
        auto fixture = Fixture{};
        fixture.join(carol, "$carol_join:c.example.org");

        WHEN("carol sends a PDU carrying equal stable and unstable sticky fields")
        {
            auto const result = fixture.ingest(
                fixture.envelope_of({std::string{carol}, "$equal:c.example.org", t0, one_minute, one_minute}));
            REQUIRE(result.status == fed::PduIngestionStatus::accepted);

            THEN("a row is kept: received now, expiring a duration later")
            {
                auto const* row = fixture.row("$equal:c.example.org");
                REQUIRE(row != nullptr);
                REQUIRE(row->sender == carol);
                REQUIRE(row->room_id == fixture.room_id());
                REQUIRE(row->received_at_ms == t0);
                REQUIRE(row->expires_at_ms == t0 + one_minute);
            }
        }

        WHEN("carol sends a PDU stamped ten minutes in the future with a one-hour duration")
        {
            auto const result = fixture.ingest(fixture.envelope_of(
                {std::string{carol}, "$future:c.example.org", t0 + 10 * one_minute, one_hour, one_hour}));
            REQUIRE(result.status == fed::PduIngestionStatus::accepted);

            THEN("the received time caps the expiry, so the sender cannot extend its stay")
            {
                auto const* row = fixture.row("$future:c.example.org");
                REQUIRE(row != nullptr);
                REQUIRE(row->received_at_ms == t0);
                REQUIRE(row->expires_at_ms == t0 + one_hour);
            }
        }

        WHEN("carol sends one PDU with the stable field only and one with the unstable field only")
        {
            REQUIRE(
                fixture.ingest(fixture.envelope_of({std::string{carol}, "$stable:c.example.org", t0, one_minute, {}}))
                    .status == fed::PduIngestionStatus::accepted);
            REQUIRE(
                fixture.ingest(fixture.envelope_of({std::string{carol}, "$unstable:c.example.org", t0, {}, one_minute}))
                    .status == fed::PduIngestionStatus::accepted);

            THEN("each is sticky")
            {
                REQUIRE(fixture.row("$stable:c.example.org") != nullptr);
                REQUIRE(fixture.row("$unstable:c.example.org") != nullptr);
            }
        }
    }
}

SCENARIO("An accepted remote PDU that is not sticky, or arrives expired, twice or while disabled, gets no new row",
         "[sticky-events][federation][integration][inbound]")
{
    GIVEN("a room with a remote user from server C joined to it")
    {
        auto fixture = Fixture{};
        fixture.join(carol, "$carol_join:c.example.org");

        WHEN("carol sends a PDU whose two sticky fields disagree")
        {
            auto const result = fixture.ingest(
                fixture.envelope_of({std::string{carol}, "$unequal:c.example.org", t0, one_minute, 2 * one_minute}));

            THEN("it is accepted as an ordinary event and gets no row")
            {
                REQUIRE(result.status == fed::PduIngestionStatus::accepted);
                REQUIRE(fixture.store().events.find("$unequal:c.example.org") != fixture.store().events.end());
                REQUIRE(fixture.row("$unequal:c.example.org") == nullptr);
            }
        }

        WHEN("carol sends a sticky PDU that expired before it arrived")
        {
            auto const result = fixture.ingest(fixture.envelope_of(
                {std::string{carol}, "$old:c.example.org", t0 - 2 * one_hour, one_minute, one_minute}));

            THEN("it is accepted and gets no row")
            {
                REQUIRE(result.status == fed::PduIngestionStatus::accepted);
                REQUIRE(fixture.row("$old:c.example.org") == nullptr);
            }
        }

        WHEN("the same sticky PDU is sent twice")
        {
            auto const envelope =
                fixture.envelope_of({std::string{carol}, "$twice:c.example.org", t0, one_minute, one_minute});
            REQUIRE(fixture.ingest(envelope).status == fed::PduIngestionStatus::accepted);
            auto const before = fixture.store().sticky_events.size();
            REQUIRE(fixture.ingest(envelope).status == fed::PduIngestionStatus::already_stored);

            THEN("the second changes nothing")
            {
                REQUIRE(fixture.store().sticky_events.size() == before);
            }
        }

        WHEN("sticky events are disabled")
        {
            fixture.homeserver().config.server().sticky_events.enabled = false;
            auto const result = fixture.ingest(
                fixture.envelope_of({std::string{carol}, "$disabled:c.example.org", t0, one_minute, one_minute}));

            THEN("the PDU is accepted and no row is kept")
            {
                REQUIRE(result.status == fed::PduIngestionStatus::accepted);
                REQUIRE(fixture.row("$disabled:c.example.org") == nullptr);
            }
        }
    }
}

SCENARIO("A rejected or soft-failed sticky PDU gets no row", "[sticky-events][federation][integration][inbound]")
{
    GIVEN("a room with carol joined, and dave of server D who never joined")
    {
        auto fixture = Fixture{};
        fixture.join(carol, "$carol_join:c.example.org");

        WHEN("dave, who is not in the room, sends a sticky PDU")
        {
            auto const result = fixture.ingest(
                fixture.envelope_of({std::string{dave}, "$stranger:d.example.org", t0, one_minute, one_minute}));

            THEN("it is rejected and gets no row")
            {
                REQUIRE(result.status == fed::PduIngestionStatus::rejected_auth);
                REQUIRE(fixture.row("$stranger:d.example.org") == nullptr);
            }
        }

        WHEN("carol sends a sticky PDU that her server wrote before she left, and it arrives after her leave")
        {
            auto const late =
                fixture.envelope_of({std::string{carol}, "$late:c.example.org", t0, one_minute, one_minute}, 40U);
            REQUIRE(
                fixture.ingest(fixture.membership_envelope(carol, "leave", "$carol_leave:c.example.org", 41U)).status ==
                fed::PduIngestionStatus::accepted);
            auto const result = fixture.ingest(late);

            THEN("it is soft-failed and gets no row")
            {
                REQUIRE(result.status == fed::PduIngestionStatus::soft_failed);
                REQUIRE(fixture.row("$late:c.example.org") == nullptr);
            }
        }
    }
}

SCENARIO("The per-sender cap applies to a remote sender, and a remote redaction removes the row",
         "[sticky-events][federation][integration][inbound]")
{
    GIVEN("a room with carol joined")
    {
        auto fixture = Fixture{};
        fixture.join(carol, "$carol_join:c.example.org");

        WHEN("the cap is two and carol sends three sticky PDUs")
        {
            fixture.homeserver().config.server().sticky_events.max_per_sender = 2U;
            for (auto const* id : {"$one:c.example.org", "$two:c.example.org", "$three:c.example.org"})
            {
                REQUIRE(fixture.ingest(fixture.envelope_of({std::string{carol}, id, t0, one_hour, one_hour})).status ==
                        fed::PduIngestionStatus::accepted);
            }

            THEN("she holds two unexpired rows and the newest is one of them")
            {
                REQUIRE(fixture.store().sticky_events.unexpired_count_of_sender(carol, t0) == 2U);
                REQUIRE(fixture.row("$three:c.example.org") != nullptr);
            }
        }

        WHEN("carol redacts her own sticky PDU")
        {
            REQUIRE(
                fixture
                    .ingest(fixture.envelope_of({std::string{carol}, "$target:c.example.org", t0, one_hour, one_hour}))
                    .status == fed::PduIngestionStatus::accepted);
            REQUIRE(fixture.row("$target:c.example.org") != nullptr);
            auto redaction = RemotePdu{std::string{carol}, "$redaction:c.example.org"};
            redaction.type = "m.room.redaction";
            redaction.redacts = "$target:c.example.org";
            auto const result = fixture.ingest(fixture.envelope_of(redaction, 60U));
            REQUIRE(result.status == fed::PduIngestionStatus::accepted);

            THEN("the row is gone")
            {
                REQUIRE(fixture.store().sticky_events.contains("$target:c.example.org") == false);
            }
        }
    }
}

SCENARIO("A server that joins a room is sent this server's own unexpired sticky events, and no others",
         "[sticky-events][federation][integration][outbound]")
{
    GIVEN("alice's room with carol joined, three of alice's sticky events, one of them expired, one plain message and "
          "one sticky event of carol's")
    {
        auto fixture = Fixture{};
        fixture.join(carol, "$carol_join:c.example.org");
        auto const short_lived = fixture.alice_sends_sticky("a", 10'000);
        auto const medium = fixture.alice_sends_sticky("b", one_minute);
        auto const long_lived = fixture.alice_sends_sticky("c", 30 * one_minute);
        auto const plain = fixture.alice_sends_plain("d");
        REQUIRE(
            fixture.ingest(fixture.envelope_of({std::string{carol}, "$carols:c.example.org", t0, one_hour, one_hour}))
                .status == fed::PduIngestionStatus::accepted);
        fixture.set_time(t0 + 20'000);
        auto const c_queue_before = fixture.queued_pdus_for(server_c);
        REQUIRE(fixture.queued_pdus_for(server_d).empty());

        WHEN("dave of server D joins")
        {
            fixture.join(dave, "$dave_join:d.example.org");

            THEN("D is queued the two unexpired events, unchanged, and nothing else")
            {
                auto const sent = fixture.queued_pdus_for(server_d);
                REQUIRE(sent.size() == 2U);
                REQUIRE(sent[0] == fixture.stored_form(medium));
                REQUIRE(sent[1] == fixture.stored_form(long_lived));
                REQUIRE(count_of(sent, fixture.stored_form(short_lived)) == 0);
                REQUIRE(count_of(sent, fixture.stored_form(plain)) == 0);
                REQUIRE(count_of(sent, fixture.stored_form("$carols:c.example.org")) == 0);
            }

            THEN("no other server is sent them again")
            {
                auto const c_after = fixture.queued_pdus_for(server_c);
                REQUIRE(count_of(c_after, fixture.stored_form(medium)) ==
                        count_of(c_queue_before, fixture.stored_form(medium)));
                REQUIRE(count_of(c_after, fixture.stored_form(long_lived)) ==
                        count_of(c_queue_before, fixture.stored_form(long_lived)));
            }

            AND_WHEN("a second user of server D joins")
            {
                auto const before = fixture.queued_pdus_for(server_d).size();
                fixture.join(erin, "$erin_join:d.example.org");

                THEN("server D, already in the room, is not sent them again")
                {
                    REQUIRE(fixture.queued_pdus_for(server_d).size() == before);
                }
            }
        }

        WHEN("sticky events are disabled and dave of server D joins")
        {
            fixture.homeserver().config.server().sticky_events.enabled = false;
            fixture.join(dave, "$dave_join:d.example.org");

            THEN("D is sent no sticky event")
            {
                REQUIRE(fixture.queued_pdus_for(server_d).empty());
            }
        }

        WHEN("every sticky event has expired and dave of server D joins")
        {
            fixture.set_time(t0 + 2 * one_hour);
            fixture.join(dave, "$dave_join:d.example.org");

            THEN("D is sent none")
            {
                REQUIRE(fixture.queued_pdus_for(server_d).empty());
            }
        }
    }
}

SCENARIO("The push to a joining server sends nothing to a server the operator or the room refuses",
         "[sticky-events][federation][integration][outbound][security]")
{
    GIVEN("alice's room with one unexpired sticky event of hers")
    {
        auto fixture = Fixture{};
        auto const sticky = fixture.alice_sends_sticky("a", one_hour);

        WHEN("the operator's federation policy denies server D")
        {
            fixture.homeserver().federation.config.denied_servers.emplace_back(server_d);
            auto const pushed = fixture.push_to(server_d);

            THEN("D is queued nothing")
            {
                REQUIRE(pushed == 0U);
                REQUIRE(fixture.queued_pdus_for(server_d).empty());
            }
        }

        WHEN("the room's server ACL denies server D")
        {
            REQUIRE(request(fixture.runtime(), "PUT",
                            "/_matrix/client/v3/rooms/" + fixture.room_id() + "/state/m.room.server_acl",
                            fixture.alice_token(), R"({"allow":["*"],"deny":["d.example.org"]})")
                        .status == 200U);
            auto const pushed = fixture.push_to(server_d);

            THEN("D is queued nothing, and an allowed server is still sent the event")
            {
                REQUIRE(pushed == 0U);
                REQUIRE(fixture.queued_pdus_for(server_d).empty());
                REQUIRE(fixture.push_to(server_c) == 1U);
                REQUIRE(fixture.queued_pdus_for(server_c).back() == fixture.stored_form(sticky));
            }
        }

        WHEN("the destination is empty, or this server itself")
        {
            auto const to_nobody = fixture.push_to("");
            auto const to_self = fixture.push_to(fixture.homeserver().config.server().server_name);

            THEN("nothing is queued")
            {
                REQUIRE(to_nobody == 0U);
                REQUIRE(to_self == 0U);
                REQUIRE(fixture.queued_pdus_for(fixture.homeserver().config.server().server_name).empty());
            }
        }

        WHEN("there is no dispatch worker")
        {
            fixture.homeserver().dispatch_worker.reset();

            THEN("nothing is queued")
            {
                REQUIRE(fixture.push_to(server_d) == 0U);
            }
        }

        WHEN("the table holds a row of alice's whose event this server does not hold")
        {
            REQUIRE(db::record_sticky_event(
                fixture.store(),
                {"$missing:example.org", fixture.room_id(), "@alice:example.org", t0, t0 + one_hour - 1}, {60U, 1000U},
                t0).recorded);
            auto const pushed = fixture.push_to(server_d);

            THEN("only the event it holds is sent")
            {
                REQUIRE(pushed == 1U);
                REQUIRE(fixture.queued_pdus_for(server_d) == std::vector<std::string>{fixture.stored_form(sticky)});
            }
        }
    }
}
