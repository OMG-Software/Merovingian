// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Sticky events (MSC4354, ADR-0853, ADR-0854): the client send path. Every request goes through
// `handle_client_server_request` on a real runtime. No scenario sleeps: time is `test_frozen_event_clock_ms` (the
// stamp), `PersistentStore::test_sticky_clock_ms` (what the readers and the prune judge expiry against) and
// `test_delayed_event_clock_ms` (the delayed events' job). The feature is not in the Matrix v1.19 specification, so
// there is no conformance scenario.

#include "../support/InMemoryDatabaseConfig.hpp"
#include "../support/JsonTestSupport.hpp"
#include "../support/MasterKey.hpp"
#include "../support/RegistrationToken.hpp"
#include "merovingian/canonicaljson/Parser.hpp"
#include "merovingian/canonicaljson/Value.hpp"
#include "merovingian/config/ClientRateLimitsConfig.hpp"
#include "merovingian/config/Config.hpp"
#include "merovingian/config/ListenersConfig.hpp"
#include "merovingian/config/LogModulesConfig.hpp"
#include "merovingian/config/SecurityConfig.hpp"
#include "merovingian/config/ServerConfig.hpp"
#include "merovingian/crypto/Ed25519PublicKey.hpp"
#include "merovingian/database/DelayedEventTable.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/database/StickyEventTable.hpp"
#include "merovingian/events/EventId.hpp"
#include "merovingian/events/EventSigner.hpp"
#include "merovingian/events/SigningKeyId.hpp"
#include "merovingian/events/StickyEvent.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"
#include "merovingian/homeserver/DelayedEvents.hpp"
#include "merovingian/homeserver/HomeserverRuntime.hpp"
#include "merovingian/homeserver/LocalHttpResponse.hpp"
#include "merovingian/homeserver/StickyEventPrune.hpp"
#include "merovingian/homeserver/StopFlag.hpp"
#include "merovingian/rooms/RoomVersionPolicy.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <variant>
#include <vector>

namespace
{

namespace hs = merovingian::homeserver;
namespace cj = merovingian::canonicaljson;
namespace db = merovingian::database;
namespace ev = merovingian::events;
using namespace merovingian::tests;

constexpr auto t0 = std::int64_t{1'700'000'000'000};
constexpr auto password = std::string_view{"CorrectHorse7!"};
constexpr auto stable_name = std::string_view{"sticky_duration_ms"};
constexpr auto unstable_name = std::string_view{"org.matrix.msc4354.sticky_duration_ms"};
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

[[nodiscard]] auto errcode_of(hs::LocalHttpResponse const& response) -> std::string
{
    auto const body = parse_object(response.body);
    auto const* code = string_member(body, "errcode");
    return code == nullptr ? std::string{} : *code;
}

// A running homeserver with alice and bob in one public room. Alice created it. All three clocks start at t0.
class Fixture final
{
public:
    Fixture()
        : m_started{hs::start_client_server(memory_config())}
    {
        REQUIRE(m_started.started);
        m_alice_token = sign_in("alice", "D1");
        m_bob_token = sign_in("bob", "D2");
        auto const created =
            request(runtime(), "POST", "/_matrix/client/v3/createRoom", m_alice_token, R"({"preset":"public_chat"})");
        REQUIRE(created.status == 200U);
        m_room_id = *string_member(parse_object(created.body), "room_id");
        REQUIRE(request(runtime(), "POST", "/_matrix/client/v3/join/" + m_room_id, m_bob_token, "{}").status == 200U);
        set_time(t0);
    }

    [[nodiscard]] auto runtime() noexcept -> hs::ClientServerRuntime&
    {
        return m_started.runtime;
    }

    [[nodiscard]] auto store() noexcept -> db::PersistentStore&
    {
        return m_started.runtime.homeserver.database.persistent_store;
    }

    [[nodiscard]] auto room_path() const -> std::string
    {
        return "/_matrix/client/v3/rooms/" + m_room_id;
    }

    auto set_time(std::int64_t now_ms) -> void
    {
        runtime().homeserver.test_delayed_event_clock_ms = static_cast<std::uint64_t>(now_ms);
        runtime().homeserver.test_frozen_event_clock_ms = now_ms;
        store().test_sticky_clock_ms = now_ms;
    }

    // PUT .../send/m.test.sticky/{txn}?{query}; alice's token.
    [[nodiscard]] auto put_send(std::string_view txn, std::string_view query, std::string body = R"({"body":"hello"})")
        -> hs::LocalHttpResponse
    {
        return request(runtime(), "PUT",
                       room_path() + "/send/m.test.sticky/" + std::string{txn} +
                           (query.empty() ? "" : "?" + std::string{query}),
                       m_alice_token, std::move(body));
    }

    [[nodiscard]] auto event_count() noexcept -> std::size_t
    {
        return store().events.size();
    }

    // The stored PDU of `event_id`, parsed.
    [[nodiscard]] auto stored(std::string const& event_id) -> cj::Object
    {
        auto const found = store().events.find(event_id);
        REQUIRE(found != store().events.end());
        return parse_object(found->json);
    }

    // GET .../event/{eventId} as alice, or as the holder of `token` when given, parsed.
    [[nodiscard]] auto served(std::string const& event_id, std::string const& token = {}) -> cj::Object
    {
        auto const response =
            request(runtime(), "GET", room_path() + "/event/" + event_id, token.empty() ? m_alice_token : token);
        REQUIRE(response.status == 200U);
        return parse_object(response.body);
    }

    [[nodiscard]] auto alice_token() const noexcept -> std::string const&
    {
        return m_alice_token;
    }

    [[nodiscard]] auto bob_token() const noexcept -> std::string const&
    {
        return m_bob_token;
    }

    [[nodiscard]] auto room_id() const noexcept -> std::string const&
    {
        return m_room_id;
    }

private:
    std::string m_alice_token{};
    std::string m_bob_token{};
    std::string m_room_id{};

    [[nodiscard]] auto sign_in(std::string const& name, std::string const& device) -> std::string
    {
        REQUIRE(
            request(runtime(), "POST", "/_matrix/client/v3/register", {}, registration_json(name, password)).status ==
            200U);
        auto const login = request(runtime(), "POST", "/_matrix/client/v3/login", {},
                                   R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@)" + name +
                                       R"(:example.org"},"password":")" + std::string{password} + R"(","device_id":")" +
                                       device + R"("})");
        REQUIRE(login.status == 200U);
        auto const login_body = parse_object(login.body);
        auto const* token = string_member(login_body, "access_token");
        REQUIRE(token != nullptr);
        return *token;
    }

    hs::ClientServerStartResult m_started;
};

[[nodiscard]] auto event_id_of(hs::LocalHttpResponse const& response) -> std::string
{
    REQUIRE(response.status == 200U);
    auto const body = parse_object(response.body);
    auto const* id = string_member(body, "event_id");
    REQUIRE(id != nullptr);
    return *id;
}

// The `duration_ms` of the object under `key`, or nullopt.
[[nodiscard]] auto duration_under(cj::Object const& event, std::string_view key) -> std::optional<std::int64_t>
{
    auto const* object = object_member_as_object(event, key);
    if (object == nullptr)
    {
        return std::nullopt;
    }
    auto const* duration = int_member(*object, "duration_ms");
    return duration == nullptr ? std::nullopt : std::optional<std::int64_t>{*duration};
}

// The two remaining-time fields of a served event's `unsigned`.
struct Remaining final
{
    std::optional<std::int64_t> stable{};
    std::optional<std::int64_t> unstable{};
};

[[nodiscard]] auto remaining_of(cj::Object const& served_event) -> Remaining
{
    auto result = Remaining{};
    if (auto const* unsigned_object = object_member_as_object(served_event, "unsigned"); unsigned_object != nullptr)
    {
        if (auto const* value = int_member(*unsigned_object, ev::sticky_remaining_field); value != nullptr)
        {
            result.stable = *value;
        }
        if (auto const* value = int_member(*unsigned_object, ev::unstable_sticky_remaining_field); value != nullptr)
        {
            result.unstable = *value;
        }
    }
    return result;
}

} // namespace

SCENARIO("A message sent with either sticky parameter name is a sticky event whose hash and signature cover it",
         "[sticky-events][integration][send]")
{
    GIVEN("alice and bob in a room and a duration of half an hour")
    {
        auto fixture = Fixture{};
        auto const name = GENERATE(std::string{stable_name}, std::string{unstable_name});

        WHEN("alice sends a message with the parameter under one name")
        {
            auto const response = fixture.put_send("t1", name + "=1800000");
            THEN("the stored PDU carries both fields, equal, in the hash, the event ID and the signature")
            {
                auto const event_id = event_id_of(response);
                auto const pdu = fixture.stored(event_id);
                REQUIRE(duration_under(pdu, "sticky") == std::optional<std::int64_t>{1'800'000});
                REQUIRE(duration_under(pdu, "msc4354_sticky") == std::optional<std::int64_t>{1'800'000});
                REQUIRE(fixture.store().sticky_events.find(event_id, t0) != nullptr);

                auto const stored_value = cj::Value{pdu};
                auto const* policy = merovingian::rooms::find_room_version_policy("12");
                REQUIRE(policy != nullptr);
                auto const* hashes = object_member_as_object(pdu, "hashes");
                REQUIRE(hashes != nullptr);
                auto const content_hash = ev::make_content_hash(stored_value);
                REQUIRE(content_hash.error.empty());
                REQUIRE(*string_member(*hashes, "sha256") == content_hash.sha256);
                auto const derived = ev::make_reference_hash_event_id(stored_value, *policy);
                REQUIRE(derived.error.empty());
                REQUIRE(derived.event_id == event_id);

                auto const keys = db::snapshot_server_signing_keys_of(fixture.store(), "example.org");
                REQUIRE_FALSE(keys.empty());
                auto verified = false;
                for (auto const& key : keys)
                {
                    auto const result = ev::verify_event_signature(
                        stored_value, *policy, ev::SigningKeyId{"example.org", key.key_id},
                        merovingian::crypto::Ed25519PublicKey{ev::matrix_bytes_from_base64(key.public_key)},
                        *fixture.runtime().homeserver.crypto_provider);
                    verified = verified || result.valid;
                }
                REQUIRE(verified);
            }
        }
    }
}

SCENARIO("A sticky parameter that is not a single whole number of at least 1 is refused and sends nothing",
         "[sticky-events][integration][send]")
{
    GIVEN("alice in a room")
    {
        auto fixture = Fixture{};
        auto const query = GENERATE(
            as<std::string>{}, "sticky_duration_ms=0", "sticky_duration_ms=-1", "sticky_duration_ms=9007199254740992",
            "sticky_duration_ms=1.5", "sticky_duration_ms=", "sticky_duration_ms=abc", "sticky_duration_ms",
            "sticky_duration_ms=5&sticky_duration_ms=6", "sticky_duration_ms=5&org.matrix.msc4354.sticky_duration_ms=5",
            "org.matrix.msc4354.sticky_duration_ms=5&org.matrix.msc4354.sticky_duration_ms=5",
            "org.matrix.msc4354.sticky_duration_%6Ds=0");
        auto const before = fixture.event_count();

        WHEN("alice sends a message with it")
        {
            auto const response = fixture.put_send("t1", query);
            THEN("the answer is 400 M_INVALID_PARAM and no event was stored")
            {
                REQUIRE(response.status == 400U);
                REQUIRE(errcode_of(response) == "M_INVALID_PARAM");
                REQUIRE(fixture.event_count() == before);
                REQUIRE(fixture.store().sticky_events.size() == 0U);
            }
        }
    }
}

SCENARIO("The largest duration canonical JSON allows is accepted and kept as given",
         "[sticky-events][integration][send]")
{
    GIVEN("alice in a room")
    {
        auto fixture = Fixture{};
        WHEN("alice sends a message with 2^53-1")
        {
            auto const event_id = event_id_of(fixture.put_send("t1", "sticky_duration_ms=9007199254740991"));
            THEN("the PDU holds it, and the row expires an hour after it was sent")
            {
                REQUIRE(duration_under(fixture.stored(event_id), "sticky") ==
                        std::optional<std::int64_t>{9'007'199'254'740'991});
                auto const* row = fixture.store().sticky_events.find(event_id, t0);
                REQUIRE(row != nullptr);
                REQUIRE(row->expires_at_ms == t0 + one_hour);
            }
        }
    }
}

SCENARIO("With sticky events disabled the parameter is 403 and the event is never sent",
         "[sticky-events][integration][send]")
{
    GIVEN("a server with sticky events off")
    {
        auto fixture = Fixture{};
        fixture.runtime().limits.sticky_events_enabled = false;
        auto const before = fixture.event_count();
        auto const query =
            GENERATE(as<std::string>{}, "sticky_duration_ms=5000", "org.matrix.msc4354.sticky_duration_ms=5000",
                     "sticky_duration_ms=0", "sticky_duration_ms=5000&org.matrix.msc4140.delay=60000");

        WHEN("alice sends with the parameter")
        {
            auto const response = fixture.put_send("t1", query);
            THEN("the answer is 403 M_FORBIDDEN and nothing was sent or scheduled")
            {
                REQUIRE(response.status == 403U);
                REQUIRE(errcode_of(response) == "M_FORBIDDEN");
                REQUIRE(fixture.event_count() == before);
                REQUIRE(fixture.store().delayed_events.size() == 0U);
            }
        }
        AND_WHEN("alice schedules through the dedicated path with it")
        {
            auto const response =
                request(fixture.runtime(), "PUT", fixture.room_path() + "/delayed_event/m.test.sticky/t2",
                        fixture.alice_token(), R"({"delay_ms":1000,"content":{"a":1},"sticky_duration_ms":5000})");
            THEN("the answer is 403 M_FORBIDDEN")
            {
                REQUIRE(response.status == 403U);
                REQUIRE(errcode_of(response) == "M_FORBIDDEN");
                REQUIRE(fixture.store().delayed_events.size() == 0U);
            }
        }
        AND_WHEN("alice sends without the parameter")
        {
            THEN("the send is ordinary and not sticky")
            {
                auto const event_id = event_id_of(fixture.put_send("t3", ""));
                REQUIRE_FALSE(duration_under(fixture.stored(event_id), "sticky").has_value());
            }
        }
    }
}

SCENARIO("A sticky parameter on a state, POST send or redact request is refused", "[sticky-events][integration][send]")
{
    GIVEN("alice in a room and an event of hers to redact")
    {
        auto fixture = Fixture{};
        auto const target = event_id_of(fixture.put_send("t0", ""));
        auto const before = fixture.event_count();
        auto const name = GENERATE(std::string{stable_name}, std::string{unstable_name});
        auto const enabled = GENERATE(true, false);
        fixture.runtime().limits.sticky_events_enabled = enabled;

        WHEN("it is given to a state route")
        {
            auto const target_path =
                GENERATE(as<std::string>{}, "/state/m.test.state/key", "/state/m.test.state/", "/state/m.test.state");
            auto const response = request(fixture.runtime(), "PUT",
                                          fixture.room_path() + target_path + "?" + name + "=5000" +
                                              GENERATE(as<std::string>{}, "", "&org.matrix.msc4140.delay=1000"),
                                          fixture.alice_token(), R"({"v":1})");
            THEN("it is 400 M_INVALID_PARAM and nothing is stored or scheduled")
            {
                REQUIRE(response.status == 400U);
                REQUIRE(errcode_of(response) == "M_INVALID_PARAM");
                REQUIRE(fixture.event_count() == before);
                REQUIRE(fixture.store().delayed_events.size() == 0U);
            }
        }
        AND_WHEN("it is given to POST /send")
        {
            auto const response = request(fixture.runtime(), "POST", fixture.room_path() + "/send?" + name + "=5000",
                                          fixture.alice_token(), R"({"type":"m.test.sticky","content":{"a":1}})");
            THEN("it is 400 M_INVALID_PARAM")
            {
                REQUIRE(response.status == 400U);
                REQUIRE(errcode_of(response) == "M_INVALID_PARAM");
                REQUIRE(fixture.event_count() == before);
            }
        }
        AND_WHEN("it is given to a redaction")
        {
            auto const response =
                request(fixture.runtime(), "PUT", fixture.room_path() + "/redact/" + target + "/r1?" + name + "=5000",
                        fixture.alice_token(), "{}");
            THEN("it is 400 M_INVALID_PARAM and the target is not redacted")
            {
                REQUIRE(response.status == 400U);
                REQUIRE(errcode_of(response) == "M_INVALID_PARAM");
                REQUIRE(fixture.event_count() == before);
            }
        }
    }
}

SCENARIO("A sticky event is served with its remaining time, capped at an hour, until it expires",
         "[sticky-events][integration][serve]")
{
    GIVEN("a half-hour sticky event and a two-hour one, sent at the same moment")
    {
        auto fixture = Fixture{};
        auto const short_id = event_id_of(fixture.put_send("t1", "sticky_duration_ms=1800000"));
        auto const long_id = event_id_of(fixture.put_send("t2", "org.matrix.msc4354.sticky_duration_ms=7200000"));
        auto const plain_id = event_id_of(fixture.put_send("t3", ""));

        WHEN("ten minutes pass and alice reads them")
        {
            fixture.set_time(t0 + 600'000);
            THEN("both sticky events carry both fields, positive and at most an hour, and the plain one neither")
            {
                auto const short_remaining = remaining_of(fixture.served(short_id));
                REQUIRE(short_remaining.stable == std::optional<std::int64_t>{1'200'000});
                REQUIRE(short_remaining.unstable == short_remaining.stable);
                auto const long_remaining = remaining_of(fixture.served(long_id));
                REQUIRE(long_remaining.stable == std::optional<std::int64_t>{one_hour - 600'000});
                REQUIRE(long_remaining.unstable == long_remaining.stable);
                REQUIRE_FALSE(remaining_of(fixture.served(plain_id)).stable.has_value());
                // The PDU keeps the value as the client gave it; only the lifetime is capped.
                REQUIRE(duration_under(fixture.stored(long_id), "sticky") == std::optional<std::int64_t>{7'200'000});
            }
            AND_THEN("/messages and /context serve the same fields")
            {
                auto const messages = request(fixture.runtime(), "GET",
                                              fixture.room_path() + "/messages?dir=b&limit=20", fixture.alice_token());
                REQUIRE(messages.status == 200U);
                REQUIRE(messages.body.find("sticky_duration_remaining_ms") != std::string::npos);
                REQUIRE(messages.body.find("msc4354_sticky_duration_ttl_ms") != std::string::npos);
                auto const context =
                    request(fixture.runtime(), "GET", fixture.room_path() + "/context/" + short_id + "?limit=2",
                            fixture.alice_token());
                REQUIRE(context.status == 200U);
                REQUIRE(context.body.find("sticky_duration_remaining_ms") != std::string::npos);
                auto const sync = request(fixture.runtime(), "GET", "/_matrix/client/v3/sync", fixture.alice_token());
                REQUIRE(sync.status == 200U);
                REQUIRE(sync.body.find("sticky_duration_remaining_ms") != std::string::npos);
            }
        }
        AND_WHEN("the clock passes the short event's expiry but not the long one's")
        {
            fixture.set_time(t0 + 1'800'001);
            THEN("the short one is served without the fields and the long one with them")
            {
                REQUIRE_FALSE(remaining_of(fixture.served(short_id)).stable.has_value());
                REQUIRE_FALSE(remaining_of(fixture.served(short_id)).unstable.has_value());
                REQUIRE(remaining_of(fixture.served(long_id)).stable.has_value());
            }
        }
        AND_WHEN("the clock passes an hour and the prune job's function runs")
        {
            fixture.set_time(t0 + one_hour + 1);
            REQUIRE(fixture.store().sticky_events.size() == 2U);
            REQUIRE(hs::prune_sticky_events(fixture.runtime().homeserver) == hs::sticky_events_prune_interval);
            THEN("neither is served sticky and both rows are gone")
            {
                REQUIRE_FALSE(remaining_of(fixture.served(short_id)).stable.has_value());
                REQUIRE_FALSE(remaining_of(fixture.served(long_id)).stable.has_value());
                REQUIRE(fixture.store().sticky_events.size() == 0U);
            }
        }
    }
}

SCENARIO("Redacting a sticky event removes its row and its fields", "[sticky-events][integration][redaction]")
{
    GIVEN("a sticky event of alice")
    {
        auto fixture = Fixture{};
        auto const event_id = event_id_of(fixture.put_send("t1", "sticky_duration_ms=1800000"));
        REQUIRE(fixture.store().sticky_events.find(event_id, t0) != nullptr);

        WHEN("alice redacts it")
        {
            REQUIRE(request(fixture.runtime(), "PUT", fixture.room_path() + "/redact/" + event_id + "/r1",
                            fixture.alice_token(), "{}")
                        .status == 200U);
            THEN("the row is gone and the stored and served events carry neither field")
            {
                REQUIRE(fixture.store().sticky_events.find(event_id, t0) == nullptr);
                REQUIRE(fixture.store().sticky_events.size() == 0U);
                auto const pdu = fixture.stored(event_id);
                REQUIRE_FALSE(duration_under(pdu, "sticky").has_value());
                REQUIRE_FALSE(duration_under(pdu, "msc4354_sticky").has_value());
                auto const served = fixture.served(event_id);
                REQUIRE_FALSE(remaining_of(served).stable.has_value());
                REQUIRE_FALSE(remaining_of(served).unstable.has_value());
            }
        }
    }
}

SCENARIO("Deactivating an account removes its sticky events and no one else's",
         "[sticky-events][integration][deactivate]")
{
    GIVEN("a sticky event of alice and one of bob")
    {
        auto fixture = Fixture{};
        auto const alices = event_id_of(fixture.put_send("t1", "sticky_duration_ms=1800000"));
        auto const bobs = event_id_of(request(fixture.runtime(), "PUT",
                                              fixture.room_path() + "/send/m.test.sticky/b1?sticky_duration_ms=1800000",
                                              fixture.bob_token(), R"({"body":"hello"})"));
        REQUIRE(fixture.store().sticky_events.size() == 2U);

        WHEN("alice deactivates her account")
        {
            auto const deactivated =
                request(fixture.runtime(), "POST", "/_matrix/client/v3/account/deactivate", fixture.alice_token(),
                        R"({"auth":{"type":"m.login.password","password":")" + std::string{password} + R"("}})");

            THEN("her row is gone, bob's stays, and her event is no longer served as sticky")
            {
                REQUIRE(deactivated.status == 200U);
                REQUIRE(fixture.store().sticky_events.find(alices, t0) == nullptr);
                REQUIRE(fixture.store().sticky_events.find(bobs, t0) != nullptr);
                REQUIRE(fixture.store().sticky_events.size() == 1U);
                REQUIRE_FALSE(remaining_of(fixture.served(alices, fixture.bob_token())).stable.has_value());
                REQUIRE(remaining_of(fixture.served(bobs, fixture.bob_token())).stable.has_value());
            }
        }
    }
}

SCENARIO("A sender holds at most the configured number of unexpired sticky events, the oldest giving way",
         "[sticky-events][integration][cap]")
{
    GIVEN("a server that allows two sticky events per sender")
    {
        auto fixture = Fixture{};
        fixture.runtime().limits.max_sticky_events_per_sender = 2U;
        auto const first = event_id_of(fixture.put_send("t1", "sticky_duration_ms=1800000"));
        fixture.set_time(t0 + 1'000);
        auto const second = event_id_of(fixture.put_send("t2", "sticky_duration_ms=1800000"));

        WHEN("alice sends a third")
        {
            fixture.set_time(t0 + 2'000);
            auto const third = event_id_of(fixture.put_send("t3", "sticky_duration_ms=1800000"));
            THEN("the send succeeded, the oldest stopped being sticky and the other two are")
            {
                auto const now = t0 + 2'000;
                REQUIRE(fixture.store().sticky_events.find(first, now) == nullptr);
                REQUIRE(fixture.store().sticky_events.find(second, now) != nullptr);
                REQUIRE(fixture.store().sticky_events.find(third, now) != nullptr);
                REQUIRE_FALSE(remaining_of(fixture.served(first)).stable.has_value());
                REQUIRE(remaining_of(fixture.served(third)).stable.has_value());
            }
        }
    }
}

SCENARIO("A sticky event that expires a sender's row in another room reports that room as changed",
         "[sticky-events][integration][cap][worker]")
{
    // The federation worker serves an unexpired sticky event past history visibility from its room snapshot
    // (ADR-0858), so a row the sender cap deletes must reach every room it was in, not only the room sent to
    // (ADR-0862).
    GIVEN("a server that allows one sticky event per sender, and alice's sticky event in the first room")
    {
        auto fixture = Fixture{};
        fixture.runtime().limits.max_sticky_events_per_sender = 1U;
        auto const first = event_id_of(fixture.put_send("t1", "sticky_duration_ms=1800000"));
        auto const created = request(fixture.runtime(), "POST", "/_matrix/client/v3/createRoom", fixture.alice_token(),
                                     R"({"preset":"public_chat"})");
        REQUIRE(created.status == 200U);
        auto const other_room = *string_member(parse_object(created.body), "room_id");
        auto changed_rooms = std::vector<std::string>{};
        fixture.runtime().homeserver.test_room_changed_log = &changed_rooms;

        WHEN("alice sends a sticky event in a second room")
        {
            fixture.set_time(t0 + 1'000);
            auto const second = event_id_of(request(fixture.runtime(), "PUT",
                                                    "/_matrix/client/v3/rooms/" + other_room +
                                                        "/send/m.test.sticky/t2" + "?sticky_duration_ms=1800000",
                                                    fixture.alice_token(), R"({"body":"hello"})"));
            fixture.runtime().homeserver.test_room_changed_log = nullptr;
            THEN("the first room's row is gone and the first room is reported changed")
            {
                auto const now = t0 + 1'000;
                REQUIRE(fixture.store().sticky_events.find(first, now) == nullptr);
                REQUIRE(fixture.store().sticky_events.find(second, now) != nullptr);
                REQUIRE(std::ranges::find(changed_rooms, fixture.room_id()) != changed_rooms.end());
            }
        }

        WHEN("alice sends a second sticky event in the same room")
        {
            fixture.set_time(t0 + 1'000);
            auto const second = event_id_of(fixture.put_send("t2", "sticky_duration_ms=1800000"));
            fixture.runtime().homeserver.test_room_changed_log = nullptr;
            THEN("the second room, which lost nothing, is not reported changed")
            {
                REQUIRE(fixture.store().sticky_events.find(second, t0 + 1'000) != nullptr);
                REQUIRE(std::ranges::find(changed_rooms, other_room) == changed_rooms.end());
            }
        }
    }
}

SCENARIO("A room holds at most the configured number of unexpired sticky events, the oldest giving way",
         "[sticky-events][integration][cap]")
{
    GIVEN("a server that allows two sticky events per room, and two of alice's in the room")
    {
        auto fixture = Fixture{};
        fixture.runtime().limits.max_sticky_events_per_room = 2U;
        auto const first = event_id_of(fixture.put_send("t1", "sticky_duration_ms=1800000"));
        fixture.set_time(t0 + 1'000);
        auto const second = event_id_of(fixture.put_send("t2", "sticky_duration_ms=1800000"));

        WHEN("bob, of the same server, sends one")
        {
            fixture.set_time(t0 + 2'000);
            auto const bobs = event_id_of(request(
                fixture.runtime(), "PUT", fixture.room_path() + "/send/m.test.sticky/b1?sticky_duration_ms=1800000",
                fixture.bob_token(), R"({"body":"hello"})"));
            THEN("the send succeeded, the room's oldest stopped being sticky and the other two are")
            {
                auto const now = t0 + 2'000;
                REQUIRE(fixture.store().sticky_events.find(first, now) == nullptr);
                REQUIRE(fixture.store().sticky_events.find(second, now) != nullptr);
                REQUIRE(fixture.store().sticky_events.find(bobs, now) != nullptr);
                REQUIRE(fixture.store().sticky_events.unexpired_of_room(fixture.room_id(), now).size() == 2U);
            }
        }
    }
}

SCENARIO("A delayed sticky event is sent sticky and its lifetime starts when it is sent",
         "[sticky-events][integration][delayed]")
{
    GIVEN("alice and a delay of one minute")
    {
        auto fixture = Fixture{};
        auto const via_query = GENERATE(true, false);

        WHEN("she schedules a sticky message")
        {
            auto const scheduled =
                via_query
                    ? fixture.put_send("t1",
                                       "org.matrix.msc4140.delay=60000&" + std::string{unstable_name} + "=1800000")
                    : request(
                          fixture.runtime(), "PUT",
                          "/_matrix/client/unstable/org.matrix.msc4140/rooms/" + fixture.room_id() +
                              "/delayed_event/m.test.sticky/t1",
                          fixture.alice_token(),
                          R"({"delay_ms":60000,"content":{"body":"later"},"org.matrix.msc4354.sticky_duration_ms":1800000})");
            REQUIRE(scheduled.status == 200U);
            auto const before = fixture.event_count();
            THEN("nothing is sent and no sticky row exists yet")
            {
                REQUIRE(fixture.store().sticky_events.size() == 0U);
                REQUIRE(fixture.event_count() == before);
            }
            AND_WHEN("the job runs at the due time")
            {
                fixture.set_time(t0 + 60'000);
                std::ignore = hs::send_due_delayed_events(fixture.runtime(), static_cast<std::uint64_t>(t0 + 60'000),
                                                          hs::StopFlag{});
                THEN("the event is sticky, stamped when it was sent, and expires from then")
                {
                    REQUIRE(fixture.event_count() == before + 1U);
                    REQUIRE(fixture.store().sticky_events.size() == 1U);
                    auto const* delayed = fixture.store().delayed_events.earliest_due();
                    REQUIRE(delayed == nullptr);
                    auto const rows = fixture.store().sticky_events.unexpired_of_room(fixture.room_id(), t0 + 60'000);
                    REQUIRE(rows.size() == 1U);
                    REQUIRE(rows.front()->received_at_ms == t0 + 60'000);
                    REQUIRE(rows.front()->expires_at_ms == t0 + 60'000 + 1'800'000);
                    auto const pdu = fixture.stored(rows.front()->event_id);
                    REQUIRE(duration_under(pdu, "sticky") == std::optional<std::int64_t>{1'800'000});
                    REQUIRE(duration_under(pdu, "msc4354_sticky") == std::optional<std::int64_t>{1'800'000});
                    REQUIRE(remaining_of(fixture.served(rows.front()->event_id)).stable ==
                            std::optional<std::int64_t>{1'800'000});
                }
            }
        }
    }
}

SCENARIO("The dedicated delayed-event routes read the sticky duration from the body",
         "[sticky-events][integration][delayed]")
{
    GIVEN("alice in a room")
    {
        auto fixture = Fixture{};
        auto const stable_route = GENERATE(true, false);
        auto const path = (stable_route ? fixture.room_path()
                                        : "/_matrix/client/unstable/org.matrix.msc4140/rooms/" + fixture.room_id()) +
                          "/delayed_event/m.test.sticky/";
        auto const body = GENERATE(
            as<std::string>{},
            R"({"delay_ms":1000,"content":{"a":1},"sticky_duration_ms":5000,"org.matrix.msc4354.sticky_duration_ms":5000})",
            R"({"delay_ms":1000,"content":{"a":1},"sticky_duration_ms":0})",
            R"({"delay_ms":1000,"content":{"a":1},"sticky_duration_ms":-5})",
            R"({"delay_ms":1000,"content":{"a":1},"org.matrix.msc4354.sticky_duration_ms":"5000"})",
            R"({"delay_ms":1000,"content":{"a":1},"sticky_duration_ms":5000,"state_key":"k"})");

        WHEN("the body is invalid or names a state key")
        {
            auto const response = request(fixture.runtime(), "PUT", path + "t1", fixture.alice_token(), body);
            THEN("it is 400 M_INVALID_PARAM and nothing is scheduled")
            {
                REQUIRE(response.status == 400U);
                REQUIRE(errcode_of(response) == "M_INVALID_PARAM");
                REQUIRE(fixture.store().delayed_events.size() == 0U);
            }
        }
        AND_WHEN("the body gives one valid duration under either name")
        {
            auto const name = GENERATE(std::string{stable_name}, std::string{unstable_name});
            auto const response = request(fixture.runtime(), "PUT", path + "t2", fixture.alice_token(),
                                          R"({"delay_ms":1000,"content":{"a":1},")" + name + R"(":7000})");
            THEN("it is scheduled with the duration kept")
            {
                REQUIRE(response.status == 200U);
                REQUIRE(fixture.store().delayed_events.size() == 1U);
                auto const* row = fixture.store().delayed_events.earliest_due();
                REQUIRE(row != nullptr);
                REQUIRE(row->sticky_duration_ms == std::optional<std::int64_t>{7000});
            }
        }
    }
}

SCENARIO("/versions advertises the sticky events flag from the configuration", "[sticky-events][integration][versions]")
{
    GIVEN("a server with sticky events on or off")
    {
        auto fixture = Fixture{};
        auto const enabled = GENERATE(true, false);
        fixture.runtime().limits.sticky_events_enabled = enabled;

        WHEN("a client asks /versions")
        {
            auto const response = request(fixture.runtime(), "GET", "/_matrix/client/versions");
            THEN("unstable_features org.matrix.msc4354 equals the setting")
            {
                REQUIRE(response.status == 200U);
                auto const body = parse_object(response.body);
                auto const* features = object_member_as_object(body, "unstable_features");
                REQUIRE(features != nullptr);
                auto const* flag = bool_member(*features, "org.matrix.msc4354");
                REQUIRE(flag != nullptr);
                REQUIRE(*flag == enabled);
            }
        }
    }
}
