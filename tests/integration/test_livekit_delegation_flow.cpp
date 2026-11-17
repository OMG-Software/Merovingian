// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// MSC4195's delegated delayed leave (ADR-0832) and the LiveKit webhook (ADR-0833): the request, the job's decisions on
// GetParticipant's answers, and the webhook's authentication. LiveKit is a mock (`test_livekit_perform`); time is the
// delayed events' test clock and the job's `now_ms`; nothing sleeps.

#include "../support/JsonTestSupport.hpp"
#include "../support/LiveKitTestSupport.hpp"
#include "merovingian/database/DelayedEventStatus.hpp"
#include "merovingian/database/LiveKitDelegationStore.hpp"
#include "merovingian/database/LiveKitDelegationTable.hpp"
#include "merovingian/database/PersistentLiveKitDelegation.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/HomeserverRuntime.hpp"
#include "merovingian/homeserver/LiveKitDelegations.hpp"
#include "merovingian/homeserver/LiveKitNames.hpp"
#include "merovingian/homeserver/LocalHttpRequest.hpp"
#include "merovingian/homeserver/OperationResult.hpp"
#include "merovingian/homeserver/RuntimeMutex.hpp"
#include "merovingian/homeserver/StopFlag.hpp"
#include "merovingian/http/Header.hpp"
#include "merovingian/http/OutboundRequest.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include <sodium.h>

#include <array>
#include <chrono>
#include <cstdint>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

namespace
{

namespace hs = merovingian::homeserver;
using namespace merovingian::tests;
using namespace merovingian::tests::livekit;

constexpr auto t0_ms = std::uint64_t{1'800'000'000'000U};
constexpr auto hour_ms = std::uint64_t{3'600'000U};
constexpr auto delegate_path = std::string_view{"/_matrix/client/v1/rtc/livekit/delegate_delayed_leave"};
constexpr auto delegate_unstable_path =
    std::string_view{"/_matrix/client/unstable/io.element.msc4195/rtc/livekit/delegate_delayed_leave"};

// Schedules a delayed event of the token's user in the fixture's room (their call's leave, as far as this server can
// tell: the server holds any delayed event of the user's own) and returns its delay ID. A message, so a member without
// power to send state can schedule one too.
[[nodiscard]] auto schedule_leave(LiveKitFixture& fixture, std::string const& token, std::uint64_t const delay_ms,
                                  std::string_view const txn = "alice-call") -> std::string
{
    auto const answer = request(fixture.runtime(), "PUT",
                                "/_matrix/client/v3/rooms/" + fixture.room_id + "/send/m.test.leave/" +
                                    std::string{txn} + "?org.matrix.msc4140.delay=" + std::to_string(delay_ms),
                                token, "{}");
    REQUIRE(answer.status == 200U);
    auto const body = parse_object(answer.body);
    auto const* id = string_member(body, "delay_id");
    REQUIRE(id != nullptr);
    return *id;
}

[[nodiscard]] auto delegation_body(std::string_view const room_id, std::string_view const delay_id,
                                   std::string_view const url = sfu_url, std::string_view const slot = "m.call#room",
                                   std::string_view const member = "DEVICEID_member") -> std::string
{
    return R"({"url":")" + std::string{url} + R"(","room_id":")" + std::string{room_id} + R"(","slot_id":")" +
           std::string{slot} + R"(","member_id":")" + std::string{member} + R"(","delay_id":")" +
           std::string{delay_id} + R"("})";
}

[[nodiscard]] auto delegate(LiveKitFixture& fixture, std::string const& token, std::string body) -> Answer
{
    return request(fixture.runtime(), "POST", std::string{delegate_path}, token, std::move(body));
}

[[nodiscard]] auto run_job(LiveKitFixture& fixture, std::uint64_t const now_ms) -> std::chrono::milliseconds
{
    fixture.runtime().homeserver.test_delayed_event_clock_ms = now_ms;
    auto const stop = hs::StopFlag{};
    return hs::run_livekit_delegations(fixture.runtime(), now_ms, stop);
}

[[nodiscard]] auto delayed_row(LiveKitFixture& fixture, std::string_view const delay_id)
    -> merovingian::database::PersistentDelayedEvent const*
{
    return fixture.runtime().homeserver.database.persistent_store.delayed_events.find(delay_id);
}

[[nodiscard]] auto delegations(LiveKitFixture& fixture) -> merovingian::database::LiveKitDelegationTable const&
{
    return fixture.runtime().homeserver.database.persistent_store.livekit_delegations;
}

[[nodiscard]] auto get_participant_calls(LiveKitFixture& fixture) -> std::size_t
{
    auto count = std::size_t{0U};
    for (auto const& call : fixture.mock().requests)
    {
        count += call.url.ends_with("/twirp/livekit.RoomService/GetParticipant") ? 1U : 0U;
    }
    return count;
}

// alice in her room, with the clock at t0, one delayed leave of an hour, delegated.
struct Delegated final
{
    LiveKitFixture fixture{};
    std::string delay_id{};

    Delegated()
    {
        fixture.runtime().homeserver.test_delayed_event_clock_ms = t0_ms;
        delay_id = schedule_leave(fixture, fixture.alice_token, hour_ms);
        auto const answer = delegate(fixture, fixture.alice_token, delegation_body(fixture.room_id, delay_id));
        REQUIRE(answer.status == 200U);
        REQUIRE(answer.body == "{}");
    }
};

// --- LiveKit's webhook, signed as LiveKit signs it, independently of the code under test ---

[[nodiscard]] auto base64url(std::string_view const bytes) -> std::string
{
    auto out = std::string(sodium_base64_encoded_len(bytes.size(), sodium_base64_VARIANT_URLSAFE_NO_PADDING), '\0');
    sodium_bin2base64(out.data(), out.size(), reinterpret_cast<unsigned char const*>(bytes.data()), bytes.size(),
                      sodium_base64_VARIANT_URLSAFE_NO_PADDING);
    out.resize(out.find('\0'));
    return out;
}

[[nodiscard]] auto body_hash(std::string_view const body) -> std::string
{
    auto digest = std::array<unsigned char, crypto_hash_sha256_BYTES>{};
    crypto_hash_sha256(digest.data(), reinterpret_cast<unsigned char const*>(body.data()), body.size());
    auto out = std::string(sodium_base64_encoded_len(digest.size(), sodium_base64_VARIANT_ORIGINAL), '\0');
    sodium_bin2base64(out.data(), out.size(), digest.data(), digest.size(), sodium_base64_VARIANT_ORIGINAL);
    out.resize(out.find('\0'));
    return out;
}

[[nodiscard]] auto hs256(std::string_view const payload_json, std::string_view const secret) -> std::string
{
    auto const signing_input = base64url(R"({"alg":"HS256","typ":"JWT"})") + "." + base64url(payload_json);
    auto mac = std::array<unsigned char, crypto_auth_hmacsha256_BYTES>{};
    auto state = crypto_auth_hmacsha256_state{};
    crypto_auth_hmacsha256_init(&state, reinterpret_cast<unsigned char const*>(secret.data()), secret.size());
    crypto_auth_hmacsha256_update(&state, reinterpret_cast<unsigned char const*>(signing_input.data()),
                                  signing_input.size());
    crypto_auth_hmacsha256_final(&state, mac.data());
    return signing_input + "." + base64url(std::string_view{reinterpret_cast<char const*>(mac.data()), mac.size()});
}

struct Webhook final
{
    std::string body;
    std::string authorization;
};

[[nodiscard]] auto webhook_event(std::string_view const event, std::string_view const room_name,
                                 std::string_view const identity, std::string_view const id,
                                 std::int64_t const created_at) -> std::string
{
    return R"({"event":")" + std::string{event} + R"(","room":{"name":")" + std::string{room_name} +
           R"("},"participant":{"identity":")" + std::string{identity} + R"(","state":"DISCONNECTED"},"id":")" +
           std::string{id} + R"(","createdAt":")" + std::to_string(created_at) + R"("})";
}

[[nodiscard]] auto signed_webhook(std::string body, std::int64_t const now_seconds,
                                  std::string_view const issuer = api_key, std::string_view const secret = api_secret,
                                  std::string const& hash_override = {}) -> Webhook
{
    auto const claims = R"({"exp":)" + std::to_string(now_seconds + 300) + R"(,"iss":")" + std::string{issuer} +
                        R"(","nbf":)" + std::to_string(now_seconds) + R"(,"sha256":")" +
                        (hash_override.empty() ? body_hash(body) : hash_override) + R"("})";
    return {std::move(body), hs256(claims, secret)};
}

[[nodiscard]] auto post_webhook(LiveKitFixture& fixture, Webhook const& webhook, std::int64_t const now_seconds,
                                std::vector<merovingian::http::Header> headers = {}) -> hs::OperationResult
{
    auto request = hs::LocalHttpRequest{};
    request.method = "POST";
    request.target = std::string{hs::livekit_webhook_path};
    request.body = webhook.body;
    if (headers.empty() && !webhook.authorization.empty())
    {
        headers.push_back({"Authorization", webhook.authorization});
    }
    request.headers = std::move(headers);
    auto const guard = hs::RuntimeLock{fixture.runtime().homeserver.mutex};
    return hs::receive_livekit_webhook(fixture.runtime(), request, now_seconds);
}

} // namespace

SCENARIO("A delegation is accepted only for the caller's own scheduled event, in the room, for this server's SFU",
         "[homeserver][livekit][rtc][delegation][negative]")
{
    GIVEN("alice and bob in alice's room, each with a delayed event, and the clock at t0")
    {
        auto fixture = LiveKitFixture{};
        fixture.runtime().homeserver.test_delayed_event_clock_ms = t0_ms;
        REQUIRE(
            request(fixture.runtime(), "POST", "/_matrix/client/v3/join/" + fixture.room_id, fixture.bob_token, "{}")
                .status == 200U);
        auto const alice_delay = schedule_leave(fixture, fixture.alice_token, hour_ms);
        auto const bob_delay = schedule_leave(fixture, fixture.bob_token, hour_ms, "bob-call");
        auto const short_delay = schedule_leave(fixture, fixture.alice_token, 299'999U, "alice-short");

        WHEN("alice delegates bob's event, an unknown one, one too short, or names another SFU")
        {
            auto const foreign = delegate(fixture, fixture.alice_token, delegation_body(fixture.room_id, bob_delay));
            auto const unknown = delegate(fixture, fixture.alice_token, delegation_body(fixture.room_id, "nosuch"));
            auto const other_room =
                delegate(fixture, fixture.alice_token, delegation_body("!other:example.org", alice_delay));
            auto const too_short =
                delegate(fixture, fixture.alice_token, delegation_body(fixture.room_id, short_delay));
            auto const wrong_url = delegate(fixture, fixture.alice_token,
                                            delegation_body(fixture.room_id, alice_delay, "wss://sfu.example.org/"));

            THEN("each is 400 M_INVALID_PARAM, bob's and an unknown one alike, and nothing is stored")
            {
                for (auto const* answer : {&foreign, &unknown, &too_short, &wrong_url})
                {
                    CHECK(answer->status == 400U);
                    CHECK(errcode_of(*answer) == "M_INVALID_PARAM");
                }
                CHECK(foreign.body == unknown.body);
                CHECK(other_room.status == 403U); // not joined to that room
                CHECK(delegations(fixture).size() == 0U);
            }
        }

        WHEN("a body is malformed")
        {
            auto const body = GENERATE(std::string{"[]"}, std::string{"{}"},
                                       std::string{R"({"url":"wss://sfu.example.org","room_id":"!r:example.org"})"},
                                       std::string{R"({"url":"wss://sfu.example.org","room_id":"!r:example.org",)"
                                                   R"("slot_id":"s","member_id":"m","delay_id":5})"},
                                       std::string{R"({"url":"wss://sfu.example.org","room_id":"!r:example.org",)"
                                                   R"("slot_id":"s","member_id":"m","delay_id":")"} +
                                           std::string(65U, 'd') + R"("})");
            auto const answer = delegate(fixture, fixture.alice_token, body);

            THEN("it is a 400 and nothing is stored")
            {
                CHECK(answer.status == 400U);
                CHECK(delegations(fixture).size() == 0U);
            }
        }

        WHEN("alice delegates her own event on either path")
        {
            auto const path = std::string{GENERATE(delegate_path, delegate_unstable_path)};
            auto const answer = request(fixture.runtime(), "POST", path, fixture.alice_token,
                                        delegation_body(fixture.room_id, alice_delay));

            THEN("it is 200 {} and one delegation is stored, with nothing called yet")
            {
                CHECK(answer.status == 200U);
                CHECK(answer.body == "{}");
                REQUIRE(delegations(fixture).size() == 1U);
                CHECK(delegations(fixture).find(alice_delay) != nullptr);
                CHECK(fixture.mock().requests.empty());
            }
        }

        WHEN("there is no access token")
        {
            auto const answer = request(fixture.runtime(), "POST", std::string{delegate_unstable_path}, {}, {});

            THEN("it is 401, never 404, so Element Call's probe finds the route")
            {
                CHECK(answer.status == 401U);
            }
        }
    }

    GIVEN("a server with no token service")
    {
        auto started = hs::start_client_server(livekit_config({}));
        REQUIRE(started.started);
        auto const token = login(started.runtime, "alice");

        WHEN("a delegation is asked for")
        {
            auto const answer = request(started.runtime, "POST", std::string{delegate_path}, token,
                                        delegation_body("!r:example.org", "d"));

            THEN("it is 404 M_UNRECOGNIZED")
            {
                CHECK(answer.status == 404U);
                CHECK(errcode_of(answer) == "M_UNRECOGNIZED");
            }
        }
    }
}

SCENARIO("One delegation per room, slot and member; a new delay ID replaces the old; at most 20 per user",
         "[homeserver][livekit][rtc][delegation]")
{
    GIVEN("alice's delegated leave")
    {
        auto delegated = Delegated{};
        auto& fixture = delegated.fixture;

        WHEN("she delegates a second event for the same slot and member")
        {
            auto const second = schedule_leave(fixture, fixture.alice_token, hour_ms, "alice-call-2");
            auto const answer = delegate(fixture, fixture.alice_token, delegation_body(fixture.room_id, second));

            THEN("it replaces the first")
            {
                CHECK(answer.status == 200U);
                CHECK(delegations(fixture).size() == 1U);
                CHECK(delegations(fixture).find(second) != nullptr);
                CHECK(delegations(fixture).find(delegated.delay_id) == nullptr);
            }
        }

        WHEN("she holds 20 delegations and asks for a 21st with a new member")
        {
            for (auto index = 1; index < 20; ++index)
            {
                auto const id = schedule_leave(fixture, fixture.alice_token, hour_ms, "k" + std::to_string(index));
                REQUIRE(delegate(fixture, fixture.alice_token,
                                 delegation_body(fixture.room_id, id, sfu_url, "m.call#room",
                                                 "member" + std::to_string(index)))
                            .status == 200U);
            }
            auto const extra = schedule_leave(fixture, fixture.alice_token, hour_ms, "k-extra");
            auto const refused = delegate(fixture, fixture.alice_token,
                                          delegation_body(fixture.room_id, extra, sfu_url, "m.call#room", "member-x"));

            THEN("it is 429 M_LIMIT_EXCEEDED and nothing is evicted")
            {
                CHECK(refused.status == 429U);
                CHECK(errcode_of(refused) == "M_LIMIT_EXCEEDED");
                CHECK(delegations(fixture).size() == 20U);
            }
        }
    }
}

SCENARIO("The job restarts a delegated leave while LiveKit shows the participant, with a GetParticipant-only token",
         "[homeserver][livekit][rtc][delegation]")
{
    GIVEN("alice's delegated one-hour leave, and LiveKit answering that she is connected")
    {
        auto delegated = Delegated{};
        auto& fixture = delegated.fixture;
        fixture.mock().get_participant_status = 200U;
        fixture.mock().get_participant_body = R"({"identity":"x","state":"ACTIVE"})";

        WHEN("the job runs at t0, then 31 minutes later")
        {
            std::ignore = run_job(fixture, t0_ms);
            auto const since_first = delayed_row(fixture, delegated.delay_id)->delayed_since_ms;
            std::ignore = run_job(fixture, t0_ms + 31U * 60'000U);
            auto const* row = delayed_row(fixture, delegated.delay_id);

            THEN("the first run leaves the timer, and the second, with under half the delay left, restarts it")
            {
                CHECK(since_first == t0_ms);
                REQUIRE(row != nullptr);
                CHECK(row->status == merovingian::database::DelayedEventStatus::scheduled);
                CHECK(row->delayed_since_ms == t0_ms + 31U * 60'000U);
            }

            THEN("each call asked LiveKit's API address for the participant's MSC4195 room and identity only")
            {
                REQUIRE(get_participant_calls(fixture) == 2U);
                auto const& call = fixture.mock().requests.back();
                CHECK(call.url == "https://sfu-api.example.org:443/twirp/livekit.RoomService/GetParticipant");
                auto const room_name = hs::livekit_room_name(fixture.room_id, "m.call#room");
                auto const identity = hs::livekit_participant_identity("@alice:example.org", "DEVICEID_member");
                REQUIRE((room_name.has_value() && identity.has_value()));
                CHECK(call.body == R"({"room":")" + *room_name + R"(","identity":")" + *identity + R"("})");
                auto const authorization = header_value(call, "Authorization");
                REQUIRE(authorization.has_value());
                REQUIRE(authorization->starts_with("Bearer "));
                auto const payload = verified_payload(std::string_view{*authorization}.substr(7U));
                CHECK(string_member(payload, "sub") == nullptr);
                auto const* video = object_member_as_object(payload, "video");
                REQUIRE(video != nullptr);
                CHECK(video->size() == 2U);
                auto const* admin = bool_member(*video, "roomAdmin");
                auto const* room = string_member(*video, "room");
                REQUIRE((admin != nullptr && room != nullptr));
                CHECK(*admin);
                CHECK(*room == *room_name);
            }
        }

        WHEN("the job runs 10 seconds after t0, before the check interval has passed")
        {
            std::ignore = run_job(fixture, t0_ms);
            std::ignore = run_job(fixture, t0_ms + 10'000U);

            THEN("LiveKit was asked once")
            {
                CHECK(get_participant_calls(fixture) == 1U);
            }
        }
    }
}

SCENARIO("The job sends a delegated leave once LiveKit no longer shows a participant it saw",
         "[homeserver][livekit][rtc][delegation]")
{
    GIVEN("alice's delegated leave, seen connected at t0")
    {
        auto delegated = Delegated{};
        auto& fixture = delegated.fixture;
        fixture.mock().get_participant_status = 200U;
        fixture.mock().get_participant_body = R"({"state":"ACTIVE"})";
        std::ignore = run_job(fixture, t0_ms);

        WHEN("LiveKit then answers not_found, or the participant DISCONNECTED")
        {
            auto const gone = GENERATE(std::pair<std::uint16_t, std::string>{404U, R"({"code":"not_found","msg":"x"})"},
                                       std::pair<std::uint16_t, std::string>{200U, R"({"state":"DISCONNECTED"})"});
            fixture.mock().get_participant_status = gone.first;
            fixture.mock().get_participant_body = gone.second;
            std::ignore = run_job(fixture, t0_ms + 31'000U);
            auto const* row = delayed_row(fixture, delegated.delay_id);

            THEN("the leave is sent at once and the delegation ends")
            {
                REQUIRE(row != nullptr);
                CHECK(row->status == merovingian::database::DelayedEventStatus::sent);
                CHECK(delegations(fixture).size() == 0U);
            }
        }

        WHEN("LiveKit cannot be reached, or answers something else")
        {
            auto const unknown = GENERATE(0, 1, 2);
            if (unknown == 0)
            {
                fixture.mock().reachable = false;
            }
            else
            {
                fixture.mock().get_participant_status = unknown == 1 ? 500U : 404U;
                fixture.mock().get_participant_body = unknown == 1 ? "{}" : R"({"code":"permission_denied"})";
            }
            std::ignore = run_job(fixture, t0_ms + 31U * 60'000U);
            auto const* row = delayed_row(fixture, delegated.delay_id);

            THEN("nothing is sent and nothing is restarted: the event keeps its own timer")
            {
                REQUIRE(row != nullptr);
                CHECK(row->status == merovingian::database::DelayedEventStatus::scheduled);
                CHECK(row->delayed_since_ms == t0_ms);
                CHECK(delegations(fixture).size() == 1U);
            }
        }
    }

    GIVEN("alice's delegated leave, never seen connected")
    {
        auto delegated = Delegated{};
        auto& fixture = delegated.fixture;
        fixture.mock().get_participant_status = 404U;
        fixture.mock().get_participant_body = R"({"code":"not_found"})";

        WHEN("LiveKit answers not_found within the 2-minute grace, then after it")
        {
            std::ignore = run_job(fixture, t0_ms + 60'000U);
            auto const status_in_grace = delayed_row(fixture, delegated.delay_id)->status;
            std::ignore = run_job(fixture, t0_ms + 120'000U);
            auto const* row = delayed_row(fixture, delegated.delay_id);

            THEN("it waits for a client still connecting, then sends the leave")
            {
                CHECK(status_in_grace == merovingian::database::DelayedEventStatus::scheduled);
                REQUIRE(row != nullptr);
                CHECK(row->status == merovingian::database::DelayedEventStatus::sent);
            }
        }
    }
}

SCENARIO("A delegation stored again while a check was in flight is not given that check's answer",
         "[homeserver][livekit][rtc][delegation]")
{
    GIVEN("alice's delegated leave, and LiveKit answering that she is connected")
    {
        auto delegated = Delegated{};
        auto& fixture = delegated.fixture;
        fixture.mock().get_participant_status = 200U;
        fixture.mock().get_participant_body = R"({"identity":"x","state":"ACTIVE"})";

        WHEN("while LiveKit is asked, with the lock free, she delegates the same delay ID for another member")
        {
            auto const answer_connected = fixture.runtime().homeserver.test_livekit_perform;
            auto redelegated = Answer{};
            fixture.runtime().homeserver.test_livekit_perform =
                [&](merovingian::http::OutboundRequest const& outbound) {
                    redelegated = delegate(
                        fixture, fixture.alice_token,
                        delegation_body(fixture.room_id, delegated.delay_id, sfu_url, "m.call#room", "OTHER_member"));
                    return answer_connected(outbound);
                };
            std::ignore = run_job(fixture, t0_ms);
            fixture.runtime().homeserver.test_livekit_perform = answer_connected;
            auto const& progress = fixture.runtime().homeserver.livekit_delegation_progress;
            auto const entry = progress.find(delegated.delay_id);

            THEN("the new delegation is stored, and the old member's answer does not count as seeing the new one")
            {
                CHECK(redelegated.status == 200U);
                auto const* row = delegations(fixture).find(delegated.delay_id);
                REQUIRE(row != nullptr);
                CHECK(row->member_id == "OTHER_member");
                REQUIRE(entry != progress.end());
                CHECK(entry->second.last_seen_connected_ms == 0U);
            }

            AND_WHEN("a minute later LiveKit does not know the new member")
            {
                fixture.mock().get_participant_status = 404U;
                fixture.mock().get_participant_body = R"({"code":"not_found","msg":"participant not found"})";
                std::ignore = run_job(fixture, t0_ms + 60'000U);

                THEN("the leave is not sent: the new member is still inside its time to connect")
                {
                    auto const* event = delayed_row(fixture, delegated.delay_id);
                    REQUIRE(event != nullptr);
                    CHECK(event->status == merovingian::database::DelayedEventStatus::scheduled);
                    CHECK(delegations(fixture).size() == 1U);
                }
            }
        }
    }
}

SCENARIO("One run drops a bounded number of delegations, and the rest soon after",
         "[homeserver][livekit][rtc][delegation]")
{
    GIVEN("alice's delegated leave, and 70 stored delegations whose events are not scheduled")
    {
        auto delegated = Delegated{};
        auto& fixture = delegated.fixture;
        auto& store = fixture.runtime().homeserver.database.persistent_store;
        constexpr auto stale = std::size_t{70U};
        for (auto index = std::size_t{0U}; index < stale; ++index)
        {
            auto row = merovingian::database::PersistentLiveKitDelegation{};
            row.delay_id = "stale-" + std::to_string(index);
            row.user_id = "@stale" + std::to_string(index / 20U) + ":example.org";
            row.room_id = fixture.room_id;
            row.slot_id = "m.call#room";
            row.member_id = "member-" + std::to_string(index);
            row.created_ms = t0_ms;
            REQUIRE(merovingian::database::store_livekit_delegation(store, std::move(row)));
        }
        REQUIRE(delegations(fixture).size() == stale + 1U);

        WHEN("the job runs once, then again")
        {
            auto const first_wait = run_job(fixture, t0_ms);
            auto const after_first = delegations(fixture).size();
            std::ignore = run_job(fixture, t0_ms + 1'000U);

            THEN("the first run drops 64 and asks to run again soon; the second drops the rest and keeps alice's")
            {
                CHECK(after_first == stale + 1U - hs::livekit_delegation_drops_per_run);
                CHECK(first_wait < hs::livekit_delegation_check_interval);
                CHECK(delegations(fixture).size() == 1U);
                CHECK(delegations(fixture).find(delegated.delay_id) != nullptr);
            }
        }
    }
}

SCENARIO("A delegation ends without a call when its event is no longer scheduled or its user leaves",
         "[homeserver][livekit][rtc][delegation]")
{
    GIVEN("alice's delegated leave")
    {
        auto delegated = Delegated{};
        auto& fixture = delegated.fixture;

        WHEN("she cancels the event, then the job runs")
        {
            REQUIRE(request(fixture.runtime(), "POST",
                            "/_matrix/client/v1/delayed_events/" + delegated.delay_id + "/cancel", fixture.alice_token,
                            "{}")
                        .status == 200U);
            std::ignore = run_job(fixture, t0_ms);

            THEN("the delegation is dropped and LiveKit is not asked")
            {
                CHECK(delegations(fixture).size() == 0U);
                CHECK(get_participant_calls(fixture) == 0U);
            }
        }
    }

    GIVEN("bob's delegated leave in alice's room")
    {
        auto fixture = LiveKitFixture{};
        fixture.runtime().homeserver.test_delayed_event_clock_ms = t0_ms;
        REQUIRE(
            request(fixture.runtime(), "POST", "/_matrix/client/v3/join/" + fixture.room_id, fixture.bob_token, "{}")
                .status == 200U);
        auto const delay_id = schedule_leave(fixture, fixture.bob_token, hour_ms, "bob-call");
        REQUIRE(delegate(fixture, fixture.bob_token, delegation_body(fixture.room_id, delay_id)).status == 200U);

        WHEN("bob leaves the room, then the job runs")
        {
            REQUIRE(request(fixture.runtime(), "POST", "/_matrix/client/v3/rooms/" + fixture.room_id + "/leave",
                            fixture.bob_token, "{}")
                        .status == 200U);
            std::ignore = run_job(fixture, t0_ms);

            THEN("the delegation is dropped and the event is left to its own timer")
            {
                CHECK(delegations(fixture).size() == 0U);
                CHECK(get_participant_calls(fixture) == 0U);
                auto const* row = delayed_row(fixture, delay_id);
                REQUIRE(row != nullptr);
                CHECK(row->status == merovingian::database::DelayedEventStatus::scheduled);
            }
        }
    }
}

SCENARIO("A LiveKit webhook is believed only when LiveKit signed it, and then only prompts a check",
         "[homeserver][livekit][rtc][delegation][webhook]")
{
    GIVEN("alice's delegated leave, checked at t0 and seen connected")
    {
        auto delegated = Delegated{};
        auto& fixture = delegated.fixture;
        fixture.mock().get_participant_status = 200U;
        fixture.mock().get_participant_body = R"({"state":"ACTIVE"})";
        std::ignore = run_job(fixture, t0_ms);
        REQUIRE(get_participant_calls(fixture) == 1U);
        auto const now_s = static_cast<std::int64_t>((t0_ms + 5'000U) / 1000U);
        auto const room_name = *hs::livekit_room_name(fixture.room_id, "m.call#room");
        auto const identity = *hs::livekit_participant_identity("@alice:example.org", "DEVICEID_member");
        auto const left = webhook_event("participant_left", room_name, identity, "EV_1", now_s);

        WHEN("a webhook is unsigned, signed with another secret, by another key, stale, or for another body")
        {
            auto const unsigned_hook = post_webhook(fixture, Webhook{left, {}}, now_s);
            auto const other_secret =
                post_webhook(fixture, signed_webhook(left, now_s, api_key, "fedcba9876543210fedcba9876543210"), now_s);
            auto const other_key = post_webhook(fixture, signed_webhook(left, now_s, "APIother"), now_s);
            auto const expired = post_webhook(fixture, signed_webhook(left, now_s - 400), now_s);
            auto const other_body =
                post_webhook(fixture, signed_webhook(left, now_s, api_key, api_secret, body_hash("{}")), now_s);
            auto const twice = post_webhook(fixture, signed_webhook(left, now_s), now_s,
                                            {
                                                {"Authorization", signed_webhook(left, now_s).authorization},
                                                {"Authorization", signed_webhook(left, now_s).authorization}
            });
            std::ignore = run_job(fixture, t0_ms + 6'000U);

            THEN("each is 401 M_UNAUTHORIZED and no check is brought forward")
            {
                for (auto const* answer : {&unsigned_hook, &other_secret, &other_key, &expired, &other_body, &twice})
                {
                    CHECK(answer->status == 401U);
                    CHECK(answer->errcode == "M_UNAUTHORIZED");
                }
                CHECK(get_participant_calls(fixture) == 1U);
            }
        }

        WHEN("LiveKit's signed participant_left arrives, with or without a Bearer prefix")
        {
            auto webhook = signed_webhook(left, now_s);
            if (GENERATE(false, true))
            {
                webhook.authorization = "Bearer " + webhook.authorization;
            }
            fixture.mock().get_participant_status = 404U;
            fixture.mock().get_participant_body = R"({"code":"not_found"})";
            auto const answer = post_webhook(fixture, webhook, now_s);
            auto const status_after_webhook = delayed_row(fixture, delegated.delay_id)->status;
            std::ignore = run_job(fixture, t0_ms + 6'000U);

            THEN("it is 200, changes nothing by itself, and the next run checks at once and sends the leave")
            {
                CHECK(answer.status == 200U);
                CHECK(status_after_webhook == merovingian::database::DelayedEventStatus::scheduled);
                CHECK(get_participant_calls(fixture) == 2U);
                CHECK(delayed_row(fixture, delegated.delay_id)->status ==
                      merovingian::database::DelayedEventStatus::sent);
            }
        }

        WHEN("a signed webhook is replayed, stale, of another kind, or for no recorded delegation")
        {
            auto const first = post_webhook(fixture, signed_webhook(left, now_s), now_s);
            std::ignore = run_job(fixture, t0_ms + 6'000U);
            auto const calls_after_first = get_participant_calls(fixture);
            auto const replay = post_webhook(fixture, signed_webhook(left, now_s), now_s);
            auto const stale = post_webhook(
                fixture,
                signed_webhook(webhook_event("participant_left", room_name, identity, "EV_2", now_s - 400), now_s),
                now_s);
            auto const other_kind = post_webhook(
                fixture, signed_webhook(webhook_event("track_published", room_name, identity, "EV_3", now_s), now_s),
                now_s);
            auto const stranger = post_webhook(
                fixture,
                signed_webhook(webhook_event("participant_left", room_name, std::string(43U, 'A'), "EV_4", now_s),
                               now_s),
                now_s);
            std::ignore = run_job(fixture, t0_ms + 7'000U);

            THEN("each is 200 and none brings a check forward")
            {
                CHECK(first.status == 200U);
                for (auto const* answer : {&replay, &stale, &other_kind, &stranger})
                {
                    CHECK(answer->status == 200U);
                }
                CHECK(get_participant_calls(fixture) == calls_after_first);
            }
        }

        WHEN("a webhook is larger than 64 KiB")
        {
            auto const answer = post_webhook(fixture, signed_webhook(std::string(64U * 1024U + 1U, ' '), now_s), now_s);

            THEN("it is 413")
            {
                CHECK(answer.status == 413U);
            }
        }
    }
}

SCENARIO("The webhook route is answered before the access-token gate, and only with the token service on",
         "[homeserver][livekit][rtc][delegation][webhook][client-server]")
{
    GIVEN("a server with the token service on and LiveKit's signed webhook for an unknown room")
    {
        auto fixture = LiveKitFixture{};
        auto const now_ms = std::uint64_t{t0_ms};
        fixture.runtime().homeserver.test_delayed_event_clock_ms = now_ms;
        auto const now_s = static_cast<std::int64_t>(now_ms / 1000U);
        auto const webhook = signed_webhook(
            webhook_event("participant_left", std::string(43U, 'B'), std::string(43U, 'C'), "EV_route", now_s), now_s);
        auto const dispatch = [&fixture](std::string method, std::vector<merovingian::http::Header> headers,
                                         std::string body) {
            auto request = hs::LocalHttpRequest{};
            request.method = std::move(method);
            request.target = std::string{hs::livekit_webhook_path} + "?unused=1";
            request.body = std::move(body);
            request.headers = std::move(headers);
            return hs::handle_client_server_request(fixture.runtime(), std::move(request)).response;
        };

        WHEN("it is posted with no access token, signed and unsigned, and fetched with GET")
        {
            auto const signed_reply = dispatch("POST",
                                               {
                                                   {"Authorization", webhook.authorization}
            },
                                               webhook.body);
            auto const unsigned_reply = dispatch("POST", {}, webhook.body);
            auto const get_reply = dispatch("GET", {}, {});

            THEN("the signed one is 200 {}, the unsigned one the webhook's 401, and GET 405")
            {
                CHECK(signed_reply.status == 200U);
                CHECK(signed_reply.body == "{}");
                CHECK(unsigned_reply.status == 401U);
                CHECK(unsigned_reply.body.find("M_UNAUTHORIZED") != std::string::npos);
                CHECK(unsigned_reply.body.find("M_MISSING_TOKEN") == std::string::npos);
                CHECK(get_reply.status == 405U);
            }
        }
    }

    GIVEN("a server with no token service")
    {
        auto started = hs::start_client_server(livekit_config({}));
        REQUIRE(started.started);

        WHEN("the webhook path is posted to")
        {
            auto request = hs::LocalHttpRequest{};
            request.method = "POST";
            request.target = std::string{hs::livekit_webhook_path};
            request.body = "{}";
            auto const reply = hs::handle_client_server_request(started.runtime, std::move(request)).response;

            THEN("it is 404, as a path this server does not serve")
            {
                CHECK(reply.status == 404U);
                CHECK(reply.body.find("M_UNRECOGNIZED") != std::string::npos);
            }
        }
    }
}
