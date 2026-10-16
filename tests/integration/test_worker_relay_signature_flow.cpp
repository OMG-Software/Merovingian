// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Decision D2 of the 0.12.13 handover (ADR-0071): main re-verifies the
// signature on every PDU a federation worker relays to it, with main's own
// remote_key_resolver, before anything is persisted. A compromised worker can
// otherwise inject events impersonating any sender the room's state
// authorises.
//
// Spec: docs/matrix-v1.19-spec/server-server-api.md, "Validating hashes and
// signatures on received events" (room versions 3 and later: the signature of
// the server the sender belongs to is required) and "Checks performed on
// receipt of a PDU", step 2 ("Passes signature checks, or else it is
// dropped").
//
// Each negative case runs in a room where the relayed event would otherwise be
// accepted; each has a correctly signed positive control.
// Tags: [worker_relay_signature].

#include "../federation_signing_test_support.hpp"
#include "../support/joining_threads.hpp"
#include "../support/remote_room_fixture.hpp"
#include "merovingian/canonicaljson/serializer.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/federation/inbound_ingestion.hpp"
#include "merovingian/homeserver/local_http_router.hpp"
#include "merovingian/homeserver/runtime.hpp"
#include "merovingian/homeserver/worker_pool.hpp"
#include "merovingian/ipc/channel.hpp"
#include "merovingian/ipc/federation_ipc_frames.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <exception>
#include <filesystem>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <tuple>
#include <vector>

#include <sys/socket.h>

namespace
{

using namespace merovingian;
using namespace merovingian::tests::remote_room;
using merovingian::federation::InboundPduEnvelope;
using merovingian::federation::PduIngestionStatus;

constexpr auto attacker_key_seed = "worker-relay-attacker-seed";

[[nodiscard]] auto string_array(std::vector<std::string> const& values) -> canonicaljson::Value
{
    auto array = canonicaljson::Array{};
    for (auto const& value : values)
    {
        array.push_back(canonicaljson::Value{value});
    }
    return canonicaljson::Value{std::move(array)};
}

// The wire frame a worker sends for pdu_ingest / membership_ingest, built from
// an envelope the way worker_event_loop.cpp's append_envelope_fields does.
// `type` is the frame type; `endpoint` is set for membership_ingest.
[[nodiscard]] auto envelope_frame(std::string_view type, InboundPduEnvelope const& env,
                                  std::optional<std::string> const& endpoint = std::nullopt) -> std::string
{
    auto obj = canonicaljson::Object{};
    obj.push_back(canonicaljson::make_member("type", canonicaljson::Value{std::string{type}}));
    if (endpoint.has_value())
    {
        obj.push_back(canonicaljson::make_member("endpoint", canonicaljson::Value{*endpoint}));
    }
    obj.push_back(canonicaljson::make_member("event_id", canonicaljson::Value{env.event_id}));
    obj.push_back(canonicaljson::make_member("room_id", canonicaljson::Value{env.room_id}));
    obj.push_back(canonicaljson::make_member("room_version", canonicaljson::Value{std::string{room_version}}));
    obj.push_back(canonicaljson::make_member("sender", canonicaljson::Value{env.sender}));
    obj.push_back(canonicaljson::make_member("event_type", canonicaljson::Value{env.event_type}));
    obj.push_back(canonicaljson::make_member("origin_server_ts", canonicaljson::Value{env.origin_server_ts}));
    obj.push_back(canonicaljson::make_member("depth", canonicaljson::Value{static_cast<std::int64_t>(env.depth)}));
    obj.push_back(canonicaljson::make_member("json", canonicaljson::Value{env.json}));
    obj.push_back(canonicaljson::make_member("origin", canonicaljson::Value{std::string{remote_server}}));
    if (env.state_key.has_value())
    {
        obj.push_back(canonicaljson::make_member("state_key", canonicaljson::Value{*env.state_key}));
    }
    obj.push_back(canonicaljson::make_member("auth_event_ids", string_array(env.auth_event_ids)));
    obj.push_back(canonicaljson::make_member("prev_event_ids", string_array(env.prev_event_ids)));
    obj.push_back(canonicaljson::make_member("signatures", canonicaljson::Value{canonicaljson::Array{}}));
    auto const serialized = canonicaljson::serialize_canonical(canonicaljson::Value{std::move(obj)});
    REQUIRE(serialized.error == canonicaljson::CanonicalJsonError::none);
    return serialized.output;
}

[[nodiscard]] auto parse_envelope(std::string const& signed_json) -> InboundPduEnvelope
{
    REQUIRE(!signed_json.empty());
    auto envelope = federation::parse_inbound_pdu_envelope(signed_json, room_version);
    REQUIRE(envelope.has_value());
    envelope->origin = remote_server;
    return *envelope;
}

[[nodiscard]] auto event_stored(homeserver::HomeserverRuntime const& runtime, std::string_view event_id) -> bool
{
    return std::ranges::any_of(runtime.database.persistent_store.events, [&](database::PersistentEvent const& e) {
        return e.event_id == event_id;
    });
}

[[nodiscard]] auto membership_of(homeserver::HomeserverRuntime const& runtime, std::string_view room_id,
                                 std::string_view user_id) -> std::string
{
    auto const& memberships = runtime.database.persistent_store.memberships;
    auto const it = std::ranges::find_if(memberships, [&](database::PersistentMembership const& m) {
        return m.room_id == room_id && m.user_id == user_id;
    });
    return it == memberships.end() ? std::string{} : it->membership;
}

struct RemoteRoom final
{
    std::string room_id;

    [[nodiscard]] auto auth_event_ids() const -> std::vector<std::string>
    {
        return {room_id + ":create", room_id + ":pl", room_id + ":member:bob"};
    }
    [[nodiscard]] auto prev_event_ids() const -> std::vector<std::string>
    {
        return {room_id + ":member"};
    }
};

// The runtime stays where the scenario started it: wire_federation_callbacks
// captures its address, so it must never be moved afterwards.
[[nodiscard]] auto seed_remote_room(homeserver::HomeserverRuntime& runtime, std::string room_id) -> RemoteRoom
{
    homeserver::wire_federation_callbacks(runtime);
    seed_room_with_genesis_state_group(runtime, room_id);
    runtime.federation.remote_key_resolver = genuine_key_resolver();
    return RemoteRoom{std::move(room_id)};
}

[[nodiscard]] auto leave_json(RemoteRoom const& room, std::string_view key_seed) -> std::string
{
    auto content = canonicaljson::Object{};
    content.push_back(canonicaljson::make_member("membership", canonicaljson::Value{std::string{"leave"}}));
    return make_remote_event_json(room.room_id, "m.room.member", std::string{remote_member}, remote_member,
                                  std::move(content), room.prev_event_ids(), room.auth_event_ids(), 4, 50, key_seed);
}

// Real authenticated/encrypted transport, with the production main handlers
// behind it. Only PDU result serialization is local (production's is private).
class MainRelayLink final
{
public:
    explicit MainRelayLink(homeserver::HomeserverRuntime& runtime)
    {
        auto fds = std::array<int, 2>{-1, -1};
        REQUIRE(::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, fds.data()) == 0);
        auto server_fd = core::FileDescriptor{fds[0]};
        auto client_fd = core::FileDescriptor{fds[1]};
        // Bound the handshake as well as every subsequent request.
        auto const timeout = timeval{5, 0};
        for (auto const fd : fds)
        {
            REQUIRE(::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
            REQUIRE(::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == 0);
        }
        auto const auth_key =
            crypto::derive_ipc_auth_key(std::span<std::uint8_t const>{std::array<std::uint8_t, 32>{}});
        REQUIRE(auth_key.has_value());
        auto server_exception = std::exception_ptr{};
        // JoiningThreads, not std::jthread: FreeBSD and OpenBSD libc++ lack jthread.
        auto handshake = tests::JoiningThreads{};
        handshake.emplace_back([&]() {
            try
            {
                server_ =
                    std::make_unique<ipc::IpcChannel>(std::move(server_fd), ipc::IpcChannel::Role::server, *auth_key);
            }
            catch (...)
            {
                server_exception = std::current_exception();
            }
        });
        client_ = std::make_unique<ipc::IpcChannel>(std::move(client_fd), ipc::IpcChannel::Role::client, *auth_key);
        handshake.join();
        REQUIRE(server_exception == nullptr);
        REQUIRE(server_ != nullptr);
        server_->set_request_handler([this, &runtime](std::uint64_t id, std::string json) {
            auto const type = ipc::ipc_json_get_str(json, "type");
            if (type == "pdu_ingest")
            {
                auto const result = homeserver::handle_pdu_ingest_request(runtime, json);
                auto const status = result.status == PduIngestionStatus::accepted          ? "accepted"
                                    : result.status == PduIngestionStatus::main_overloaded ? "main_overloaded"
                                                                                           : "rejected";
                server_->send_response(id, std::string{R"({"type":"pdu_ingest_result","status":)"} +
                                               ipc::ipc_json_str(status) + "}");
            }
            else if (type == "membership_ingest")
            {
                server_->send_response(id, homeserver::handle_membership_ingest_request(runtime, json));
            }
            else if (type == "invite_ingest")
            {
                server_->send_response(id, homeserver::handle_invite_ingest_request(runtime, json));
            }
        });
        server_->start();
        client_->start();
    }

    [[nodiscard]] auto send(std::string const& frame) -> std::string
    {
        auto reply = client_->send_request(frame, std::chrono::seconds{5});
        REQUIRE(reply.has_value());
        return *reply;
    }

private:
    std::unique_ptr<ipc::IpcChannel> server_{};
    std::unique_ptr<ipc::IpcChannel> client_{};
};

enum class MainRelayPath
{
    pdu,
    membership,
    invite
};

constexpr auto main_relay_paths = std::array{MainRelayPath::pdu, MainRelayPath::membership, MainRelayPath::invite};

struct MainRelayEvent final
{
    InboundPduEnvelope envelope;
    std::string frame;
};

[[nodiscard]] auto make_main_relay_event(homeserver::HomeserverRuntime& runtime, MainRelayPath path,
                                         std::int64_t sequence, std::string_view seed = remote_key_seed,
                                         std::string_view key_id = remote_key_id) -> MainRelayEvent
{
    auto const room = RemoteRoom{"!fed10-main-" + std::to_string(sequence) + ":local.example.org"};
    seed_room_with_genesis_state_group(runtime, room.room_id);
    auto json = std::string{};
    if (path == MainRelayPath::pdu)
    {
        json = make_remote_message_json(room.room_id, room.prev_event_ids(), room.auth_event_ids(), 4, sequence);
        if (seed != remote_key_seed)
            json =
                make_remote_message_json(room.room_id, room.prev_event_ids(), room.auth_event_ids(), 4, sequence, seed);
    }
    else
    {
        auto content = canonicaljson::Object{};
        content.push_back(canonicaljson::make_member(
            "membership", canonicaljson::Value{std::string{path == MainRelayPath::invite ? "invite" : "leave"}}));
        auto const state_key =
            path == MainRelayPath::invite ? std::string{"@alice:"} + local_server : std::string{remote_member};
        json = make_remote_event_json(room.room_id, "m.room.member", state_key, remote_member, std::move(content),
                                      room.prev_event_ids(), room.auth_event_ids(), 4, sequence, seed);
    }
    if (key_id != remote_key_id)
    {
        auto parsed = canonicaljson::parse_lossless(json);
        REQUIRE(parsed.error == canonicaljson::ParseError::none);
        auto object = std::get<canonicaljson::Object>(parsed.value.storage());
        std::erase_if(object, [](auto const& field) {
            return field.key == "signatures" || field.key == "hashes";
        });
        auto const unsigned_json = canonicaljson::serialize_canonical(canonicaljson::Value{std::move(object)});
        REQUIRE(unsigned_json.error == canonicaljson::CanonicalJsonError::none);
        json =
            federation::test::make_signed_event_json(unsigned_json.output, remote_server, key_id, seed, room_version);
    }
    auto env = parse_envelope(json);
    if (path == MainRelayPath::pdu)
        return {env, envelope_frame("pdu_ingest", env)};
    if (path == MainRelayPath::membership)
        return {env, envelope_frame("membership_ingest", env, std::string{"send_leave"})};
    auto obj = canonicaljson::Object{};
    obj.push_back(canonicaljson::make_member("type", canonicaljson::Value{std::string{"invite_ingest"}}));
    obj.push_back(canonicaljson::make_member("room_id", canonicaljson::Value{env.room_id}));
    obj.push_back(canonicaljson::make_member("event_id", canonicaljson::Value{env.event_id}));
    obj.push_back(canonicaljson::make_member("room_version", canonicaljson::Value{std::string{room_version}}));
    obj.push_back(canonicaljson::make_member("invite_event_json", canonicaljson::Value{env.json}));
    obj.push_back(canonicaljson::make_member("origin", canonicaljson::Value{std::string{remote_server}}));
    obj.push_back(canonicaljson::make_member("invite_room_state_json", canonicaljson::Value{canonicaljson::Array{}}));
    auto const serialized = canonicaljson::serialize_canonical(canonicaljson::Value{std::move(obj)});
    REQUIRE(serialized.error == canonicaljson::CanonicalJsonError::none);
    return {env, serialized.output};
}

[[nodiscard]] auto relay_accepted(MainRelayPath path, std::string const& response) -> bool
{
    return path == MainRelayPath::pdu ? ipc::ipc_json_get_str(response, "status") == "accepted"
                                      : response.find(R"("accepted":true)") != std::string::npos;
}

[[nodiscard]] auto relay_overloaded(MainRelayPath path, std::string const& response) -> bool
{
    return path == MainRelayPath::pdu
               ? ipc::ipc_json_get_str(response, "status") == "main_overloaded"
               : !relay_accepted(path, response) && ipc::ipc_json_get_u64(response, "status") == 503U;
}

// Count persistent mutations, including timeline allocation and invite metadata,
// not just the absence of the particular rejected event.
// A struct with only operator==, not a std::tuple: Catch2's expression
// decomposer cannot wrap a tuple comparison under clang with libstdc++ 14,
// whose tuple operator<=> is then matched against Catch::Decomposer.
struct MainRelayState final
{
    std::size_t events{};
    std::size_t memberships{};
    std::size_t invites{};
    std::size_t state{};
    std::size_t rooms{};
    std::uint64_t next_stream_ordering{};

    [[nodiscard]] auto operator==(MainRelayState const&) const -> bool = default;
};

[[nodiscard]] auto main_relay_state(homeserver::HomeserverRuntime const& runtime) -> MainRelayState
{
    auto const& store = runtime.database.persistent_store;
    return {store.events.size(), store.memberships.size(), store.invites.size(),
            store.state.size(),  store.rooms.size(),       runtime.database.next_stream_ordering};
}

auto check_relay_mutation(homeserver::HomeserverRuntime const& runtime, MainRelayPath path, MainRelayEvent const& event)
    -> void
{
    // Invitations record invite metadata, not the event graph (FED-5).
    if (path != MainRelayPath::invite)
        CHECK(event_stored(runtime, event.envelope.event_id));
    if (path == MainRelayPath::membership)
        CHECK(membership_of(runtime, event.envelope.room_id, remote_member) == "leave");
    if (path == MainRelayPath::invite)
    {
        CHECK(membership_of(runtime, event.envelope.room_id, std::string{"@alice:"} + local_server) == "invite");
        CHECK(std::ranges::any_of(runtime.database.persistent_store.invites, [&](auto const& invite) {
            return invite.room_id == event.envelope.room_id;
        }));
    }
}

auto prepare_main_relay(homeserver::HomeserverRuntime& runtime, std::atomic<std::size_t>& raw_calls) -> void
{
    homeserver::wire_federation_callbacks(runtime);
    runtime.database.users.push_back({std::string{"@alice:"} + local_server, "", false, false, false});
    runtime.federation.cached_pdu_key_lookup = {};
    runtime.federation.remote_key_resolver = [&raw_calls](std::string_view server, std::string_view id) {
        ++raw_calls;
        return genuine_key_resolver()(server, id);
    };
}

auto exhaust_main_admission(homeserver::HomeserverRuntime& runtime, bool occupied_slot) -> void
{
    auto guard = std::lock_guard{*runtime.federation.mutex};
    runtime.federation.config.key_resolution_max_in_flight = 1U;
    runtime.federation.config.key_resolution_per_ip_rate = {1U, 3600U};
    runtime.federation.key_resolution_buckets.clear();
    // Model a reservation owned by a different lookup: relays must not release it.
    runtime.federation.key_resolutions_in_flight = occupied_slot ? 1U : 0U;
    if (!occupied_slot)
        runtime.federation.key_resolution_buckets.push_back({"<unknown>", 1U, std::chrono::steady_clock::now()});
}

} // namespace

SCENARIO("main worker relays defer key misses without mutation and retry after admission recovers",
         "[integration][federation-worker][fed10][fed10-main-relay][fed10-main-admission]")
{
    GIVEN("real encrypted IPC, a persistent room and correctly signed relay events")
    {
        WHEN("main's source quota or a slot owned by another lookup is exhausted")
        {
            THEN("all three relay paths return retryable overload before network work or mutation")
            {
                auto sequence = std::int64_t{100};
                for (auto const relay_path : main_relay_paths)
                {
                    for (auto const occupied_slot : {false, true})
                    {
                        CAPTURE(relay_path, occupied_slot);
                        auto const db_path = unique_sqlite_path("main-relay-admission");
                        std::filesystem::remove(db_path);
                        auto started = homeserver::start_runtime(config_with_sqlite(db_path));
                        REQUIRE(started.started);
                        auto& runtime = started.runtime;
                        auto raw_calls = std::atomic<std::size_t>{0U};
                        prepare_main_relay(runtime, raw_calls);
                        auto link = MainRelayLink{runtime};

                        auto const control = make_main_relay_event(runtime, relay_path, sequence++);
                        REQUIRE(relay_accepted(relay_path, link.send(control.frame)));
                        check_relay_mutation(runtime, relay_path, control);
                        REQUIRE(raw_calls.load() == 1U);

                        auto const event = make_main_relay_event(runtime, relay_path, sequence++);
                        exhaust_main_admission(runtime, occupied_slot);
                        auto const before = main_relay_state(runtime);
                        auto const response = link.send(event.frame);
                        CHECK(relay_overloaded(relay_path, response));
                        CHECK_FALSE(relay_accepted(relay_path, response));
                        CHECK(raw_calls.load() == 1U);
                        CHECK(main_relay_state(runtime) == before);
                        CHECK_FALSE(event_stored(runtime, event.envelope.event_id));
                        CHECK(runtime.federation.key_resolutions_in_flight == (occupied_slot ? 1U : 0U));
                        CHECK(runtime.federation.key_resolution_failures.empty());

                        {
                            auto guard = std::lock_guard{*runtime.federation.mutex};
                            runtime.federation.key_resolutions_in_flight = 0U;
                            runtime.federation.key_resolution_buckets.clear();
                        }
                        auto const retry = link.send(event.frame);
                        CHECK(relay_accepted(relay_path, retry));
                        check_relay_mutation(runtime, relay_path, event);
                        CHECK(raw_calls.load() == 2U);
                        CHECK(runtime.federation.key_resolutions_in_flight == 0U);
                        CHECK(runtime.federation.key_resolution_buckets.size() == 1U);
                        if (!runtime.federation.key_resolution_buckets.empty())
                        {
                            CHECK(runtime.federation.key_resolution_buckets.front().source == "<unknown>");
                            CHECK(runtime.federation.key_resolution_buckets.front().resolutions_seen == 1U);
                        }
                        std::filesystem::remove(db_path);
                    }
                }
            }
        }
    }
}

SCENARIO("main worker relays verify matching cached keys without borrowing admission slots",
         "[integration][federation-worker][fed10][fed10-main-relay][fed10-main-cache]")
{
    GIVEN("main holds only a network-free verification key and receives genuinely signed IPC relays")
    {
        WHEN("admission is exhausted and the cache returns matching or mismatched key identities")
        {
            THEN("matching cached keys work but mismatches cannot bypass admission or cause mutation")
            {
                auto sequence = std::int64_t{200};
                for (auto const relay_path : main_relay_paths)
                {
                    for (auto const occupied_slot : {false, true})
                    {
                        CAPTURE(relay_path, occupied_slot);
                        auto const db_path = unique_sqlite_path("main-relay-cache");
                        std::filesystem::remove(db_path);
                        auto started = homeserver::start_runtime(config_with_sqlite(db_path));
                        REQUIRE(started.started);
                        auto& runtime = started.runtime;
                        auto raw_calls = std::atomic<std::size_t>{0U};
                        prepare_main_relay(runtime, raw_calls);
                        auto link = MainRelayLink{runtime};
                        auto const remote = genuine_key_resolver()(remote_server, remote_key_id);
                        REQUIRE(remote.has_value());
                        auto cached_key = remote->signing_key;
                        runtime.federation.cached_pdu_key_lookup = [&cached_key](std::string_view, std::string_view) {
                            return std::optional<federation::FederationKeyRecord>{cached_key};
                        };
                        auto const event = make_main_relay_event(runtime, relay_path, sequence++);
                        exhaust_main_admission(runtime, occupied_slot);
                        CHECK(relay_accepted(relay_path, link.send(event.frame)));
                        check_relay_mutation(runtime, relay_path, event);
                        CHECK(raw_calls.load() == 0U);
                        CHECK(runtime.federation.key_resolutions_in_flight == (occupied_slot ? 1U : 0U));

                        for (auto const wrong_server : {false, true})
                        {
                            cached_key = remote->signing_key;
                            if (wrong_server)
                                cached_key.server_name += ".invalid";
                            else
                                cached_key.key_id += "-different";
                            auto const mismatch = make_main_relay_event(runtime, relay_path, sequence++);
                            auto const before = main_relay_state(runtime);
                            CHECK(relay_overloaded(relay_path, link.send(mismatch.frame)));
                            CHECK(raw_calls.load() == 0U);
                            CHECK(main_relay_state(runtime) == before);
                            CHECK_FALSE(event_stored(runtime, mismatch.envelope.event_id));
                            CHECK(runtime.federation.key_resolutions_in_flight == (occupied_slot ? 1U : 0U));
                        }
                        CHECK(runtime.federation.key_resolution_failures.empty());

                        // A key-only cache works even without a full resolver,
                        // but never bypasses the event-time validity rule.
                        cached_key = remote->signing_key;
                        runtime.federation.remote_key_resolver = {};
                        auto const cache_only = make_main_relay_event(runtime, relay_path, sequence++);
                        CHECK(relay_accepted(relay_path, link.send(cache_only.frame)));
                        check_relay_mutation(runtime, relay_path, cache_only);
                        CHECK(raw_calls.load() == 0U);
                        CHECK(runtime.federation.key_resolutions_in_flight == (occupied_slot ? 1U : 0U));
                        cached_key.valid_until_ts = 0;
                        auto const expired = make_main_relay_event(runtime, relay_path, sequence++);
                        auto const before_expired = main_relay_state(runtime);
                        auto const expired_response = link.send(expired.frame);
                        CHECK_FALSE(relay_accepted(relay_path, expired_response));
                        CHECK_FALSE(relay_overloaded(relay_path, expired_response));
                        CHECK(main_relay_state(runtime) == before_expired);
                        CHECK(raw_calls.load() == 0U);
                        CHECK(runtime.federation.key_resolutions_in_flight == (occupied_slot ? 1U : 0U));
                        std::filesystem::remove(db_path);
                    }
                }
            }
        }
    }
}

SCENARIO("main worker relays bound negative-cache entries per server and key",
         "[integration][federation-worker][fed10][fed10-main-relay][fed10-main-negative]")
{
    GIVEN("real encrypted IPC and a main resolver that genuinely cannot supply the requested keys")
    {
        WHEN("workers repeat a failed key and then request another key of the same server")
        {
            THEN("only fresh misses call the resolver, the negative cache stays bounded and no data changes")
            {
                auto sequence = std::int64_t{300};
                for (auto const relay_path : main_relay_paths)
                {
                    CAPTURE(relay_path);
                    auto const db_path = unique_sqlite_path("main-relay-negative");
                    std::filesystem::remove(db_path);
                    auto started = homeserver::start_runtime(config_with_sqlite(db_path));
                    REQUIRE(started.started);
                    auto& runtime = started.runtime;
                    auto raw_calls = std::atomic<std::size_t>{0U};
                    prepare_main_relay(runtime, raw_calls);
                    runtime.federation.config.key_resolution_cache_entries = 1U;
                    runtime.federation.config.key_resolution_per_ip_rate = {5U, 3600U};
                    runtime.federation.config.key_resolution_failure_ttl_seconds = 3600U;
                    runtime.federation.remote_key_resolver =
                        [&raw_calls](std::string_view,
                                     std::string_view) -> std::optional<federation::FederationRemoteRuntime> {
                        ++raw_calls;
                        return std::nullopt;
                    };
                    auto link = MainRelayLink{runtime};
                    auto const first = make_main_relay_event(runtime, relay_path, sequence++);
                    auto const before = main_relay_state(runtime);
                    for (auto attempt = 0U; attempt != 3U; ++attempt)
                    {
                        auto const response = link.send(first.frame);
                        CHECK_FALSE(relay_accepted(relay_path, response));
                        CHECK_FALSE(relay_overloaded(relay_path, response));
                        CHECK(raw_calls.load() == 1U);
                        CHECK(main_relay_state(runtime) == before);
                        CHECK(runtime.federation.key_resolutions_in_flight == 0U);
                        CHECK(runtime.federation.key_resolution_failures.size() == 1U);
                    }
                    auto const alternate = make_main_relay_event(runtime, relay_path, sequence++, remote_key_seed,
                                                                 "ed25519:relay-alternate");
                    auto const with_alternate = main_relay_state(runtime);
                    CHECK_FALSE(relay_accepted(relay_path, link.send(alternate.frame)));
                    CHECK(raw_calls.load() == 2U);
                    CHECK(main_relay_state(runtime) == with_alternate);
                    CHECK(runtime.federation.key_resolution_failures.size() == 1U);
                    CHECK_FALSE(relay_accepted(relay_path, link.send(first.frame)));
                    CHECK(raw_calls.load() == 3U);
                    CHECK(main_relay_state(runtime) == with_alternate);
                    CHECK(runtime.federation.key_resolution_failures.size() == 1U);
                    CHECK(runtime.federation.key_resolution_buckets.size() == 1U);
                    if (!runtime.federation.key_resolution_buckets.empty())
                        CHECK(runtime.federation.key_resolution_buckets.front().resolutions_seen == 3U);
                    std::filesystem::remove(db_path);
                }
            }
        }
    }
}

SCENARIO("main re-verifies the signature of a /send PDU relayed by a federation worker",
         "[integration][federation-worker][worker_relay_signature]")
{
    GIVEN("a room in which the remote member may post, and main knowing the remote server's genuine key")
    {
        auto const path = unique_sqlite_path("merovingian-worker-relay-sig-");
        std::filesystem::remove(path);
        auto started = homeserver::start_runtime(config_with_sqlite(path));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const room = seed_remote_room(runtime, "!relay-sig-send:local.example.org");

        WHEN("the worker relays a message signed with the sender server's genuine key")
        {
            auto const env = parse_envelope(
                make_remote_message_json(room.room_id, room.prev_event_ids(), room.auth_event_ids(), 4, 40));
            auto const result = homeserver::handle_pdu_ingest_request(runtime, envelope_frame("pdu_ingest", env));

            THEN("it is accepted and stored")
            {
                INFO("reason: " << result.reason);
                REQUIRE(result.status == PduIngestionStatus::accepted);
                REQUIRE(event_stored(runtime, env.event_id));
            }
        }

        WHEN("the worker relays a message signed with a key that is not the sender server's")
        {
            auto const env = parse_envelope(make_remote_message_json(room.room_id, room.prev_event_ids(),
                                                                     room.auth_event_ids(), 4, 41, attacker_key_seed));
            auto const result = homeserver::handle_pdu_ingest_request(runtime, envelope_frame("pdu_ingest", env));

            THEN("it is dropped: not accepted and not stored")
            {
                REQUIRE(result.status != PduIngestionStatus::accepted);
                REQUIRE_FALSE(event_stored(runtime, env.event_id));
            }
        }

        WHEN("the worker relays a message whose sender key main cannot resolve")
        {
            runtime.federation.remote_key_resolver =
                [](std::string_view, std::string_view) -> std::optional<federation::FederationRemoteRuntime> {
                return std::nullopt;
            };
            auto const env = parse_envelope(
                make_remote_message_json(room.room_id, room.prev_event_ids(), room.auth_event_ids(), 4, 42));
            auto const result = homeserver::handle_pdu_ingest_request(runtime, envelope_frame("pdu_ingest", env));

            THEN("it is dropped: not accepted and not stored")
            {
                REQUIRE(result.status != PduIngestionStatus::accepted);
                REQUIRE_FALSE(event_stored(runtime, env.event_id));
            }
        }

        WHEN("the worker's frame names a different event ID from the one the signed event hashes to")
        {
            auto env = parse_envelope(
                make_remote_message_json(room.room_id, room.prev_event_ids(), room.auth_event_ids(), 4, 43));
            auto const genuine_event_id = env.event_id;
            env.event_id = "$forged-event-id";
            auto const result = homeserver::handle_pdu_ingest_request(runtime, envelope_frame("pdu_ingest", env));

            THEN("it is dropped: nothing is stored under either ID")
            {
                REQUIRE(result.status != PduIngestionStatus::accepted);
                REQUIRE_FALSE(event_stored(runtime, "$forged-event-id"));
                REQUIRE_FALSE(event_stored(runtime, genuine_event_id));
            }
        }

        WHEN("the key must be resolved while another thread needs the runtime lock")
        {
            auto resolver_called = false;
            auto lock_was_free = false;
            runtime.federation.remote_key_resolver =
                [&](std::string_view server_name,
                    std::string_view key_id) -> std::optional<federation::FederationRemoteRuntime> {
                resolver_called = true;
                // A real resolver may block on the network here. Another
                // thread must be able to take the runtime lock meanwhile.
                auto probe = std::thread{[&]() {
                    lock_was_free = runtime.mutex.try_lock();
                    if (lock_was_free)
                    {
                        runtime.mutex.unlock();
                    }
                }};
                probe.join();
                return genuine_key_resolver()(server_name, key_id);
            };
            auto const env = parse_envelope(
                make_remote_message_json(room.room_id, room.prev_event_ids(), room.auth_event_ids(), 4, 44));
            auto const result = homeserver::handle_pdu_ingest_request(runtime, envelope_frame("pdu_ingest", env));

            THEN("main resolved the key itself, without holding the runtime lock, and accepted the PDU")
            {
                REQUIRE(resolver_called);
                REQUIRE(lock_was_free);
                REQUIRE(result.status == PduIngestionStatus::accepted);
            }
        }

        std::filesystem::remove(path);
    }
}

SCENARIO("main re-verifies the signature of a send_leave relayed by a federation worker",
         "[integration][federation-worker][worker_relay_signature]")
{
    GIVEN("a room in which the remote member has joined, and main knowing the remote server's genuine key")
    {
        auto const path = unique_sqlite_path("merovingian-worker-relay-sig-");
        std::filesystem::remove(path);
        auto started = homeserver::start_runtime(config_with_sqlite(path));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const room = seed_remote_room(runtime, "!relay-sig-leave:local.example.org");

        WHEN("the worker relays the member's leave signed with the sender server's genuine key")
        {
            auto const env = parse_envelope(leave_json(room, remote_key_seed));
            auto const response = homeserver::handle_membership_ingest_request(
                runtime, envelope_frame("membership_ingest", env, std::string{"send_leave"}));

            THEN("the leave is accepted and the member has left")
            {
                INFO("response: " << response);
                REQUIRE(response.find(R"("accepted":true)") != std::string::npos);
                REQUIRE(membership_of(runtime, room.room_id, remote_member) == "leave");
            }
        }

        WHEN("the worker relays a leave for the member signed with a key that is not the sender server's")
        {
            auto const env = parse_envelope(leave_json(room, attacker_key_seed));
            auto const response = homeserver::handle_membership_ingest_request(
                runtime, envelope_frame("membership_ingest", env, std::string{"send_leave"}));

            THEN("it is refused and the member is still joined")
            {
                INFO("response: " << response);
                REQUIRE(response.find(R"("accepted":false)") != std::string::npos);
                REQUIRE(membership_of(runtime, room.room_id, remote_member) == "join");
                REQUIRE_FALSE(event_stored(runtime, env.event_id));
            }
        }

        std::filesystem::remove(path);
    }
}

SCENARIO("main re-verifies the signature of an invite relayed by a federation worker",
         "[integration][federation-worker][worker_relay_signature]")
{
    GIVEN("a local user, and main knowing the remote server's genuine key")
    {
        auto const path = unique_sqlite_path("merovingian-worker-relay-sig-");
        std::filesystem::remove(path);
        auto started = homeserver::start_runtime(config_with_sqlite(path));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        std::ignore = seed_remote_room(runtime, "!relay-sig-invite-host:local.example.org");
        auto const invitee = std::string{"@alice:"} + local_server;
        runtime.database.users.push_back({invitee, "", false, false, false});
        auto const remote_room_id = std::string{"!remote-room:remote.example.org"};

        auto const invite_frame = [&](std::string_view key_seed) {
            auto content = canonicaljson::Object{};
            content.push_back(canonicaljson::make_member("membership", canonicaljson::Value{std::string{"invite"}}));
            auto const event_json =
                make_remote_event_json(remote_room_id, "m.room.member", invitee, remote_member, std::move(content),
                                       {"$remote-prev"}, {"$remote-create"}, 5, 60, key_seed);
            auto obj = canonicaljson::Object{};
            obj.push_back(canonicaljson::make_member("type", canonicaljson::Value{std::string{"invite_ingest"}}));
            obj.push_back(canonicaljson::make_member("room_id", canonicaljson::Value{remote_room_id}));
            obj.push_back(
                canonicaljson::make_member("event_id", canonicaljson::Value{parse_envelope(event_json).event_id}));
            obj.push_back(canonicaljson::make_member("room_version", canonicaljson::Value{std::string{room_version}}));
            obj.push_back(canonicaljson::make_member("invite_event_json", canonicaljson::Value{event_json}));
            obj.push_back(canonicaljson::make_member("origin", canonicaljson::Value{std::string{remote_server}}));
            obj.push_back(
                canonicaljson::make_member("invite_room_state_json", canonicaljson::Value{canonicaljson::Array{}}));
            auto const serialized = canonicaljson::serialize_canonical(canonicaljson::Value{std::move(obj)});
            REQUIRE(serialized.error == canonicaljson::CanonicalJsonError::none);
            return serialized.output;
        };

        WHEN("the worker relays an invite signed with the sender server's genuine key")
        {
            auto const response = homeserver::handle_invite_ingest_request(runtime, invite_frame(remote_key_seed));

            THEN("the invite is accepted and recorded")
            {
                INFO("response: " << response);
                REQUIRE(response.find(R"("accepted":true)") != std::string::npos);
                REQUIRE(membership_of(runtime, remote_room_id, invitee) == "invite");
            }
        }

        WHEN("the worker relays an invite signed with a key that is not the sender server's")
        {
            auto const response = homeserver::handle_invite_ingest_request(runtime, invite_frame(attacker_key_seed));

            THEN("it is refused and no invite is recorded")
            {
                INFO("response: " << response);
                REQUIRE(response.find(R"("accepted":false)") != std::string::npos);
                REQUIRE(membership_of(runtime, remote_room_id, invitee).empty());
            }
        }

        std::filesystem::remove(path);
    }
}
