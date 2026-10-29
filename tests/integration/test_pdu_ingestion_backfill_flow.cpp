// SPDX-License-Identifier: GPL-3.0-or-later
//
// ADR-0064 phase C integration test: when an inbound PDU names a prev_event
// this server has never seen, ingest_pdu_event fetches it from the sending
// server via /_matrix/federation/v1/get_missing_events, verifies the
// returned event (content hash, signature, auth), stores it as an outlier
// with a state group, and then accepts the original PDU.
//
// Spec: docs/matrix-v1.19-spec/server-server-api.md — "Backfilling and
// retrieving missing events", "Checks performed on receipt of a PDU".
// Tags: [pdu_ingestion][backfill].

#include "../federation_signing_test_support.hpp"
#include "../support/remote_room_fixture.hpp"
#include "../support/tls_mock_server.hpp"
#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/serializer.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/core/query_params.hpp"
#include "merovingian/core/socket_handle.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/events/event_signer.hpp"
#include "merovingian/federation/inbound_ingestion.hpp"
#include "merovingian/federation/inbound_request.hpp"
#include "merovingian/homeserver/local_http_router.hpp"
#include "merovingian/homeserver/runtime.hpp"
#include "merovingian/homeserver/state_bookkeeping.hpp"
#include "merovingian/homeserver/tls.hpp"
#include "merovingian/net/tcp_acceptor.hpp"
#include "merovingian/rooms/room_version_policy.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <future>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

namespace
{

using namespace merovingian;
using merovingian::federation::InboundPduEnvelope;
using merovingian::federation::PduIngestionStatus;
using merovingian::homeserver::HomeserverRuntime;

// The room fixture, remote-signed event builders and the remote server's key
// live in tests/support/remote_room_fixture.hpp, shared with the worker relay
// signature tests.
using namespace merovingian::tests::remote_room;

[[nodiscard]] auto make_remote_event_pdu(std::string const& room_id, std::string const& type,
                                         std::optional<std::string> const& state_key, std::string const& sender,
                                         merovingian::canonicaljson::Object content,
                                         std::vector<std::string> const& prev_event_ids,
                                         std::vector<std::string> const& auth_event_ids, std::int64_t depth,
                                         std::int64_t ts, std::string_view key_seed = remote_key_seed)
    -> InboundPduEnvelope
{
    auto const signed_json = make_remote_event_json(room_id, type, state_key, sender, std::move(content),
                                                    prev_event_ids, auth_event_ids, depth, ts, key_seed);
    REQUIRE(!signed_json.empty());
    auto envelope = merovingian::federation::parse_inbound_pdu_envelope(signed_json, room_version);
    REQUIRE(envelope.has_value());
    envelope->origin = remote_server;
    return *envelope;
}

[[nodiscard]] auto make_remote_message_pdu(std::string const& room_id, std::vector<std::string> const& prev_event_ids,
                                           std::vector<std::string> const& auth_event_ids, std::int64_t depth,
                                           std::int64_t ts) -> InboundPduEnvelope
{
    auto const signed_json = make_remote_message_json(room_id, prev_event_ids, auth_event_ids, depth, ts);
    REQUIRE(!signed_json.empty());
    auto envelope = merovingian::federation::parse_inbound_pdu_envelope(signed_json, room_version);
    REQUIRE(envelope.has_value());
    envelope->origin = remote_server;
    return *envelope;
}

// Seeds a restrictive power_levels event accepted into the room, making it the
// new forward extremity and current state. Used to construct a state-before
// that is stricter than the permissive genesis power_levels.
auto seed_strict_power_levels(HomeserverRuntime& runtime, std::string const& room_id,
                              std::string const& /*permissive_pl_id*/, std::string const& prev_event_id) -> std::string
{
    using namespace merovingian;

    auto& store = runtime.database.persistent_store;
    auto* policy = rooms::find_room_version_policy(room_version);
    REQUIRE(policy != nullptr);

    auto const strict_pl_id = room_id + ":strict-pl";
    auto content = canonicaljson::Object{};
    content.push_back(canonicaljson::make_member("state_default", canonicaljson::Value{std::int64_t{100}}));
    auto users = canonicaljson::Object{};
    users.push_back(canonicaljson::make_member("@admin:local.example.org", canonicaljson::Value{std::int64_t{100}}));
    content.push_back(canonicaljson::make_member("users", canonicaljson::Value{std::move(users)}));

    auto obj = canonicaljson::Object{};
    obj.push_back(canonicaljson::make_member("type", canonicaljson::Value{std::string{"m.room.power_levels"}}));
    obj.push_back(canonicaljson::make_member("state_key", canonicaljson::Value{std::string{}}));
    obj.push_back(canonicaljson::make_member("room_id", canonicaljson::Value{room_id}));
    obj.push_back(canonicaljson::make_member("sender", canonicaljson::Value{std::string{"@admin:local.example.org"}}));
    obj.push_back(canonicaljson::make_member("content", canonicaljson::Value{std::move(content)}));
    obj.push_back(canonicaljson::make_member("origin_server_ts", canonicaljson::Value{std::int64_t{5}}));
    obj.push_back(canonicaljson::make_member("depth", canonicaljson::Value{std::int64_t{4}}));
    auto prev = canonicaljson::Array{};
    prev.push_back(canonicaljson::Value{prev_event_id});
    obj.push_back(canonicaljson::make_member("prev_events", canonicaljson::Value{std::move(prev)}));
    obj.push_back(canonicaljson::make_member("auth_events", canonicaljson::Value{canonicaljson::Array{}}));
    auto hashes = canonicaljson::Object{};
    hashes.push_back(canonicaljson::make_member("sha256", canonicaljson::Value{std::string{"hash"}}));
    obj.push_back(canonicaljson::make_member("hashes", canonicaljson::Value{std::move(hashes)}));
    auto const serialized = canonicaljson::serialize_canonical(canonicaljson::Value{std::move(obj)});
    REQUIRE(serialized.error == canonicaljson::CanonicalJsonError::none);

    store.events.push_back(
        {strict_pl_id, room_id, "@admin:local.example.org", serialized.output, 4U, 0U, {prev_event_id}, {}, {}});
    store.state.push_back({room_id, "m.room.power_levels", "", strict_pl_id});

    auto const state_before = homeserver::compute_state_before(store, room_id, *policy, {prev_event_id});
    REQUIRE(state_before.ok);
    auto const state_after = homeserver::compute_state_after(state_before.state, strict_pl_id, "m.room.power_levels",
                                                             std::optional<std::string>{std::string{}});
    auto const group = homeserver::record_event_state(store, room_id, strict_pl_id, {prev_event_id}, state_after, true);
    REQUIRE(group.has_value());
    REQUIRE(homeserver::recompute_current_state(store, room_id, *policy));
    return strict_pl_id;
}

[[nodiscard]] auto get_missing_events_response(std::string const& event_json) -> std::string
{
    auto const parsed = merovingian::canonicaljson::parse_lossless(event_json);
    REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);

    auto events = merovingian::canonicaljson::Array{};
    events.push_back(parsed.value);
    auto obj = merovingian::canonicaljson::Object{};
    obj.push_back(
        merovingian::canonicaljson::make_member("events", merovingian::canonicaljson::Value{std::move(events)}));

    auto const serialized =
        merovingian::canonicaljson::serialize_canonical(merovingian::canonicaljson::Value{std::move(obj)});
    REQUIRE(serialized.error == merovingian::canonicaljson::CanonicalJsonError::none);
    return serialized.output;
}

// Reads a full HTTP/1.1 request (headers + Content-Length body) from a TLS
// connection so the mock can receive a POST body before responding. The generic
// helpers in tls_mock_server.hpp stop at the header terminator, which is fine
// for GETs but risks a POST client seeing the response before its body is read.
[[nodiscard]] auto read_full_http_request(merovingian::homeserver::TlsConnection& connection) -> std::string
{
    auto buffer = std::array<char, 8192>{};
    auto request = std::string{};
    while (request.find("\r\n\r\n") == std::string::npos)
    {
        auto const n = connection.read(buffer.data(), buffer.size());
        if (n <= 0)
        {
            break;
        }
        request.append(buffer.data(), static_cast<std::size_t>(n));
    }
    auto const header_end = request.find("\r\n\r\n");
    if (header_end == std::string::npos)
    {
        return request;
    }
    auto const content_length_pos = request.find("Content-Length: ");
    if (content_length_pos == std::string::npos)
    {
        return request;
    }
    auto const value_start = content_length_pos + std::string{"Content-Length: "}.size();
    auto const value_end = request.find("\r\n", value_start);
    if (value_end == std::string::npos)
    {
        return request;
    }
    auto length = std::size_t{0U};
    auto const length_text = std::string_view{request}.substr(value_start, value_end - value_start);
    for (auto const ch : length_text)
    {
        if (ch < '0' || ch > '9')
        {
            break;
        }
        length = (length * 10U) + static_cast<std::size_t>(ch - '0');
    }
    auto const body_start = header_end + 4U;
    while (request.size() < body_start + length)
    {
        auto const n = connection.read(buffer.data(), buffer.size());
        if (n <= 0)
        {
            break;
        }
        request.append(buffer.data(), static_cast<std::size_t>(n));
    }
    return request;
}

inline auto run_body_aware_tls_server(merovingian::net::TcpAcceptor& acceptor,
                                      merovingian::homeserver::TlsServerContext& tls_context,
                                      std::string const& http_response,
                                      std::string* captured_request = nullptr) noexcept -> void
{
    auto const client_fd = merovingian::tests::tls_mock::accept_loopback(acceptor, 5000);
    if (client_fd < 0)
    {
        return;
    }
    // Owns the accepted descriptor: TlsConnection only borrows it, so without
    // this every served connection stayed open for the rest of the run.
    auto const owned_client_fd = merovingian::core::SocketHandle{client_fd};
    auto tls_result = merovingian::homeserver::accept_tls_connection(tls_context, client_fd, 5000);
    if (!tls_result.connection.has_value())
    {
        return;
    }
    auto& connection = *tls_result.connection;
    auto const request = read_full_http_request(connection);
    if (captured_request != nullptr)
    {
        *captured_request = request;
    }
    std::ignore = connection.write(http_response);
}

// Multi-request body-aware TLS server. Dispatches each received request to the
// first unused response whose path substring appears in the request bytes. This
// variant reads the full request (headers + Content-Length body) so POSTs such
// as /get_missing_events are handled correctly.
inline auto run_body_aware_dispatch_tls_server(merovingian::net::TcpAcceptor& acceptor,
                                               merovingian::homeserver::TlsServerContext& tls_context,
                                               std::vector<std::pair<std::string, std::string>> const& path_responses,
                                               std::vector<std::string>* captured_requests = nullptr) noexcept -> void
{
    auto served = std::vector<bool>(path_responses.size(), false);
    for (auto iteration = std::size_t{0U}; iteration < path_responses.size(); ++iteration)
    {
        auto const client_fd = merovingian::tests::tls_mock::accept_loopback(acceptor, 10000);
        if (client_fd < 0)
        {
            return;
        }
        // Owns the accepted descriptor: TlsConnection only borrows it, so without
        // this every served connection stayed open for the rest of the run.
        auto const owned_client_fd = merovingian::core::SocketHandle{client_fd};
        auto tls_result = merovingian::homeserver::accept_tls_connection(tls_context, client_fd, 5000);
        if (!tls_result.connection.has_value())
        {
            continue;
        }
        auto& connection = *tls_result.connection;
        auto const request = read_full_http_request(connection);
        if (captured_requests != nullptr)
        {
            captured_requests->push_back(request);
        }
        auto chosen = path_responses.size();
        for (auto index = std::size_t{0U}; index < path_responses.size(); ++index)
        {
            if (!served[index] && request.find(path_responses[index].first) != std::string::npos)
            {
                chosen = index;
                break;
            }
        }
        if (chosen == path_responses.size())
        {
            for (auto index = std::size_t{0U}; index < path_responses.size(); ++index)
            {
                if (!served[index])
                {
                    chosen = index;
                    break;
                }
            }
        }
        if (chosen == path_responses.size())
        {
            std::ignore = connection.write(path_responses.front().second);
            continue;
        }
        served[chosen] = true;
        std::ignore = connection.write(path_responses[chosen].second);
    }
}

[[nodiscard]] auto make_empty_get_missing_events_response() -> std::string
{
    auto obj = canonicaljson::Object{};
    obj.push_back(canonicaljson::make_member("events", canonicaljson::Value{canonicaljson::Array{}}));
    auto const serialized = canonicaljson::serialize_canonical(canonicaljson::Value{std::move(obj)});
    REQUIRE(serialized.error == canonicaljson::CanonicalJsonError::none);
    return serialized.output;
}

[[nodiscard]] auto make_state_ids_response(std::vector<std::string> const& pdu_ids,
                                           std::vector<std::string> const& auth_chain_ids) -> std::string
{
    auto pdu_array = canonicaljson::Array{};
    for (auto const& id : pdu_ids)
    {
        pdu_array.push_back(canonicaljson::Value{id});
    }
    auto auth_array = canonicaljson::Array{};
    for (auto const& id : auth_chain_ids)
    {
        auth_array.push_back(canonicaljson::Value{id});
    }
    auto obj = canonicaljson::Object{};
    obj.push_back(canonicaljson::make_member("auth_chain_ids", canonicaljson::Value{std::move(auth_array)}));
    obj.push_back(canonicaljson::make_member("pdu_ids", canonicaljson::Value{std::move(pdu_array)}));
    auto const serialized = canonicaljson::serialize_canonical(canonicaljson::Value{std::move(obj)});
    REQUIRE(serialized.error == canonicaljson::CanonicalJsonError::none);
    return serialized.output;
}

[[nodiscard]] auto make_event_transaction_response(std::string const& event_json, std::string const& origin)
    -> std::string
{
    auto parsed = merovingian::canonicaljson::parse_lossless(event_json);
    REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
    auto pdus = merovingian::canonicaljson::Array{};
    pdus.push_back(std::move(parsed.value));
    auto obj = merovingian::canonicaljson::Object{};
    obj.push_back(merovingian::canonicaljson::make_member("origin", merovingian::canonicaljson::Value{origin}));
    obj.push_back(merovingian::canonicaljson::make_member("origin_server_ts",
                                                          merovingian::canonicaljson::Value{std::int64_t{0}}));
    obj.push_back(merovingian::canonicaljson::make_member("pdus", merovingian::canonicaljson::Value{std::move(pdus)}));
    auto const serialized =
        merovingian::canonicaljson::serialize_canonical(merovingian::canonicaljson::Value{std::move(obj)});
    REQUIRE(serialized.error == merovingian::canonicaljson::CanonicalJsonError::none);
    return serialized.output;
}

// Spec: GET /_matrix/federation/v1/event_auth/{roomId}/{eventId}
// Returns the "auth_chain" array of PDUs on success.
[[nodiscard]] auto make_event_auth_response(std::vector<std::string> const& event_jsons) -> std::string
{
    auto auth_chain = merovingian::canonicaljson::Array{};
    for (auto const& json : event_jsons)
    {
        auto parsed = merovingian::canonicaljson::parse_lossless(json);
        REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
        auth_chain.push_back(std::move(parsed.value));
    }
    auto obj = merovingian::canonicaljson::Object{};
    obj.push_back(merovingian::canonicaljson::make_member("auth_chain",
                                                          merovingian::canonicaljson::Value{std::move(auth_chain)}));
    auto const serialized =
        merovingian::canonicaljson::serialize_canonical(merovingian::canonicaljson::Value{std::move(obj)});
    REQUIRE(serialized.error == merovingian::canonicaljson::CanonicalJsonError::none);
    return serialized.output;
}

// These regressions observe the wired durable cache provider, not just the raw
// resolver (which admission would suppress even if recovery kept attempting it).
class BackfillAdmissionObservation final
{
public:
    explicit BackfillAdmissionObservation(HomeserverRuntime& runtime)
        : runtime_{runtime}
        , cache_lookup_{runtime.federation.cached_pdu_key_lookup}
        , released_{release_.get_future().share()}
    {
        runtime_.federation.cached_pdu_key_lookup = [this](std::string_view server, std::string_view id) {
            if (server == remote_server)
                cache_attempts.emplace_back(id);
            return cache_lookup_(server, id);
        };
        runtime_.federation.remote_key_resolver =
            [this](std::string_view server, std::string_view id) -> std::optional<federation::FederationRemoteRuntime> {
            if (server == foreign_server && id == remote_key_id)
            {
                entered_.set_value();
                // Even a broken cleanup cannot leave a test worker blocked forever.
                if (released_.wait_for(std::chrono::seconds{10}) != std::future_status::ready)
                    return std::nullopt;
                auto remote = remote_runtime();
                remote.server_name = foreign_server;
                remote.signing_key.server_name = foreign_server;
                return remote;
            }
            ++raw_calls;
            if (server == remote_server && id == remote_key_id)
                return remote_runtime();
            return std::nullopt;
        };
    }

    ~BackfillAdmissionObservation()
    {
        release_foreign();
        runtime_.federation.cached_pdu_key_lookup = cache_lookup_;
        runtime_.federation.remote_key_resolver = {};
    }
    BackfillAdmissionObservation(BackfillAdmissionObservation const&) = delete;
    auto operator=(BackfillAdmissionObservation const&) -> BackfillAdmissionObservation& = delete;

    [[nodiscard]] auto hold_foreign() -> bool
    {
        auto entered = entered_.get_future();
        // std::thread, not std::jthread: FreeBSD and OpenBSD libc++ lack jthread.
        // release_foreign() releases the held resolution, then joins.
        foreign_ = std::thread{[this] {
            foreign_result_ = federation::resolve_verification_key(runtime_.federation, "foreign-source",
                                                                   foreign_server, remote_key_id);
        }};
        return entered.wait_for(std::chrono::seconds{2}) == std::future_status::ready;
    }

    auto release_foreign() -> void
    {
        if (foreign_.joinable())
        {
            release_.set_value();
            foreign_.join();
        }
    }

    [[nodiscard]] auto foreign_succeeded() const -> bool
    {
        return foreign_result_.has_value() && foreign_result_->key.has_value() && !foreign_result_->locally_denied;
    }

    std::vector<std::string> cache_attempts{};
    std::size_t raw_calls{};

private:
    static constexpr auto foreign_server = "held.example.org";
    HomeserverRuntime& runtime_;
    decltype(federation::FederationRuntimeState::cached_pdu_key_lookup) cache_lookup_;
    std::promise<void> release_{};
    std::promise<void> entered_{};
    std::shared_future<void> released_;
    std::optional<federation::VerificationKeyResolution> foreign_result_{};
    std::thread foreign_{};
};

// Keep a live peer available until ingestion finishes. Unexpected fallback
// requests get a bounded 404 and are counted, rather than hanging in connect
// or being hidden by a one-response server that has already exited.
[[nodiscard]] auto ingest_with_bounded_backfill_peer(HomeserverRuntime& runtime, InboundPduEnvelope const& pdu,
                                                     net::TcpAcceptor& acceptor,
                                                     homeserver::TlsServerContext& tls_context,
                                                     std::string const& response,
                                                     std::vector<std::string>& request_lines)
    -> federation::PduIngestionResult
{
    auto const not_found = tests::tls_mock::json_http_response("404 Not Found", R"({"errcode":"M_NOT_FOUND"})");
    // std::thread with a stop flag, not std::jthread: FreeBSD and OpenBSD libc++
    // lack jthread. The guard stops and joins the peer however ingestion ends.
    auto stop = std::atomic<bool>{false};
    auto server = std::thread{[&] {
        for (auto served = 0U; served < 16U && !stop.load();)
        {
            auto const fd = tests::tls_mock::accept_loopback(acceptor, 100);
            if (fd < 0)
                continue;
            auto const owned_fd = core::SocketHandle{fd};
            auto tls = homeserver::accept_tls_connection(tls_context, fd, 1000);
            if (!tls.connection.has_value())
                continue;
            auto& connection = *tls.connection;
            auto const request = read_full_http_request(connection);
            auto const line = request.substr(0U, request.find("\r\n"));
            request_lines.push_back(line);
            ++served;
            auto const missing = line.starts_with("POST /_matrix/federation/v1/get_missing_events/");
            std::ignore = connection.write(missing ? response : not_found);
        }
    }};
    struct StopAndJoin final
    {
        StopAndJoin(std::atomic<bool>& stop_flag, std::thread& peer) noexcept
            : stop{stop_flag}
            , thread{peer}
        {
        }
        std::atomic<bool>& stop;
        std::thread& thread;
        StopAndJoin(StopAndJoin const&) = delete;
        auto operator=(StopAndJoin const&) -> StopAndJoin& = delete;
        StopAndJoin(StopAndJoin&&) = delete;
        auto operator=(StopAndJoin&&) -> StopAndJoin& = delete;
        ~StopAndJoin()
        {
            stop.store(true);
            if (thread.joinable())
            {
                thread.join();
            }
        }
    };
    auto const finish = StopAndJoin{stop, server};
    return homeserver::ingest_pdu_event(runtime, pdu);
}

[[nodiscard]] auto make_cache_signed_message_pdu(std::string const& room_id, std::vector<std::string> const& prev_ids,
                                                 std::vector<std::string> const& auth_ids, std::int64_t depth,
                                                 std::int64_t ts, std::string_view cache_key_id) -> InboundPduEnvelope
{
    auto parsed = canonicaljson::parse_lossless(make_remote_message_json(room_id, prev_ids, auth_ids, depth, ts));
    REQUIRE(parsed.error == canonicaljson::ParseError::none);
    auto object = std::get<canonicaljson::Object>(parsed.value.storage());
    std::erase_if(object, [](auto const& member) {
        return member.key == "hashes" || member.key == "signatures";
    });
    auto const unsigned_json = canonicaljson::serialize_canonical(canonicaljson::Value{std::move(object)});
    REQUIRE(unsigned_json.error == canonicaljson::CanonicalJsonError::none);
    // The same legitimate public key can be published under a second key ID.
    // The event really bears that ID; the cache is never a one-shot fake.
    auto const signed_json = federation::test::make_signed_event_json(unsigned_json.output, remote_server, cache_key_id,
                                                                      remote_key_seed, room_version);
    auto envelope = federation::parse_inbound_pdu_envelope(signed_json, room_version);
    REQUIRE(envelope.has_value());
    envelope->origin = remote_server;
    return *envelope;
}

auto exercise_sticky_backfill_denial(bool capacity_full, bool partial_progress) -> void
{
    // The certificate's RAII directory also owns SQLite and its sidecars; it
    // outlives the runtime and all verification/network threads on every exit.
    auto certificate = tests::tls_mock::write_test_tls_certificate("localhost");
    auto const path = certificate.directory / "backfill.sqlite";
    auto started = homeserver::start_runtime(config_with_sqlite(path));
    REQUIRE(started.started);
    auto& runtime = started.runtime;
    homeserver::wire_federation_callbacks(runtime);
    REQUIRE(static_cast<bool>(runtime.federation.cached_pdu_key_lookup));
    auto const room_id = std::string{"!backfill-sticky-progress:local.example.org"};
    seed_room_with_genesis_state_group(runtime, room_id);
    auto const auth_ids = std::vector<std::string>{room_id + ":create", room_id + ":pl", room_id + ":member:bob"};
    auto const cache_key_id = std::string{"ed25519:backfill-cached"};
    auto const public_key = remote_runtime().signing_key;
    REQUIRE(database::store_server_signing_key(runtime.database.persistent_store,
                                               {std::string{remote_server}, cache_key_id,
                                                events::matrix_base64_from_bytes(public_key.public_key_bytes),
                                                public_key.valid_until_ts}));
    auto const cached_key = runtime.federation.cached_pdu_key_lookup(remote_server, cache_key_id);
    REQUIRE(cached_key.has_value());
    REQUIRE_FALSE(runtime.federation.cached_pdu_key_lookup(remote_server, remote_key_id).has_value());
    auto const first =
        partial_progress ? make_cache_signed_message_pdu(room_id, {room_id + ":member"}, auth_ids, 4, 10, cache_key_id)
                         : make_remote_message_pdu(room_id, {room_id + ":member"}, auth_ids, 4, 10);
    auto const blocked = partial_progress
                             ? make_remote_message_pdu(room_id, {first.event_id}, auth_ids, 5, 11)
                             : make_cache_signed_message_pdu(room_id, {first.event_id}, auth_ids, 5, 11, cache_key_id);
    auto const later = make_cache_signed_message_pdu(room_id, {blocked.event_id}, auth_ids, 6, 12, cache_key_id);
    auto const pdu = make_remote_message_pdu(room_id, {later.event_id}, auth_ids, 7, 20);
    REQUIRE(first.event_id != blocked.event_id);
    REQUIRE(blocked.event_id != later.event_id);
    REQUIRE(later.event_id != pdu.event_id);
    for (auto const& event : {first, blocked, later, pdu})
    {
        auto const parsed = canonicaljson::parse_lossless(event.json);
        REQUIRE(parsed.error == canonicaljson::ParseError::none);
        REQUIRE(events::verify_pdu_content_hash(parsed.value));
        CHECK(federation::test::reference_hash_event_id(event.json, room_version) == event.event_id);
        auto const parsed_pdu = federation::parse_federation_pdu(event.json, [](std::string_view) {
            return std::string{room_version};
        });
        auto const key = (event.event_id == later.event_id ||
                          (partial_progress ? event.event_id == first.event_id : event.event_id == blocked.event_id))
                             ? *cached_key
                             : public_key;
        REQUIRE(federation::authorize_federation_pdu(parsed_pdu, remote_server, key).accepted);
    }
    runtime.federation.config.backfill.max_outbound_calls = 8U;
    runtime.federation.config.backfill.max_total_outbound_calls = 12U;
    runtime.federation.config.backfill.max_snapshot_outbound_calls = 4U;
    runtime.federation.config.backfill_timeout_seconds = 5U;
    runtime.federation.config.key_resolution_per_ip_rate = {1U, 3600U};
    runtime.federation.config.key_resolution_max_in_flight = 1U;
    runtime.federation.key_resolution_buckets.push_back(
        {"<unknown>", capacity_full ? 0U : 1U, std::chrono::steady_clock::now()});
    auto observation = BackfillAdmissionObservation{runtime};
    if (capacity_full)
        REQUIRE(observation.hold_foreign());
    REQUIRE(runtime.federation.key_resolutions_in_flight == (capacity_full ? 1U : 0U));
    auto tls = homeserver::make_tls_server_context(certificate.certificate_file, certificate.private_key_file);
    REQUIRE(tls.ok());
    auto tls_context = std::move(*tls.context);
    auto acceptor = net::TcpAcceptor{};
    REQUIRE(acceptor.bind("127.0.0.1", 0U).ok);
    runtime.test_forced_outbound_resolution[remote_server] = homeserver::TestOnlyForcedOutboundResolution{
        "localhost", acceptor.bound_port(), {"127.0.0.1"}, certificate.certificate_pem};
    auto returned_events = canonicaljson::Array{};
    // Deliberately reverse wire order: the real recovery depth ordering decides
    // which verification has already made progress when admission refuses work.
    for (auto const& event : {later, blocked, first})
        returned_events.push_back(canonicaljson::parse_lossless(event.json).value);
    auto body = canonicaljson::Object{};
    body.push_back(canonicaljson::make_member("events", canonicaljson::Value{std::move(returned_events)}));
    auto const serialized = canonicaljson::serialize_canonical(canonicaljson::Value{std::move(body)});
    REQUIRE(serialized.error == canonicaljson::CanonicalJsonError::none);
    auto const response = tests::tls_mock::json_http_response("200 OK", serialized.output);
    auto& store = runtime.database.persistent_store;
    auto const events_before = store.events.size();
    auto const groups_before = store.state_groups.size();
    auto const links_before = store.event_state_groups.size();
    auto const genesis_group = database::find_event_state_group(store, room_id + ":member");
    REQUIRE(genesis_group.has_value());
    auto const count_event = [](database::PersistentStore const& source, std::string const& id) {
        return std::ranges::count(source.events, id, &database::PersistentEvent::event_id);
    };
    auto const count_mapping = [](database::PersistentStore const& source, std::string const& id) {
        return std::ranges::count(source.event_state_groups, id, &database::PersistentEventStateGroup::event_id);
    };
    auto requests = std::vector<std::string>{};
    auto const denied = ingest_with_bounded_backfill_peer(runtime, pdu, acceptor, tls_context, response, requests);
    REQUIRE(denied.status == PduIngestionStatus::main_overloaded);
    CHECK(requests.size() == 1U);
    REQUIRE_FALSE(requests.empty());
    CHECK(requests.front().starts_with("POST /_matrix/federation/v1/get_missing_events/"));
    CHECK(runtime.federation.config.backfill.max_outbound_calls > requests.size());
    CHECK(runtime.federation.config.backfill.max_total_outbound_calls > requests.size());
    CHECK(observation.raw_calls == 0U);
    auto const expected_attempts = partial_progress ? std::vector<std::string>{cache_key_id, remote_key_id}
                                                    : std::vector<std::string>{remote_key_id};
    CHECK(observation.cache_attempts == expected_attempts);
    CHECK(runtime.federation.key_resolutions_in_flight == (capacity_full ? 1U : 0U));
    CHECK(runtime.federation.key_resolution_failures.empty());
    CHECK(store.events.size() == events_before + (partial_progress ? 1U : 0U));
    CHECK(store.state_groups.size() == groups_before);
    CHECK(store.event_state_groups.size() == links_before + (partial_progress ? 1U : 0U));
    for (auto const& event : {first, blocked, later, pdu})
    {
        auto const retained = partial_progress && event.event_id == first.event_id;
        CHECK(count_event(store, event.event_id) == (retained ? 1 : 0));
        CHECK(count_mapping(store, event.event_id) == (retained ? 1 : 0));
    }
    {
        auto disk = database::open_sqlite_persistent_store(path.string());
        REQUIRE(disk.ok);
        for (auto const& event : {first, blocked, later, pdu})
        {
            auto const retained = partial_progress && event.event_id == first.event_id;
            CHECK(count_event(disk.store, event.event_id) == (retained ? 1 : 0));
            CHECK(count_mapping(disk.store, event.event_id) == (retained ? 1 : 0));
        }
    }
    observation.release_foreign();
    if (capacity_full)
        CHECK(observation.foreign_succeeded());
    REQUIRE(runtime.federation.key_resolutions_in_flight == 0U);
    CHECK(runtime.federation.key_resolution_failures.empty());
    if (!partial_progress)
        return;
    auto const first_row = std::ranges::find(store.events, first.event_id, &database::PersistentEvent::event_id);
    REQUIRE(first_row != store.events.end());
    CHECK(first_row->status == "outlier");
    auto const first_ordering = first_row->stream_ordering;
    auto const first_group = database::find_event_state_group(store, first.event_id);
    CHECK(first_group == genesis_group);
    runtime.federation.key_resolution_buckets.clear();
    observation.cache_attempts.clear();
    requests.clear();
    // Resend the very same const envelope, including unchanged JSON/event ID.
    auto const retry = ingest_with_bounded_backfill_peer(runtime, pdu, acceptor, tls_context, response, requests);
    REQUIRE(retry.status == PduIngestionStatus::accepted);
    CHECK(requests.size() == 1U);
    CHECK(observation.raw_calls == 1U);
    CHECK(observation.cache_attempts == std::vector<std::string>{cache_key_id, remote_key_id, cache_key_id});
    CHECK(runtime.federation.key_resolutions_in_flight == 0U);
    CHECK(runtime.federation.key_resolution_failures.empty());
    CHECK(store.events.size() == events_before + 4U);
    // Messages preserve their parent's state: no new group is required, but
    // each event (including the already retained outlier) has one mapping.
    CHECK(store.state_groups.size() == groups_before);
    CHECK(store.event_state_groups.size() == links_before + 4U);
    CHECK(database::find_event_state_group(store, first.event_id) == first_group);
    auto const retained_first = std::ranges::find(store.events, first.event_id, &database::PersistentEvent::event_id);
    REQUIRE(retained_first != store.events.end());
    CHECK(retained_first->stream_ordering == first_ordering);
    CHECK(retained_first->status == "outlier");
    for (auto const& event : {first, blocked, later, pdu})
    {
        CHECK(count_event(store, event.event_id) == 1);
        CHECK(count_mapping(store, event.event_id) == 1);
        CHECK(database::find_event_state_group(store, event.event_id) == genesis_group);
    }
    requests.clear();
    observation.cache_attempts.clear();
    auto const duplicate = ingest_with_bounded_backfill_peer(runtime, pdu, acceptor, tls_context, response, requests);
    // This low-level persistence sink has no transaction replay dedup: an
    // already stored event fails its pre-check. Row/state idempotency, not a
    // second accepted result from that sink, is the regression contract here.
    CHECK(duplicate.status == PduIngestionStatus::internal_error);
    CHECK(requests.empty());
    CHECK(observation.cache_attempts.empty());
    CHECK(observation.raw_calls == 1U);
    CHECK(store.events.size() == events_before + 4U);
    CHECK(store.state_groups.size() == groups_before);
    CHECK(store.event_state_groups.size() == links_before + 4U);
    auto disk = database::open_sqlite_persistent_store(path.string());
    REQUIRE(disk.ok);
    for (auto const& event : {first, blocked, later, pdu})
    {
        CHECK(count_event(store, event.event_id) == 1);
        CHECK(count_mapping(store, event.event_id) == 1);
        CHECK(count_event(disk.store, event.event_id) == 1);
        CHECK(count_mapping(disk.store, event.event_id) == 1);
        CHECK(database::find_event_state_group(disk.store, event.event_id) == genesis_group);
    }
    CHECK(disk.store.state_groups.size() == groups_before);
}

// --- EVT-1: a restricted join's authorising server must have validly signed it
//
// Spec: docs/matrix-v1.19-spec/rooms/v10.md, auth rule 4.2.1: "If content has a
// join_authorised_via_users_server key: If the event is not validly signed by
// the homeserver of the user ID denoted by the key, reject." The rule applies
// whatever the room's join rule. The room below is restricted, so a join by a
// non-member also needs rule 4.3.5: the authorising user must be joined with
// invite power, which the auth rules can check only if every path selects that
// user's m.room.member event into the auth map ("Auth events selection").
// A genuine join is accepted and a structurally present but forged authorising
// signature is refused.

constexpr auto authorising_server = "authoriser.example.org";
constexpr auto authorising_user = "@dave:authoriser.example.org";
constexpr auto authorising_key_id = "ed25519:authoriser";
constexpr auto authorising_key_seed = "backfill-authorising-server-seed";
constexpr auto attacker_key_seed = "backfill-attacker-seed";
constexpr auto joiner = "@carol:remote.example.org";

enum class AuthorisingSignature
{
    genuine,
    signed_by_wrong_key,
    garbage
};

// The authorising server's genuine published signing key.
[[nodiscard]] auto authorising_runtime() -> federation::FederationRemoteRuntime
{
    auto remote = remote_runtime();
    remote.server_name = authorising_server;
    remote.signing_key = {authorising_server, authorising_key_id, 4'102'444'800'000U,
                          federation::test::keypair_from_seed(authorising_key_seed).public_key};
    remote.discovery.server_name = authorising_server;
    return remote;
}

// A remote_key_resolver that knows the sending server's and the authorising
// server's genuine keys, and nothing else.
[[nodiscard]] auto both_servers_key_resolver()
{
    return [](std::string_view server_name,
              std::string_view key_id) -> std::optional<federation::FederationRemoteRuntime> {
        if (server_name == authorising_server && key_id == authorising_key_id)
        {
            return authorising_runtime();
        }
        return genuine_key_resolver()(server_name, key_id);
    };
}

// The status of a stored event, or nullopt when it is not stored at all.
[[nodiscard]] auto stored_status(HomeserverRuntime const& runtime, std::string_view event_id)
    -> std::optional<std::string>
{
    auto const& stored = runtime.database.persistent_store.events;
    auto const it = std::ranges::find_if(stored, [&](database::PersistentEvent const& e) {
        return e.event_id == event_id;
    });
    return it == stored.end() ? std::nullopt : std::optional<std::string>{it->status};
}

// The room's genesis (seed_room_with_genesis_state_group) plus a restricted
// m.room.join_rules event and the authorising user's join (default invite
// power), in both the room's current state and the state group the genesis
// events map to, so a join whose prev_event is the admin's join sees them.
auto seed_authorising_user(HomeserverRuntime& runtime, std::string const& room_id) -> void
{
    auto& store = runtime.database.persistent_store;
    auto const join_rules_id = room_id + ":join_rules";
    auto const authoriser_id = room_id + ":member:authoriser";
    auto const state_event_json = [&](std::string_view type, std::string_view state_key, std::string_view sender,
                                      std::string_view content, std::int64_t depth, std::string_view event_id) {
        return std::string{R"({"auth_events":[],"content":)"} + std::string{content} + R"(,"depth":)" +
               std::to_string(depth) + R"(,"event_id":")" + std::string{event_id} +
               R"(","hashes":{"sha256":"hash"},"origin_server_ts":)" + std::to_string(depth) +
               R"(,"prev_events":[],"room_id":")" + room_id + R"(","sender":")" + std::string{sender} +
               R"(","state_key":")" + std::string{state_key} + R"(","type":")" + std::string{type} + R"("})";
    };
    store.events.push_back(
        {join_rules_id, room_id, local_admin,
         state_event_json(
             "m.room.join_rules", "", local_admin,
             R"({"join_rule":"restricted","allow":[{"type":"m.room_membership","room_id":"!allowed:example.org"}]})", 4,
             join_rules_id),
         4U, 0U, std::vector<std::string>{}, std::vector<std::string>{}, std::vector<events::EventSignature>{}});
    store.state.push_back({room_id, "m.room.join_rules", "", join_rules_id});
    store.events.push_back({authoriser_id, room_id, authorising_user,
                            state_event_json("m.room.member", authorising_user, authorising_user,
                                             R"({"membership":"join"})", 5, authoriser_id),
                            5U, 0U, std::vector<std::string>{}, std::vector<std::string>{},
                            std::vector<events::EventSignature>{}});
    store.state.push_back({room_id, "m.room.member", authorising_user, authoriser_id});
    store.memberships.push_back({room_id, authorising_user, "join", 0U});

    auto const genesis_group = database::find_event_state_group(store, room_id + ":member");
    REQUIRE(genesis_group.has_value());
    auto const full_state = std::vector<database::PersistentStateGroupStateEntry>{
        {"", "m.room.create",       "",               room_id + ":create"    },
        {"", "m.room.power_levels", "",               room_id + ":pl"        },
        {"", "m.room.member",       local_admin,      room_id + ":member"    },
        {"", "m.room.member",       remote_member,    room_id + ":member:bob"},
        {"", "m.room.join_rules",   "",               join_rules_id          },
        {"", "m.room.member",       authorising_user, authoriser_id          },
    };
    auto const group =
        database::create_or_reuse_state_group(store, room_id, room_id + ":authoriser-group", genesis_group, full_state);
    REQUIRE(group.has_value());
    for (auto const& event_id : std::vector<std::string>{room_id + ":create", room_id + ":pl", room_id + ":member",
                                                         room_id + ":member:bob", join_rules_id, authoriser_id})
    {
        REQUIRE(database::set_event_state_group(store, event_id, *group));
    }
}

// Adds an entry under signatures[authorising_server] to an event that is
// already signed by its sender's server. `genuine` is a valid signature;
// `signed_by_wrong_key` is a well-formed signature made with another key;
// `garbage` is a non-empty, well-formed base64 value that signs nothing.
// The event ID (a reference hash) does not cover signatures, so all three
// variants of one event share it.
[[nodiscard]] auto with_authorising_signature(std::string const& sender_signed_json, AuthorisingSignature kind)
    -> std::string
{
    auto const parsed = canonicaljson::parse_lossless(sender_signed_json);
    REQUIRE(parsed.error == canonicaljson::ParseError::none);
    if (kind == AuthorisingSignature::garbage)
    {
        auto const serialized = canonicaljson::serialize_canonical(parsed.value);
        REQUIRE(serialized.error == canonicaljson::CanonicalJsonError::none);
        auto text = serialized.output;
        auto const marker = std::string_view{R"("signatures":{)"};
        auto const at = text.find(marker);
        REQUIRE(at != std::string::npos);
        text.insert(at + marker.size(), std::string{"\""} + authorising_server + "\":{\"" + authorising_key_id +
                                            "\":\"" + std::string(86U, 'A') + "\"},");
        return text;
    }
    auto const* policy = rooms::find_room_version_policy(room_version);
    REQUIRE(policy != nullptr);
    auto const key_seed = kind == AuthorisingSignature::genuine ? std::string_view{authorising_key_seed}
                                                                : std::string_view{attacker_key_seed};
    auto store = federation::test::TestSigningKeyStore{
        crypto::SigningKeyRecord{authorising_server, authorising_key_id,
                                 crypto::Ed25519PublicKey{federation::test::keypair_from_seed(key_seed).public_key},
                                 true}
    };
    auto provider = federation::test::TestEd25519Provider{std::string{key_seed}};
    auto const signed_event = events::sign_event_for_server(parsed.value, *policy, store, provider, authorising_server);
    REQUIRE(signed_event.error.empty());
    return signed_event.event_json;
}

// A join by a user of the sending server, naming the authorising user. The
// sender's server's signature is always genuine; `kind` is the authorising
// server's.
[[nodiscard]] auto authorised_join_json(std::string const& room_id, AuthorisingSignature kind) -> std::string
{
    auto content = canonicaljson::Object{};
    content.push_back(canonicaljson::make_member("membership", canonicaljson::Value{std::string{"join"}}));
    content.push_back(canonicaljson::make_member("join_authorised_via_users_server",
                                                 canonicaljson::Value{std::string{authorising_user}}));
    auto const auth_event_ids = std::vector<std::string>{room_id + ":create", room_id + ":pl", room_id + ":join_rules",
                                                         room_id + ":member:authoriser"};
    return with_authorising_signature(make_remote_event_json(room_id, "m.room.member", std::string{joiner}, joiner,
                                                             std::move(content), {room_id + ":member"}, auth_event_ids,
                                                             6, 70),
                                      kind);
}

} // namespace

SCENARIO("ingest_pdu_event backfills a missing prev_event from the sending server and accepts the PDU",
         "[pdu_ingestion][backfill]")
{
    GIVEN("a fresh runtime seeded with a room genesis state group")
    {
        auto const path = unique_sqlite_path();
        std::filesystem::remove(path);
        auto started = merovingian::homeserver::start_runtime(config_with_sqlite(path));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        merovingian::homeserver::wire_federation_callbacks(runtime);
        auto const room_id = std::string{"!backfill:local.example.org"};
        seed_room_with_genesis_state_group(runtime, room_id);

        auto const create_id = room_id + ":create";
        auto const pl_id = room_id + ":pl";
        auto const member_id = room_id + ":member";
        auto const member_bob_id = room_id + ":member:bob";
        auto const auth_event_ids = std::vector<std::string>{create_id, pl_id, member_bob_id};

        auto const missing_event = make_remote_message_pdu(room_id, {member_id}, auth_event_ids, 3, 10);
        auto const missing_event_id = missing_event.event_id;

        auto const pdu = make_remote_message_pdu(room_id, {missing_event_id}, auth_event_ids, 4, 20);

        AND_GIVEN("a mock sending server that returns the missing event on /get_missing_events")
        {
            auto certificate = merovingian::tests::tls_mock::write_test_tls_certificate("localhost");
            auto tls_context_result = merovingian::homeserver::make_tls_server_context(certificate.certificate_file,
                                                                                       certificate.private_key_file);
            REQUIRE(tls_context_result.ok());
            auto tls_context = std::move(*tls_context_result.context);
            auto acceptor = merovingian::net::TcpAcceptor{};
            REQUIRE(acceptor.bind("127.0.0.1", 0U).ok);
            auto const port = acceptor.bound_port();
            REQUIRE(port > 0U);

            runtime.test_forced_outbound_resolution[remote_server] =
                merovingian::homeserver::TestOnlyForcedOutboundResolution{
                    "localhost", port, {"127.0.0.1"}, certificate.certificate_pem};

            runtime.federation.remote_key_resolver =
                [](std::string_view server_name,
                   std::string_view key_id) -> std::optional<merovingian::federation::FederationRemoteRuntime> {
                if (server_name != remote_server || key_id != remote_key_id)
                {
                    return std::nullopt;
                }
                return remote_runtime();
            };

            auto captured_request = std::string{};
            auto const response_body = get_missing_events_response(missing_event.json);
            auto const http_response = merovingian::tests::tls_mock::json_http_response("200 OK", response_body);
            auto server_thread = std::thread{[&]() {
                run_body_aware_tls_server(acceptor, tls_context, http_response, &captured_request);
            }};
            auto const join_server = merovingian::tests::tls_mock::ScopedThreadJoin{server_thread};
            std::ignore = join_server;

            WHEN("the PDU is ingested")
            {
                auto const result = merovingian::homeserver::ingest_pdu_event(runtime, pdu);

                THEN("the PDU is accepted")
                {
                    REQUIRE(result.status == PduIngestionStatus::accepted);
                }

                THEN("the missing prev_event is stored as an outlier with a state group")
                {
                    auto const* event = [&]() -> merovingian::database::PersistentEvent const* {
                        for (auto const& e : runtime.database.persistent_store.events)
                        {
                            if (e.event_id == missing_event_id)
                            {
                                return &e;
                            }
                        }
                        return nullptr;
                    }();
                    REQUIRE(event != nullptr);
                    REQUIRE(event->status == "outlier");
                    REQUIRE(merovingian::database::find_event_state_group(runtime.database.persistent_store,
                                                                          missing_event_id)
                                .has_value());
                }

                THEN("the mock server received exactly one /get_missing_events request")
                {
                    REQUIRE(captured_request.find("POST /_matrix/federation/v1/get_missing_events/") !=
                            std::string::npos);
                }
            }

            std::filesystem::remove(path);
        }
    }
}

// Spec: Matrix Server-Server API v1.19
// Endpoint / Section: Checks performed on receipt of a PDU, step 5
// URL: ../../docs/matrix-v1.19-spec/server-server-api.md#checks-performed-on-receipt-of-a-pdu
//
// "Passes authorisation rules based on the state before the event, otherwise
// it is rejected." A backfilled event (fetched as a missing prev_event) must
// run the same step-5 check as a directly received PDU. If it passes its own
// auth_events but fails against the state before it, it must be stored as
// rejected and its after-state must exclude the event, so later PDUs that
// reference it do not see its state.
SCENARIO("Backfill verification obeys shared key admission and retries local denial",
         "[pdu_ingestion][backfill][fed10][fed10-backfill-admission]")
{
    GIVEN("a signed missing predecessor returned over real loopback TLS")
    {
        WHEN("its verification key is cold or cached while main admission is exhausted")
        {
            THEN("cold work is deferred without persistence and cache-only work remains available")
            {
                for (auto const mode : {0U, 1U, 2U, 3U})
                {
                    CAPTURE(mode);
                    auto const cached = mode >= 2U;
                    auto const capacity_full = mode == 0U || mode == 2U;
                    auto const path = unique_sqlite_path();
                    std::filesystem::remove(path);
                    auto started = merovingian::homeserver::start_runtime(config_with_sqlite(path));
                    REQUIRE(started.started);
                    auto& runtime = started.runtime;
                    merovingian::homeserver::wire_federation_callbacks(runtime);
                    auto const room_id = std::string{"!backfill-admission:local.example.org"};
                    seed_room_with_genesis_state_group(runtime, room_id);
                    auto const auth_ids =
                        std::vector<std::string>{room_id + ":create", room_id + ":pl", room_id + ":member:bob"};
                    auto const predecessor = make_remote_message_pdu(room_id, {room_id + ":member"}, auth_ids, 3, 10);
                    auto const pdu = make_remote_message_pdu(room_id, {predecessor.event_id}, auth_ids, 4, 20);
                    runtime.federation.config.backfill.max_outbound_calls = 1U;
                    runtime.federation.config.key_resolution_per_ip_rate = {1U, 3600U};
                    runtime.federation.config.key_resolution_max_in_flight = 1U;
                    runtime.federation.key_resolution_buckets.push_back(
                        {"<unknown>", capacity_full ? 0U : 1U, std::chrono::steady_clock::now()});
                    runtime.federation.key_resolutions_in_flight = capacity_full ? 1U : 0U;
                    auto raw_calls = std::size_t{};
                    runtime.federation.remote_key_resolver = [&raw_calls](std::string_view server, std::string_view id)
                        -> std::optional<merovingian::federation::FederationRemoteRuntime> {
                        ++raw_calls;
                        if (server == remote_server && id == remote_key_id)
                            return remote_runtime();
                        return std::nullopt;
                    };
                    runtime.federation.cached_pdu_key_lookup =
                        [cached](std::string_view server,
                                 std::string_view id) -> std::optional<merovingian::federation::FederationKeyRecord> {
                        if (cached && server == remote_server && id == remote_key_id)
                            return remote_runtime().signing_key;
                        return std::nullopt;
                    };
                    if (mode == 3U)
                        runtime.federation.remote_key_resolver = {};
                    auto certificate = merovingian::tests::tls_mock::write_test_tls_certificate("localhost");
                    auto tls = merovingian::homeserver::make_tls_server_context(certificate.certificate_file,
                                                                                certificate.private_key_file);
                    REQUIRE(tls.ok());
                    auto tls_context = std::move(*tls.context);
                    auto acceptor = merovingian::net::TcpAcceptor{};
                    REQUIRE(acceptor.bind("127.0.0.1", 0U).ok);
                    runtime.test_forced_outbound_resolution[remote_server] =
                        merovingian::homeserver::TestOnlyForcedOutboundResolution{
                            "localhost", acceptor.bound_port(), {"127.0.0.1"}, certificate.certificate_pem};
                    auto const response = merovingian::tests::tls_mock::json_http_response(
                        "200 OK", get_missing_events_response(predecessor.json));
                    auto const perform = [&]() {
                        auto thread = std::thread{[&]() {
                            run_body_aware_tls_server(acceptor, tls_context, response);
                        }};
                        auto const joined = merovingian::tests::tls_mock::ScopedThreadJoin{thread};
                        std::ignore = joined;
                        return merovingian::homeserver::ingest_pdu_event(runtime, pdu);
                    };
                    auto const events_before = runtime.database.persistent_store.events.size();
                    auto const groups_before = runtime.database.persistent_store.state_groups.size();
                    auto const links_before = runtime.database.persistent_store.event_state_groups.size();
                    auto const result = perform();
                    CHECK(raw_calls == 0U);
                    CHECK(runtime.federation.key_resolutions_in_flight == (capacity_full ? 1U : 0U));
                    CHECK(runtime.federation.key_resolution_failures.empty());
                    if (cached)
                    {
                        CHECK(result.status == PduIngestionStatus::accepted);
                        CHECK(merovingian::database::find_event_state_group(runtime.database.persistent_store,
                                                                            predecessor.event_id)
                                  .has_value());
                    }
                    else
                    {
                        CHECK(result.status == PduIngestionStatus::main_overloaded);
                        CHECK(runtime.database.persistent_store.events.size() == events_before);
                        CHECK(runtime.database.persistent_store.state_groups.size() == groups_before);
                        CHECK(runtime.database.persistent_store.event_state_groups.size() == links_before);
                        runtime.federation.key_resolutions_in_flight = 0U;
                        runtime.federation.key_resolution_buckets.clear();
                        auto const retry = perform();
                        CHECK(retry.status == PduIngestionStatus::accepted);
                        CHECK(raw_calls == 1U);
                        CHECK(runtime.federation.key_resolutions_in_flight == 0U);
                        CHECK(merovingian::database::find_event_state_group(runtime.database.persistent_store,
                                                                            predecessor.event_id)
                                  .has_value());
                    }
                    std::filesystem::remove(path);
                }
            }
        }
    }
}

SCENARIO("Backfill local denial stops verification and HTTP with recovery capacity remaining",
         "[pdu_ingestion][backfill][fed10][fed10-backfill-sticky]")
{
    GIVEN("three genuinely signed missing events and a durable cache-verifiable later event")
    {
        WHEN("the first cold verification lookup encounters local admission denial")
        {
            THEN("quota-full and foreign-slot-full both stop all later work without failure caching or storage")
            {
                for (auto const capacity_full : {false, true})
                {
                    CAPTURE(capacity_full);
                    exercise_sticky_backfill_denial(capacity_full, false);
                }
            }
        }
    }
}

SCENARIO("Backfill retains earlier outlier progress across local denial and unchanged-PDU retries",
         "[pdu_ingestion][backfill][fed10][fed10-backfill-partial-progress]")
{
    GIVEN("a durable cached signing key for an earlier valid outlier and a cold key for its child")
    {
        WHEN("the later verification lookup encounters local admission denial")
        {
            THEN("quota-full and foreign-slot-full retain only earlier progress and retry without duplicate rows")
            {
                for (auto const capacity_full : {false, true})
                {
                    CAPTURE(capacity_full);
                    exercise_sticky_backfill_denial(capacity_full, true);
                }
            }
        }
    }
}

SCENARIO("A backfilled event passing its auth_events but failing state-before is stored rejected",
         "[pdu_ingestion][backfill][conformance]")
{
    GIVEN("a fresh runtime seeded with a permissive genesis and a strict power_levels tip")
    {
        auto const path = unique_sqlite_path();
        std::filesystem::remove(path);
        auto started = merovingian::homeserver::start_runtime(config_with_sqlite(path));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        merovingian::homeserver::wire_federation_callbacks(runtime);
        auto const room_id = std::string{"!backfill-state-before:local.example.org"};
        seed_room_with_genesis_state_group(runtime, room_id);
        auto const create_id = room_id + ":create";
        auto const pl_id = room_id + ":pl";
        auto const member_bob_id = room_id + ":member:bob";
        auto const strict_pl_id = seed_strict_power_levels(runtime, room_id, pl_id, member_bob_id);

        // Bob's topic names the old permissive power_levels in auth_events,
        // which is a permitted selection, but its prev_event is the strict tip,
        // so the state immediately before it requires power 100.
        auto topic_content = canonicaljson::Object{};
        topic_content.push_back(canonicaljson::make_member("topic", canonicaljson::Value{std::string{"forged topic"}}));
        auto const topic_pdu =
            make_remote_event_pdu(room_id, "m.room.topic", std::string{}, "@bob:remote.example.org",
                                  std::move(topic_content), {strict_pl_id}, {create_id, pl_id, member_bob_id}, 5, 10);
        auto const topic_id = topic_pdu.event_id;

        auto const followup_pdu =
            make_remote_message_pdu(room_id, {topic_id}, {create_id, strict_pl_id, member_bob_id}, 6, 20);

        AND_GIVEN("a mock sending server that returns the topic event on /get_missing_events")
        {
            auto certificate = merovingian::tests::tls_mock::write_test_tls_certificate("localhost");
            auto tls_context_result = merovingian::homeserver::make_tls_server_context(certificate.certificate_file,
                                                                                       certificate.private_key_file);
            REQUIRE(tls_context_result.ok());
            auto tls_context = std::move(*tls_context_result.context);
            auto acceptor = merovingian::net::TcpAcceptor{};
            REQUIRE(acceptor.bind("127.0.0.1", 0U).ok);
            auto const port = acceptor.bound_port();
            REQUIRE(port > 0U);

            runtime.test_forced_outbound_resolution[remote_server] =
                merovingian::homeserver::TestOnlyForcedOutboundResolution{
                    "localhost", port, {"127.0.0.1"}, certificate.certificate_pem};

            runtime.federation.remote_key_resolver =
                [](std::string_view server_name,
                   std::string_view key_id) -> std::optional<merovingian::federation::FederationRemoteRuntime> {
                if (server_name != remote_server || key_id != remote_key_id)
                {
                    return std::nullopt;
                }
                return remote_runtime();
            };

            auto const response_body = get_missing_events_response(topic_pdu.json);
            auto const http_response = merovingian::tests::tls_mock::json_http_response("200 OK", response_body);
            auto server_thread = std::thread{[&]() {
                run_body_aware_tls_server(acceptor, tls_context, http_response, nullptr);
            }};
            auto const join_server = merovingian::tests::tls_mock::ScopedThreadJoin{server_thread};
            std::ignore = join_server;

            WHEN("the follow-up PDU referencing the missing topic is ingested")
            {
                auto const result = merovingian::homeserver::ingest_pdu_event(runtime, followup_pdu);

                THEN("the follow-up PDU is accepted")
                {
                    REQUIRE(result.status == PduIngestionStatus::accepted);
                }

                THEN("the backfilled topic is stored, marked rejected")
                {
                    auto const* event = [&]() -> merovingian::database::PersistentEvent const* {
                        for (auto const& e : runtime.database.persistent_store.events)
                        {
                            if (e.event_id == topic_id)
                            {
                                return &e;
                            }
                        }
                        return nullptr;
                    }();
                    REQUIRE(event != nullptr);
                    REQUIRE(event->status == "rejected");
                }

                THEN("the rejected topic's after-state group excludes the topic")
                {
                    auto const group =
                        merovingian::database::find_event_state_group(runtime.database.persistent_store, topic_id);
                    REQUIRE(group.has_value());
                    auto const full_state =
                        merovingian::database::read_state_group_full_state(runtime.database.persistent_store, *group);
                    REQUIRE(full_state.has_value());
                    REQUIRE(std::ranges::none_of(*full_state,
                                                 [&](merovingian::database::PersistentStateGroupStateEntry const& e) {
                                                     return e.event_type == "m.room.topic";
                                                 }));
                }

                THEN("the follow-up PDU does not see the rejected topic in current state")
                {
                    auto const& state = runtime.database.persistent_store.state;
                    REQUIRE(std::ranges::none_of(state, [&](merovingian::database::PersistentStateEvent const& s) {
                        return s.room_id == room_id && s.event_type == "m.room.topic";
                    }));
                }
            }

            std::filesystem::remove(path);
        }
    }
}

// Spec: Matrix Server-Server API v1.19
// Endpoint / Section: Checks performed on receipt of a PDU, steps 4 and 5
// URL: ../../docs/matrix-v1.19-spec/server-server-api.md#checks-performed-on-receipt-of-a-pdu
//
// A backfilled event that passes both its own auth_events and the state before
// it is stored as an outlier whose after-state includes it, so it can supply
// state to later events that reference it.
SCENARIO("A backfilled state event passing auth_events and state-before is stored with its after-state",
         "[pdu_ingestion][backfill]")
{
    GIVEN("a fresh runtime seeded with a permissive genesis")
    {
        auto const path = unique_sqlite_path();
        std::filesystem::remove(path);
        auto started = merovingian::homeserver::start_runtime(config_with_sqlite(path));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        merovingian::homeserver::wire_federation_callbacks(runtime);

        auto const room_id = std::string{"!backfill-accepted-state:local.example.org"};
        seed_room_with_genesis_state_group(runtime, room_id);
        auto const create_id = room_id + ":create";
        auto const pl_id = room_id + ":pl";
        auto const member_bob_id = room_id + ":member:bob";

        auto topic_content = canonicaljson::Object{};
        topic_content.push_back(
            canonicaljson::make_member("topic", canonicaljson::Value{std::string{"backfilled topic"}}));
        auto const topic_pdu =
            make_remote_event_pdu(room_id, "m.room.topic", std::string{}, "@bob:remote.example.org",
                                  std::move(topic_content), {pl_id}, {create_id, pl_id, member_bob_id}, 4, 10);
        auto const topic_id = topic_pdu.event_id;

        auto const followup_pdu =
            make_remote_message_pdu(room_id, {topic_id}, {create_id, pl_id, member_bob_id}, 5, 20);

        AND_GIVEN("a mock sending server that returns the topic event on /get_missing_events")
        {
            auto certificate = merovingian::tests::tls_mock::write_test_tls_certificate("localhost");
            auto tls_context_result = merovingian::homeserver::make_tls_server_context(certificate.certificate_file,
                                                                                       certificate.private_key_file);
            REQUIRE(tls_context_result.ok());
            auto tls_context = std::move(*tls_context_result.context);
            auto acceptor = merovingian::net::TcpAcceptor{};
            REQUIRE(acceptor.bind("127.0.0.1", 0U).ok);
            auto const port = acceptor.bound_port();
            REQUIRE(port > 0U);

            runtime.test_forced_outbound_resolution[remote_server] =
                merovingian::homeserver::TestOnlyForcedOutboundResolution{
                    "localhost", port, {"127.0.0.1"}, certificate.certificate_pem};

            runtime.federation.remote_key_resolver =
                [](std::string_view server_name,
                   std::string_view key_id) -> std::optional<merovingian::federation::FederationRemoteRuntime> {
                if (server_name != remote_server || key_id != remote_key_id)
                {
                    return std::nullopt;
                }
                return remote_runtime();
            };

            auto const response_body = get_missing_events_response(topic_pdu.json);
            auto const http_response = merovingian::tests::tls_mock::json_http_response("200 OK", response_body);
            auto server_thread = std::thread{[&]() {
                run_body_aware_tls_server(acceptor, tls_context, http_response, nullptr);
            }};
            auto const join_server = merovingian::tests::tls_mock::ScopedThreadJoin{server_thread};
            std::ignore = join_server;

            WHEN("the follow-up PDU referencing the missing topic is ingested")
            {
                auto const result = merovingian::homeserver::ingest_pdu_event(runtime, followup_pdu);

                THEN("the follow-up PDU is accepted")
                {
                    REQUIRE(result.status == PduIngestionStatus::accepted);
                }

                THEN("the backfilled topic is stored as an outlier")
                {
                    auto const* event = [&]() -> merovingian::database::PersistentEvent const* {
                        for (auto const& e : runtime.database.persistent_store.events)
                        {
                            if (e.event_id == topic_id)
                            {
                                return &e;
                            }
                        }
                        return nullptr;
                    }();
                    REQUIRE(event != nullptr);
                    REQUIRE(event->status == "outlier");
                }

                THEN("the outlier's after-state group includes the topic")
                {
                    auto const group =
                        merovingian::database::find_event_state_group(runtime.database.persistent_store, topic_id);
                    REQUIRE(group.has_value());
                    auto const full_state =
                        merovingian::database::read_state_group_full_state(runtime.database.persistent_store, *group);
                    REQUIRE(full_state.has_value());
                    auto const topic_entry = std::ranges::find_if(
                        *full_state, [](merovingian::database::PersistentStateGroupStateEntry const& e) {
                            return e.event_type == "m.room.topic";
                        });
                    REQUIRE(topic_entry != full_state->end());
                    REQUIRE(topic_entry->event_id == topic_id);
                }
            }

            std::filesystem::remove(path);
        }
    }
}

// Spec: Matrix Server-Server API v1.19
// Endpoint / Section: Checks performed on receipt of a PDU, step 5
// URL: ../../docs/matrix-v1.19-spec/server-server-api.md#checks-performed-on-receipt-of-a-pdu
//
// A backfilled event is authorised against the state before it, which needs
// its prev_events stored first. The /get_missing_events response order is the
// remote's choice, so a child listed before its parent must still be stored
// once the parent is (0.12.13 audit item 9: results are handled by ascending
// depth, not response order).
SCENARIO("Backfill stores a /get_missing_events child that the remote lists before its parent",
         "[pdu_ingestion][backfill][backfill_depth_order]")
{
    GIVEN("a fresh runtime seeded with a room genesis state group")
    {
        auto const path = unique_sqlite_path();
        std::filesystem::remove(path);
        auto started = merovingian::homeserver::start_runtime(config_with_sqlite(path));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        merovingian::homeserver::wire_federation_callbacks(runtime);

        auto const room_id = std::string{"!backfill-depth-order:local.example.org"};
        seed_room_with_genesis_state_group(runtime, room_id);
        auto const create_id = room_id + ":create";
        auto const pl_id = room_id + ":pl";
        auto const member_id = room_id + ":member";
        auto const member_bob_id = room_id + ":member:bob";
        auto const auth_event_ids = std::vector<std::string>{create_id, pl_id, member_bob_id};

        auto const parent = make_remote_message_pdu(room_id, {member_id}, auth_event_ids, 3, 10);
        auto const child = make_remote_message_pdu(room_id, {parent.event_id}, auth_event_ids, 4, 11);
        auto const pdu = make_remote_message_pdu(room_id, {child.event_id}, auth_event_ids, 5, 20);

        AND_GIVEN("a sending server whose /get_missing_events lists the child first and serves nothing else")
        {
            auto certificate = merovingian::tests::tls_mock::write_test_tls_certificate("localhost");
            auto tls_context_result = merovingian::homeserver::make_tls_server_context(certificate.certificate_file,
                                                                                       certificate.private_key_file);
            REQUIRE(tls_context_result.ok());
            auto tls_context = std::move(*tls_context_result.context);
            auto acceptor = merovingian::net::TcpAcceptor{};
            REQUIRE(acceptor.bind("127.0.0.1", 0U).ok);
            auto const port = acceptor.bound_port();
            REQUIRE(port > 0U);

            runtime.test_forced_outbound_resolution[remote_server] =
                merovingian::homeserver::TestOnlyForcedOutboundResolution{
                    "localhost", port, {"127.0.0.1"}, certificate.certificate_pem};

            runtime.federation.remote_key_resolver =
                [](std::string_view server_name,
                   std::string_view key_id) -> std::optional<merovingian::federation::FederationRemoteRuntime> {
                if (server_name != remote_server || key_id != remote_key_id)
                {
                    return std::nullopt;
                }
                return remote_runtime();
            };

            auto events = canonicaljson::Array{};
            for (auto const* json : {&child.json, &parent.json})
            {
                auto parsed = canonicaljson::parse_lossless(*json);
                REQUIRE(parsed.error == canonicaljson::ParseError::none);
                events.push_back(std::move(parsed.value));
            }
            auto body = canonicaljson::Object{};
            body.push_back(canonicaljson::make_member("events", canonicaljson::Value{std::move(events)}));
            auto const serialized = canonicaljson::serialize_canonical(canonicaljson::Value{std::move(body)});
            REQUIRE(serialized.error == canonicaljson::CanonicalJsonError::none);

            auto const not_found = merovingian::tests::tls_mock::json_http_response(
                "404 Not Found", R"({"errcode":"M_NOT_FOUND","error":"not found"})");
            auto const responses = std::vector<std::pair<std::string, std::string>>{
                {"POST /_matrix/federation/v1/get_missing_events/",
                 merovingian::tests::tls_mock::json_http_response("200 OK", serialized.output)},
                {"GET /_matrix/federation/v1/event/", not_found},
                {"GET /_matrix/federation/v1/state_ids/", not_found},
            };
            auto server_thread = std::thread{[&]() {
                run_body_aware_dispatch_tls_server(acceptor, tls_context, responses, nullptr);
            }};
            auto const join_server = merovingian::tests::tls_mock::ScopedThreadJoin{server_thread};
            std::ignore = join_server;

            WHEN("a PDU building on the child is ingested")
            {
                auto const result = merovingian::homeserver::ingest_pdu_event(runtime, pdu);

                THEN("the PDU is accepted")
                {
                    REQUIRE(result.status == PduIngestionStatus::accepted);
                }

                THEN("both the parent and the child are stored with a state group")
                {
                    auto const& store = runtime.database.persistent_store;
                    REQUIRE(merovingian::database::find_event_state_group(store, parent.event_id).has_value());
                    REQUIRE(merovingian::database::find_event_state_group(store, child.event_id).has_value());
                }
            }

            std::filesystem::remove(path);
        }
    }
}

// Spec: Matrix Server-Server API v1.19
// Endpoint / Section: GET /_matrix/federation/v1/event/{eventId}
// URL: ../../docs/matrix-v1.19-spec/server-server-api.md#get_matrixfederationv1eventeventid
//
// "Retrieves a single event." The response is the origin's claim to be the
// requested event; an event with another ID answers a question nobody asked
// and must not be stored as if it did (it could be anything the origin wants
// pulled into this server's store).
SCENARIO("Backfill drops an /event/{eventId} response that is not the requested event",
         "[pdu_ingestion][backfill][event_id_mismatch]")
{
    GIVEN("a fresh runtime seeded with a room genesis state group")
    {
        auto const path = unique_sqlite_path();
        std::filesystem::remove(path);
        auto started = merovingian::homeserver::start_runtime(config_with_sqlite(path));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        merovingian::homeserver::wire_federation_callbacks(runtime);

        auto const room_id = std::string{"!backfill-event-id-mismatch:local.example.org"};
        seed_room_with_genesis_state_group(runtime, room_id);
        auto const create_id = room_id + ":create";
        auto const pl_id = room_id + ":pl";
        auto const member_id = room_id + ":member";
        auto const member_bob_id = room_id + ":member:bob";
        auto const auth_event_ids = std::vector<std::string>{create_id, pl_id, member_bob_id};

        auto const missing = make_remote_message_pdu(room_id, {member_id}, auth_event_ids, 3, 10);
        auto const substitute = make_remote_message_pdu(room_id, {member_id}, auth_event_ids, 3, 11);
        REQUIRE(substitute.event_id != missing.event_id);
        auto const pdu = make_remote_message_pdu(room_id, {missing.event_id}, auth_event_ids, 4, 20);

        AND_GIVEN("a sending server that answers /event/{missing} with a different, validly signed event")
        {
            auto certificate = merovingian::tests::tls_mock::write_test_tls_certificate("localhost");
            auto tls_context_result = merovingian::homeserver::make_tls_server_context(certificate.certificate_file,
                                                                                       certificate.private_key_file);
            REQUIRE(tls_context_result.ok());
            auto tls_context = std::move(*tls_context_result.context);
            auto acceptor = merovingian::net::TcpAcceptor{};
            REQUIRE(acceptor.bind("127.0.0.1", 0U).ok);
            auto const port = acceptor.bound_port();
            REQUIRE(port > 0U);

            runtime.test_forced_outbound_resolution[remote_server] =
                merovingian::homeserver::TestOnlyForcedOutboundResolution{
                    "localhost", port, {"127.0.0.1"}, certificate.certificate_pem};
            runtime.federation.remote_key_resolver = genuine_key_resolver();

            auto const not_found = merovingian::tests::tls_mock::json_http_response(
                "404 Not Found", R"({"errcode":"M_NOT_FOUND","error":"not found"})");
            auto const responses = std::vector<std::pair<std::string, std::string>>{
                {"POST /_matrix/federation/v1/get_missing_events/",
                 merovingian::tests::tls_mock::json_http_response("200 OK", make_empty_get_missing_events_response())},
                {"GET /_matrix/federation/v1/event/",
                 merovingian::tests::tls_mock::json_http_response(
                     "200 OK", make_event_transaction_response(substitute.json, std::string{remote_server}))},
                {"GET /_matrix/federation/v1/state_ids/", not_found},
            };
            auto server_thread = std::thread{[&]() {
                run_body_aware_dispatch_tls_server(acceptor, tls_context, responses, nullptr);
            }};
            auto const join_server = merovingian::tests::tls_mock::ScopedThreadJoin{server_thread};
            std::ignore = join_server;

            WHEN("a PDU naming the missing event is ingested")
            {
                auto const result = merovingian::homeserver::ingest_pdu_event(runtime, pdu);

                THEN("the substitute event is not stored")
                {
                    REQUIRE(std::ranges::none_of(runtime.database.persistent_store.events,
                                                 [&](merovingian::database::PersistentEvent const& e) {
                                                     return e.event_id == substitute.event_id;
                                                 }));
                }

                THEN("the PDU is not accepted, its prev_event still missing")
                {
                    REQUIRE(result.status != PduIngestionStatus::accepted);
                }
            }

            std::filesystem::remove(path);
        }
    }
}

// Spec: Matrix Server-Server API v1.19
// Endpoint / Section: Backfilling and retrieving missing events
// URL: ../../docs/matrix-v1.19-spec/server-server-api.md#backfilling-and-retrieving-missing-events
//
// When /get_missing_events cannot fill the gap, the server falls back to
// /state_ids to obtain the state at the missing prev_event, fetches and
// verifies the named state events, and stores the missing event with an
// after-state group derived from the verified snapshot.
SCENARIO("ingest_pdu_event falls back to /state_ids when /get_missing_events cannot fill the gap",
         "[pdu_ingestion][backfill][conformance]")
{
    GIVEN("a fresh runtime seeded with a room genesis state group")
    {
        auto const path = unique_sqlite_path();
        std::filesystem::remove(path);
        auto started = merovingian::homeserver::start_runtime(config_with_sqlite(path));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        merovingian::homeserver::wire_federation_callbacks(runtime);

        auto const room_id = std::string{"!backfill-state-ids:local.example.org"};
        // Exercise the exact boundary of a custom, tight policy.
        runtime.federation.config.backfill.max_state_ids = 3U;
        runtime.federation.config.backfill.max_auth_chain_ids = 3U;
        seed_room_with_genesis_state_group(runtime, room_id);

        auto const create_id = room_id + ":create";
        auto const pl_id = room_id + ":pl";
        auto const member_id = room_id + ":member";
        auto const member_bob_id = room_id + ":member:bob";
        auto const auth_event_ids = std::vector<std::string>{create_id, pl_id, member_bob_id};

        // `old` is missing, so `mid` cannot be verified through the normal
        // /event/{id} path. The /state_ids fallback supplies the state at `old`
        // directly from the verified genesis snapshot, `old` is stored against
        // it, and `mid` is placed on top.
        auto const old_event = make_remote_message_pdu(room_id, {member_bob_id}, auth_event_ids, 4, 10);
        auto const old_event_id = old_event.event_id;
        auto const mid_event = make_remote_message_pdu(room_id, {old_event_id}, auth_event_ids, 5, 11);
        auto const mid_event_id = mid_event.event_id;

        auto const pdu = make_remote_message_pdu(room_id, {mid_event_id}, auth_event_ids, 6, 20);

        AND_GIVEN("a mock sending server that returns /state_ids for the missing prev_event")
        {
            auto certificate = merovingian::tests::tls_mock::write_test_tls_certificate("localhost");
            auto tls_context_result = merovingian::homeserver::make_tls_server_context(certificate.certificate_file,
                                                                                       certificate.private_key_file);
            REQUIRE(tls_context_result.ok());
            auto tls_context = std::move(*tls_context_result.context);
            auto acceptor = merovingian::net::TcpAcceptor{};
            REQUIRE(acceptor.bind("127.0.0.1", 0U).ok);
            auto const port = acceptor.bound_port();
            REQUIRE(port > 0U);

            runtime.test_forced_outbound_resolution[remote_server] =
                merovingian::homeserver::TestOnlyForcedOutboundResolution{
                    "localhost", port, {"127.0.0.1"}, certificate.certificate_pem};

            runtime.federation.remote_key_resolver =
                [](std::string_view server_name,
                   std::string_view key_id) -> std::optional<merovingian::federation::FederationRemoteRuntime> {
                if (server_name != remote_server || key_id != remote_key_id)
                {
                    return std::nullopt;
                }
                return remote_runtime();
            };

            auto const state_ids_body = make_state_ids_response(auth_event_ids, auth_event_ids);
            auto const mid_event_body = make_event_transaction_response(mid_event.json, remote_server);
            auto const old_event_body = make_event_transaction_response(old_event.json, remote_server);
            // The first /event/{id} fetch gets `mid`, which cannot be stored
            // because its own prev_event (`old`) has no state group, so it is
            // held. The state is then asked at `old`, the event nothing in hand
            // supplies, and `old` is stored against the verified snapshot; then
            // `mid` is placed on top of it. Both fetches need a response.
            auto const path_responses = std::vector<std::pair<std::string, std::string>>{
                {"POST /_matrix/federation/v1/get_missing_events/",
                 merovingian::tests::tls_mock::json_http_response("200 OK", make_empty_get_missing_events_response())},
                {"GET /_matrix/federation/v1/state_ids/",
                 merovingian::tests::tls_mock::json_http_response("200 OK", state_ids_body)                          },
                {"GET /_matrix/federation/v1/event/",
                 merovingian::tests::tls_mock::json_http_response("200 OK", mid_event_body)                          },
                {"GET /_matrix/federation/v1/event/",
                 merovingian::tests::tls_mock::json_http_response("200 OK", old_event_body)                          },
            };
            auto captured_requests = std::vector<std::string>{};
            auto server_thread = std::thread{[&]() {
                run_body_aware_dispatch_tls_server(acceptor, tls_context, path_responses, &captured_requests);
            }};
            auto const join_server = merovingian::tests::tls_mock::ScopedThreadJoin{server_thread};
            std::ignore = join_server;

            WHEN("the PDU is ingested")
            {
                auto const result = merovingian::homeserver::ingest_pdu_event(runtime, pdu);

                THEN("the PDU is accepted")
                {
                    REQUIRE(result.status == PduIngestionStatus::accepted);
                }

                THEN("the backfilled prev_event is stored as an outlier with a state group")
                {
                    auto const* event = [&]() -> merovingian::database::PersistentEvent const* {
                        for (auto const& e : runtime.database.persistent_store.events)
                        {
                            if (e.event_id == mid_event_id)
                            {
                                return &e;
                            }
                        }
                        return nullptr;
                    }();
                    REQUIRE(event != nullptr);
                    REQUIRE(event->status == "outlier");
                    REQUIRE(
                        merovingian::database::find_event_state_group(runtime.database.persistent_store, mid_event_id)
                            .has_value());
                }

                THEN("all three fallback endpoints were called")
                {
                    auto has_get_missing = false;
                    auto has_state_ids = false;
                    auto has_event = false;
                    for (auto const& req : captured_requests)
                    {
                        if (req.find("POST /_matrix/federation/v1/get_missing_events/") != std::string::npos)
                        {
                            has_get_missing = true;
                        }
                        if (req.find("GET /_matrix/federation/v1/state_ids/") != std::string::npos)
                        {
                            has_state_ids = true;
                        }
                        if (req.find("GET /_matrix/federation/v1/event/") != std::string::npos)
                        {
                            has_event = true;
                        }
                    }
                    REQUIRE(has_get_missing);
                    REQUIRE(has_state_ids);
                    REQUIRE(has_event);
                }
            }

            std::filesystem::remove(path);
        }
    }
}

// Spec: Matrix Server-Server API v1.19
// Endpoint / Section: Backfilling and retrieving missing events
// URL: ../../docs/matrix-v1.19-spec/server-server-api.md#backfilling-and-retrieving-missing-events
//
// The aggregate per-PDU network budget applies across all recovery stages. The
// final permitted response must still be processed after its call is spent.
SCENARIO("ingest_pdu_event respects the shared total backfill call budget", "[pdu_ingestion][backfill][conformance]")
{
    GIVEN("a fresh runtime seeded with a room genesis state group")
    {
        auto const path = unique_sqlite_path();
        std::filesystem::remove(path);
        auto started = merovingian::homeserver::start_runtime(config_with_sqlite(path));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        merovingian::homeserver::wire_federation_callbacks(runtime);

        auto const room_id = std::string{"!backfill-total-budget:local.example.org"};
        runtime.federation.config.backfill.max_total_outbound_calls = 1U;
        seed_room_with_genesis_state_group(runtime, room_id);

        auto const create_id = room_id + ":create";
        auto const pl_id = room_id + ":pl";
        auto const member_bob_id = room_id + ":member:bob";
        auto const auth_event_ids = std::vector<std::string>{create_id, pl_id, member_bob_id};

        auto const old_event = make_remote_message_pdu(room_id, {member_bob_id}, auth_event_ids, 4, 10);
        auto const old_event_id = old_event.event_id;
        auto const mid_event = make_remote_message_pdu(room_id, {old_event_id}, auth_event_ids, 5, 11);
        auto const mid_event_id = mid_event.event_id;

        auto const pdu = make_remote_message_pdu(room_id, {mid_event_id}, auth_event_ids, 6, 20);

        AND_GIVEN("a mock sending server whose first response fills the missing chain")
        {
            auto certificate = merovingian::tests::tls_mock::write_test_tls_certificate("localhost");
            auto tls_context_result = merovingian::homeserver::make_tls_server_context(certificate.certificate_file,
                                                                                       certificate.private_key_file);
            REQUIRE(tls_context_result.ok());
            auto tls_context = std::move(*tls_context_result.context);
            auto acceptor = merovingian::net::TcpAcceptor{};
            REQUIRE(acceptor.bind("127.0.0.1", 0U).ok);
            auto const port = acceptor.bound_port();
            REQUIRE(port > 0U);

            runtime.test_forced_outbound_resolution[remote_server] =
                merovingian::homeserver::TestOnlyForcedOutboundResolution{
                    "localhost", port, {"127.0.0.1"}, certificate.certificate_pem};

            runtime.federation.remote_key_resolver =
                [](std::string_view server_name,
                   std::string_view key_id) -> std::optional<merovingian::federation::FederationRemoteRuntime> {
                if (server_name != remote_server || key_id != remote_key_id)
                {
                    return std::nullopt;
                }
                return remote_runtime();
            };

            auto missing_events = canonicaljson::Array{};
            for (auto const& json : {old_event.json, mid_event.json})
            {
                auto const parsed_event = canonicaljson::parse_lossless(json);
                REQUIRE(parsed_event.error == canonicaljson::ParseError::none);
                missing_events.push_back(parsed_event.value);
            }
            auto missing_events_object = canonicaljson::Object{};
            missing_events_object.push_back(
                canonicaljson::make_member("events", canonicaljson::Value{std::move(missing_events)}));
            auto const missing_events_body =
                canonicaljson::serialize_canonical(canonicaljson::Value{std::move(missing_events_object)});
            REQUIRE(missing_events_body.error == canonicaljson::CanonicalJsonError::none);
            auto const path_responses = std::vector<std::pair<std::string, std::string>>{
                {"POST /_matrix/federation/v1/get_missing_events/",
                 merovingian::tests::tls_mock::json_http_response("200 OK", missing_events_body.output)},
            };
            auto captured_requests = std::vector<std::string>{};
            auto server_thread = std::thread{[&]() {
                run_body_aware_dispatch_tls_server(acceptor, tls_context, path_responses, &captured_requests);
            }};
            auto const join_server = merovingian::tests::tls_mock::ScopedThreadJoin{server_thread};
            std::ignore = join_server;

            WHEN("the PDU is ingested")
            {
                auto const result = merovingian::homeserver::ingest_pdu_event(runtime, pdu);

                THEN("the PDU is accepted from the final permitted response")
                {
                    REQUIRE(result.status == PduIngestionStatus::accepted);
                }

                THEN("recovery processes the response and makes exactly the one allowed call")
                {
                    REQUIRE(captured_requests.size() == 1U);
                }
            }

            std::filesystem::remove(path);
        }
    }
}

SCENARIO("ingest_pdu_event rejects a /state_ids response just above the configured cap",
         "[pdu_ingestion][backfill][conformance][limits]")
{
    GIVEN("a fresh room runtime configured to accept at most three state IDs")
    {
        auto const path = unique_sqlite_path();
        std::filesystem::remove(path);
        auto started = merovingian::homeserver::start_runtime(config_with_sqlite(path));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        merovingian::homeserver::wire_federation_callbacks(runtime);
        runtime.federation.config.backfill.max_state_ids = 3U;

        auto const room_id = std::string{"!backfill-state-cap:local.example.org"};
        seed_room_with_genesis_state_group(runtime, room_id);
        auto const create_id = room_id + ":create";
        auto const pl_id = room_id + ":pl";
        auto const member_bob_id = room_id + ":member:bob";
        auto const auth_event_ids = std::vector<std::string>{create_id, pl_id, member_bob_id};
        auto const old_event = make_remote_message_pdu(room_id, {member_bob_id}, auth_event_ids, 4, 10);
        auto const mid_event = make_remote_message_pdu(room_id, {old_event.event_id}, auth_event_ids, 5, 11);
        auto const pdu = make_remote_message_pdu(room_id, {mid_event.event_id}, auth_event_ids, 6, 20);

        AND_GIVEN("the origin returns a /state_ids response with four state IDs")
        {
            auto certificate = merovingian::tests::tls_mock::write_test_tls_certificate("localhost");
            auto tls_context_result = merovingian::homeserver::make_tls_server_context(certificate.certificate_file,
                                                                                       certificate.private_key_file);
            REQUIRE(tls_context_result.ok());
            auto tls_context = std::move(*tls_context_result.context);
            auto acceptor = merovingian::net::TcpAcceptor{};
            REQUIRE(acceptor.bind("127.0.0.1", 0U).ok);
            auto const port = acceptor.bound_port();
            REQUIRE(port > 0U);
            runtime.test_forced_outbound_resolution[remote_server] =
                merovingian::homeserver::TestOnlyForcedOutboundResolution{
                    "localhost", port, {"127.0.0.1"}, certificate.certificate_pem};
            runtime.federation.remote_key_resolver =
                [](std::string_view server_name,
                   std::string_view key_id) -> std::optional<merovingian::federation::FederationRemoteRuntime> {
                if (server_name != remote_server || key_id != remote_key_id)
                {
                    return std::nullopt;
                }
                return remote_runtime();
            };
            auto oversized_ids = std::vector<std::string>{room_id + ":extra:1", room_id + ":extra:2",
                                                          room_id + ":extra:3", room_id + ":extra:4"};
            auto const state_ids_body = make_state_ids_response(oversized_ids, auth_event_ids);
            auto const mid_event_body = make_event_transaction_response(mid_event.json, remote_server);
            auto const path_responses = std::vector<std::pair<std::string, std::string>>{
                {"POST /_matrix/federation/v1/get_missing_events/",
                 merovingian::tests::tls_mock::json_http_response("200 OK", make_empty_get_missing_events_response())},
                {"GET /_matrix/federation/v1/event/",
                 merovingian::tests::tls_mock::json_http_response("200 OK", mid_event_body)                          },
                {"GET /_matrix/federation/v1/state_ids/",
                 merovingian::tests::tls_mock::json_http_response("200 OK", state_ids_body)                          },
            };
            auto captured_requests = std::vector<std::string>{};
            auto server_thread = std::thread{[&]() {
                run_body_aware_dispatch_tls_server(acceptor, tls_context, path_responses, &captured_requests);
            }};
            auto const join_server = merovingian::tests::tls_mock::ScopedThreadJoin{server_thread};
            std::ignore = join_server;

            WHEN("the incoming PDU triggers fallback recovery")
            {
                auto const result = merovingian::homeserver::ingest_pdu_event(runtime, pdu);

                THEN("the PDU remains unresolved instead of materialising an oversized snapshot")
                {
                    REQUIRE(result.status == PduIngestionStatus::deferred);
                }
                THEN("the /state_ids response is checked against the configured cap")
                {
                    REQUIRE(std::ranges::any_of(captured_requests, [](std::string const& request) {
                        return request.find("GET /_matrix/federation/v1/state_ids/") != std::string::npos;
                    }));
                }
            }
        }
        std::filesystem::remove(path);
    }
}

// Spec: Matrix Server-Server API v1.19
// Endpoint / Section: Backfilling and retrieving missing events
// URL: ../../docs/matrix-v1.19-spec/server-server-api.md#backfilling-and-retrieving-missing-events
//
// A /state_ids snapshot is only usable if every named event can be fetched and
// verified. A forged event whose signature does not validate must be dropped
// from the snapshot, causing the fallback to fail closed.
SCENARIO("ingest_pdu_event rejects a /state_ids snapshot containing a forged event",
         "[pdu_ingestion][backfill][conformance]")
{
    GIVEN("a fresh runtime seeded with a room genesis state group")
    {
        auto const path = unique_sqlite_path();
        std::filesystem::remove(path);
        auto started = merovingian::homeserver::start_runtime(config_with_sqlite(path));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        merovingian::homeserver::wire_federation_callbacks(runtime);

        auto const room_id = std::string{"!backfill-state-ids-forged:local.example.org"};
        seed_room_with_genesis_state_group(runtime, room_id);

        auto const create_id = room_id + ":create";
        auto const pl_id = room_id + ":pl";
        auto const member_bob_id = room_id + ":member:bob";
        auto const auth_event_ids = std::vector<std::string>{create_id, pl_id, member_bob_id};

        auto const old_event = make_remote_message_pdu(room_id, {member_bob_id}, auth_event_ids, 4, 10);
        auto const old_event_id = old_event.event_id;
        auto const mid_event = make_remote_message_pdu(room_id, {old_event_id}, auth_event_ids, 5, 11);
        auto const mid_event_id = mid_event.event_id;

        auto const pdu = make_remote_message_pdu(room_id, {mid_event_id}, auth_event_ids, 6, 20);

        AND_GIVEN("a mock sending server that returns a /state_ids snapshot with a forged state event")
        {
            auto certificate = merovingian::tests::tls_mock::write_test_tls_certificate("localhost");
            auto tls_context_result = merovingian::homeserver::make_tls_server_context(certificate.certificate_file,
                                                                                       certificate.private_key_file);
            REQUIRE(tls_context_result.ok());
            auto tls_context = std::move(*tls_context_result.context);
            auto acceptor = merovingian::net::TcpAcceptor{};
            REQUIRE(acceptor.bind("127.0.0.1", 0U).ok);
            auto const port = acceptor.bound_port();
            REQUIRE(port > 0U);

            runtime.test_forced_outbound_resolution[remote_server] =
                merovingian::homeserver::TestOnlyForcedOutboundResolution{
                    "localhost", port, {"127.0.0.1"}, certificate.certificate_pem};

            runtime.federation.remote_key_resolver =
                [](std::string_view server_name,
                   std::string_view key_id) -> std::optional<merovingian::federation::FederationRemoteRuntime> {
                if (server_name != remote_server || key_id != remote_key_id)
                {
                    return std::nullopt;
                }
                return remote_runtime();
            };

            auto const wrong_seed = std::string{"pdu-backfill-test-forged-wrong-seed"};
            auto forged_pl_content = canonicaljson::Object{};
            forged_pl_content.push_back(canonicaljson::make_member(
                "users", canonicaljson::Value{canonicaljson::Object{canonicaljson::make_member(
                             "@bob:remote.example.org", canonicaljson::Value{std::int64_t{100}})}}));
            auto const forged_pl_pdu =
                make_remote_event_pdu(room_id, "m.room.power_levels", std::string{}, "@bob:remote.example.org",
                                      std::move(forged_pl_content), {pl_id}, auth_event_ids, 4, 10, wrong_seed);
            auto const forged_pl_id = forged_pl_pdu.event_id;

            auto const snapshot_pdu_ids = std::vector<std::string>{create_id, member_bob_id, forged_pl_id};
            auto const state_ids_body = make_state_ids_response(snapshot_pdu_ids, auth_event_ids);
            auto const mid_event_body = make_event_transaction_response(mid_event.json, remote_server);
            auto const forged_pl_body = make_event_transaction_response(forged_pl_pdu.json, remote_server);
            auto const path_responses = std::vector<std::pair<std::string, std::string>>{
                {"POST /_matrix/federation/v1/get_missing_events/",
                 merovingian::tests::tls_mock::json_http_response("200 OK", make_empty_get_missing_events_response())},
                {"GET /_matrix/federation/v1/event/",
                 merovingian::tests::tls_mock::json_http_response("200 OK", mid_event_body)                          },
                {"GET /_matrix/federation/v1/state_ids/",
                 merovingian::tests::tls_mock::json_http_response("200 OK", state_ids_body)                          },
                {"GET /_matrix/federation/v1/event/",
                 merovingian::tests::tls_mock::json_http_response("200 OK", forged_pl_body)                          },
            };
            auto captured_requests = std::vector<std::string>{};
            auto server_thread = std::thread{[&]() {
                run_body_aware_dispatch_tls_server(acceptor, tls_context, path_responses, &captured_requests);
            }};
            auto const join_server = merovingian::tests::tls_mock::ScopedThreadJoin{server_thread};
            std::ignore = join_server;

            WHEN("the PDU is ingested")
            {
                auto const result = merovingian::homeserver::ingest_pdu_event(runtime, pdu);

                THEN("the PDU is retained for a retry (deferred), not stored")
                {
                    REQUIRE(result.status == PduIngestionStatus::deferred);
                }

                THEN("the forged snapshot event is not stored")
                {
                    auto const* event = [&]() -> merovingian::database::PersistentEvent const* {
                        for (auto const& e : runtime.database.persistent_store.events)
                        {
                            if (e.event_id == forged_pl_id)
                            {
                                return &e;
                            }
                        }
                        return nullptr;
                    }();
                    REQUIRE(event == nullptr);
                }
            }

            std::filesystem::remove(path);
        }
    }
}

// Spec: Matrix Server-Server API v1.19
// Endpoint / Section: Backfilling and retrieving missing events
// URL: ../../docs/matrix-v1.19-spec/server-server-api.md#backfilling-and-retrieving-missing-events
//
// A /state_ids snapshot must only contain events that actually belong to the
// room being backfilled. A malicious origin can list an event from a different
// room where it holds power; if the snapshot accepted it, that foreign state
// would become local state. The whole snapshot must be rejected instead.
SCENARIO("ingest_pdu_event rejects a /state_ids snapshot containing an event from a different room",
         "[pdu_ingestion][backfill][conformance]")
{
    GIVEN("a fresh runtime seeded with two rooms")
    {
        auto const path = unique_sqlite_path();
        std::filesystem::remove(path);
        auto started = merovingian::homeserver::start_runtime(config_with_sqlite(path));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        merovingian::homeserver::wire_federation_callbacks(runtime);

        auto const room_a_id = std::string{"!backfill-state-ids-wrong-room-a:local.example.org"};
        auto const room_b_id = std::string{"!backfill-state-ids-wrong-room-b:local.example.org"};
        seed_room_with_genesis_state_group(runtime, room_a_id);
        seed_room_with_genesis_state_group(runtime, room_b_id);

        auto const create_a_id = room_a_id + ":create";
        auto const pl_a_id = room_a_id + ":pl";
        auto const member_bob_a_id = room_a_id + ":member:bob";
        auto const pl_b_id = room_b_id + ":pl";

        auto const auth_event_ids = std::vector<std::string>{create_a_id, pl_a_id, member_bob_a_id};

        auto const old_event = make_remote_message_pdu(room_a_id, {member_bob_a_id}, auth_event_ids, 4, 10);
        auto const old_event_id = old_event.event_id;
        auto const mid_event = make_remote_message_pdu(room_a_id, {old_event_id}, auth_event_ids, 5, 11);
        auto const mid_event_id = mid_event.event_id;

        auto const pdu = make_remote_message_pdu(room_a_id, {mid_event_id}, auth_event_ids, 6, 20);

        AND_GIVEN("a mock sending server that returns a /state_ids snapshot with a foreign-room power_levels event")
        {
            auto certificate = merovingian::tests::tls_mock::write_test_tls_certificate("localhost");
            auto tls_context_result = merovingian::homeserver::make_tls_server_context(certificate.certificate_file,
                                                                                       certificate.private_key_file);
            REQUIRE(tls_context_result.ok());
            auto tls_context = std::move(*tls_context_result.context);
            auto acceptor = merovingian::net::TcpAcceptor{};
            REQUIRE(acceptor.bind("127.0.0.1", 0U).ok);
            auto const port = acceptor.bound_port();
            REQUIRE(port > 0U);

            runtime.test_forced_outbound_resolution[remote_server] =
                merovingian::homeserver::TestOnlyForcedOutboundResolution{
                    "localhost", port, {"127.0.0.1"}, certificate.certificate_pem};

            runtime.federation.remote_key_resolver =
                [](std::string_view server_name,
                   std::string_view key_id) -> std::optional<merovingian::federation::FederationRemoteRuntime> {
                if (server_name != remote_server || key_id != remote_key_id)
                {
                    return std::nullopt;
                }
                return remote_runtime();
            };

            // pdu_ids names the foreign room's power_levels event instead of the
            // target room's. All three events are already in the store, so the
            // fallback will not try to fetch them.
            auto const snapshot_pdu_ids = std::vector<std::string>{create_a_id, member_bob_a_id, pl_b_id};
            auto const state_ids_body = make_state_ids_response(snapshot_pdu_ids, auth_event_ids);
            auto const mid_event_body = make_event_transaction_response(mid_event.json, remote_server);
            auto const path_responses = std::vector<std::pair<std::string, std::string>>{
                {"POST /_matrix/federation/v1/get_missing_events/",
                 merovingian::tests::tls_mock::json_http_response("200 OK", make_empty_get_missing_events_response())},
                {"GET /_matrix/federation/v1/event/",
                 merovingian::tests::tls_mock::json_http_response("200 OK", mid_event_body)                          },
                {"GET /_matrix/federation/v1/state_ids/",
                 merovingian::tests::tls_mock::json_http_response("200 OK", state_ids_body)                          },
                {"GET /_matrix/federation/v1/event/",
                 merovingian::tests::tls_mock::json_http_response("200 OK", mid_event_body)                          },
            };
            auto captured_requests = std::vector<std::string>{};
            auto server_thread = std::thread{[&]() {
                run_body_aware_dispatch_tls_server(acceptor, tls_context, path_responses, &captured_requests);
            }};
            auto const join_server = merovingian::tests::tls_mock::ScopedThreadJoin{server_thread};
            std::ignore = join_server;

            WHEN("the PDU is ingested")
            {
                auto const result = merovingian::homeserver::ingest_pdu_event(runtime, pdu);

                THEN("the PDU is retained for a retry (deferred), not stored because the snapshot is malformed")
                {
                    REQUIRE(result.status == PduIngestionStatus::deferred);
                }

                THEN("the foreign-room event was not used as state in room A")
                {
                    auto const group =
                        merovingian::database::find_event_state_group(runtime.database.persistent_store, mid_event_id);
                    REQUIRE(!group.has_value());
                }
            }

            std::filesystem::remove(path);
        }
    }
}

// Spec: Matrix Server-Server API v1.19
// Endpoint / Section: Rejection
// URL: ../../docs/matrix-v1.19-spec/server-server-api.md#rejection
//
// A rejected event must never be used as state. A malicious /state_ids
// response can list an event that was previously rejected (for example one
// that failed the state-before check); if the snapshot accepted it, item 1
// would be reopened by another path. The whole snapshot must be rejected.
SCENARIO("ingest_pdu_event rejects a /state_ids snapshot containing a previously rejected event",
         "[pdu_ingestion][backfill][conformance]")
{
    GIVEN("a fresh runtime seeded with a room that contains a rejected state event")
    {
        auto const path = unique_sqlite_path();
        std::filesystem::remove(path);
        auto started = merovingian::homeserver::start_runtime(config_with_sqlite(path));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        merovingian::homeserver::wire_federation_callbacks(runtime);

        auto const room_id = std::string{"!backfill-state-ids-rejected:local.example.org"};
        seed_room_with_genesis_state_group(runtime, room_id);

        auto const create_id = room_id + ":create";
        auto const pl_id = room_id + ":pl";
        auto const member_bob_id = room_id + ":member:bob";
        auto const auth_event_ids = std::vector<std::string>{create_id, pl_id, member_bob_id};

        // Seed a topic event that was previously rejected. Its after-state is
        // the genesis state, so it is mapped to the same state group as the
        // genesis tip.
        auto topic_content = canonicaljson::Object{};
        topic_content.push_back(
            canonicaljson::make_member("topic", canonicaljson::Value{std::string{"rejected topic"}}));
        auto const rejected_topic_json =
            make_remote_event_json(room_id, "m.room.topic", std::string{}, "@bob:remote.example.org",
                                   std::move(topic_content), {pl_id}, auth_event_ids, 4, 10);
        auto const rejected_topic_id =
            merovingian::federation::parse_inbound_pdu_envelope(rejected_topic_json, room_version)->event_id;
        runtime.database.persistent_store.events.push_back({rejected_topic_id,
                                                            room_id,
                                                            "@bob:remote.example.org",
                                                            rejected_topic_json,
                                                            4U,
                                                            0U,
                                                            {pl_id},
                                                            auth_event_ids,
                                                            {},
                                                            "rejected"});
        auto const genesis_group =
            merovingian::database::find_event_state_group(runtime.database.persistent_store, member_bob_id);
        REQUIRE(genesis_group.has_value());
        REQUIRE(merovingian::database::set_event_state_group(runtime.database.persistent_store, rejected_topic_id,
                                                             *genesis_group));

        auto const old_event = make_remote_message_pdu(room_id, {member_bob_id}, auth_event_ids, 4, 10);
        auto const old_event_id = old_event.event_id;
        auto const mid_event = make_remote_message_pdu(room_id, {old_event_id}, auth_event_ids, 5, 11);
        auto const mid_event_id = mid_event.event_id;

        auto const pdu = make_remote_message_pdu(room_id, {mid_event_id}, auth_event_ids, 6, 20);

        AND_GIVEN("a mock sending server that returns a /state_ids snapshot including the rejected event")
        {
            auto certificate = merovingian::tests::tls_mock::write_test_tls_certificate("localhost");
            auto tls_context_result = merovingian::homeserver::make_tls_server_context(certificate.certificate_file,
                                                                                       certificate.private_key_file);
            REQUIRE(tls_context_result.ok());
            auto tls_context = std::move(*tls_context_result.context);
            auto acceptor = merovingian::net::TcpAcceptor{};
            REQUIRE(acceptor.bind("127.0.0.1", 0U).ok);
            auto const port = acceptor.bound_port();
            REQUIRE(port > 0U);

            runtime.test_forced_outbound_resolution[remote_server] =
                merovingian::homeserver::TestOnlyForcedOutboundResolution{
                    "localhost", port, {"127.0.0.1"}, certificate.certificate_pem};

            runtime.federation.remote_key_resolver =
                [](std::string_view server_name,
                   std::string_view key_id) -> std::optional<merovingian::federation::FederationRemoteRuntime> {
                if (server_name != remote_server || key_id != remote_key_id)
                {
                    return std::nullopt;
                }
                return remote_runtime();
            };

            auto const snapshot_pdu_ids = std::vector<std::string>{create_id, pl_id, member_bob_id, rejected_topic_id};
            auto const state_ids_body = make_state_ids_response(snapshot_pdu_ids, auth_event_ids);
            auto const mid_event_body = make_event_transaction_response(mid_event.json, remote_server);
            auto const path_responses = std::vector<std::pair<std::string, std::string>>{
                {"POST /_matrix/federation/v1/get_missing_events/",
                 merovingian::tests::tls_mock::json_http_response("200 OK", make_empty_get_missing_events_response())},
                {"GET /_matrix/federation/v1/event/",
                 merovingian::tests::tls_mock::json_http_response("200 OK", mid_event_body)                          },
                {"GET /_matrix/federation/v1/state_ids/",
                 merovingian::tests::tls_mock::json_http_response("200 OK", state_ids_body)                          },
                {"GET /_matrix/federation/v1/event/",
                 merovingian::tests::tls_mock::json_http_response("200 OK", mid_event_body)                          },
            };
            auto captured_requests = std::vector<std::string>{};
            auto server_thread = std::thread{[&]() {
                run_body_aware_dispatch_tls_server(acceptor, tls_context, path_responses, &captured_requests);
            }};
            auto const join_server = merovingian::tests::tls_mock::ScopedThreadJoin{server_thread};
            std::ignore = join_server;

            WHEN("the PDU is ingested")
            {
                auto const result = merovingian::homeserver::ingest_pdu_event(runtime, pdu);

                THEN("the PDU is retained for a retry (deferred), not stored because the snapshot is malformed")
                {
                    REQUIRE(result.status == PduIngestionStatus::deferred);
                }

                THEN("the rejected event was not used as state for the backfilled event")
                {
                    auto const group =
                        merovingian::database::find_event_state_group(runtime.database.persistent_store, mid_event_id);
                    REQUIRE(!group.has_value());
                }
            }

            std::filesystem::remove(path);
        }
    }
}

// Spec: Matrix Server-Server API v1.19
// Endpoint / Section: Backfilling and retrieving missing events
// URL: ../../docs/matrix-v1.19-spec/server-server-api.md#backfilling-and-retrieving-missing-events
//
// A /state_ids response is a state map: each (type, state_key) must appear at
// most once. A duplicate entry lets the remote choose which event is kept by
// ordering. The whole response must be rejected instead of silently
// de-duplicating.
SCENARIO("ingest_pdu_event rejects a /state_ids snapshot with duplicate (type, state_key) entries",
         "[pdu_ingestion][backfill][conformance]")
{
    GIVEN("a fresh runtime seeded with a room that has two power_levels events")
    {
        auto const path = unique_sqlite_path();
        std::filesystem::remove(path);
        auto started = merovingian::homeserver::start_runtime(config_with_sqlite(path));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        merovingian::homeserver::wire_federation_callbacks(runtime);

        auto const room_id = std::string{"!backfill-state-ids-duplicate:local.example.org"};
        seed_room_with_genesis_state_group(runtime, room_id);

        auto const create_id = room_id + ":create";
        auto const pl_id = room_id + ":pl";
        auto const member_bob_id = room_id + ":member:bob";
        auto const auth_event_ids = std::vector<std::string>{create_id, pl_id, member_bob_id};

        // Seed a second power_levels event in the same room. Both have the same
        // (type, state_key) tuple, so a /state_ids response listing both is a
        // malformed state map.
        auto second_pl_content = canonicaljson::Object{};
        second_pl_content.push_back(canonicaljson::make_member("state_default", canonicaljson::Value{std::int64_t{0}}));
        auto second_pl_users = canonicaljson::Object{};
        second_pl_users.push_back(
            canonicaljson::make_member("@admin:local.example.org", canonicaljson::Value{std::int64_t{100}}));
        second_pl_content.push_back(
            canonicaljson::make_member("users", canonicaljson::Value{std::move(second_pl_users)}));
        auto const second_pl_json =
            make_remote_event_json(room_id, "m.room.power_levels", std::string{}, "@admin:local.example.org",
                                   std::move(second_pl_content), {pl_id}, auth_event_ids, 4, 10);
        auto const second_pl_id =
            merovingian::federation::parse_inbound_pdu_envelope(second_pl_json, room_version)->event_id;
        runtime.database.persistent_store.events.push_back({second_pl_id,
                                                            room_id,
                                                            "@admin:local.example.org",
                                                            second_pl_json,
                                                            4U,
                                                            0U,
                                                            {pl_id},
                                                            auth_event_ids,
                                                            {},
                                                            "accepted"});
        auto const genesis_group =
            merovingian::database::find_event_state_group(runtime.database.persistent_store, member_bob_id);
        REQUIRE(genesis_group.has_value());
        REQUIRE(merovingian::database::set_event_state_group(runtime.database.persistent_store, second_pl_id,
                                                             *genesis_group));

        auto const old_event = make_remote_message_pdu(room_id, {member_bob_id}, auth_event_ids, 5, 11);
        auto const old_event_id = old_event.event_id;
        auto const mid_event = make_remote_message_pdu(room_id, {old_event_id}, auth_event_ids, 6, 12);
        auto const mid_event_id = mid_event.event_id;

        auto const pdu = make_remote_message_pdu(room_id, {mid_event_id}, auth_event_ids, 7, 20);

        AND_GIVEN("a mock sending server that returns a /state_ids snapshot listing both power_levels events")
        {
            auto certificate = merovingian::tests::tls_mock::write_test_tls_certificate("localhost");
            auto tls_context_result = merovingian::homeserver::make_tls_server_context(certificate.certificate_file,
                                                                                       certificate.private_key_file);
            REQUIRE(tls_context_result.ok());
            auto tls_context = std::move(*tls_context_result.context);
            auto acceptor = merovingian::net::TcpAcceptor{};
            REQUIRE(acceptor.bind("127.0.0.1", 0U).ok);
            auto const port = acceptor.bound_port();
            REQUIRE(port > 0U);

            runtime.test_forced_outbound_resolution[remote_server] =
                merovingian::homeserver::TestOnlyForcedOutboundResolution{
                    "localhost", port, {"127.0.0.1"}, certificate.certificate_pem};

            runtime.federation.remote_key_resolver =
                [](std::string_view server_name,
                   std::string_view key_id) -> std::optional<merovingian::federation::FederationRemoteRuntime> {
                if (server_name != remote_server || key_id != remote_key_id)
                {
                    return std::nullopt;
                }
                return remote_runtime();
            };

            auto const snapshot_pdu_ids = std::vector<std::string>{create_id, pl_id, second_pl_id, member_bob_id};
            auto const state_ids_body = make_state_ids_response(snapshot_pdu_ids, auth_event_ids);
            auto const mid_event_body = make_event_transaction_response(mid_event.json, remote_server);
            auto const path_responses = std::vector<std::pair<std::string, std::string>>{
                {"POST /_matrix/federation/v1/get_missing_events/",
                 merovingian::tests::tls_mock::json_http_response("200 OK", make_empty_get_missing_events_response())},
                {"GET /_matrix/federation/v1/event/",
                 merovingian::tests::tls_mock::json_http_response("200 OK", mid_event_body)                          },
                {"GET /_matrix/federation/v1/state_ids/",
                 merovingian::tests::tls_mock::json_http_response("200 OK", state_ids_body)                          },
                {"GET /_matrix/federation/v1/event/",
                 merovingian::tests::tls_mock::json_http_response("200 OK", mid_event_body)                          },
            };
            auto captured_requests = std::vector<std::string>{};
            auto server_thread = std::thread{[&]() {
                run_body_aware_dispatch_tls_server(acceptor, tls_context, path_responses, &captured_requests);
            }};
            auto const join_server = merovingian::tests::tls_mock::ScopedThreadJoin{server_thread};
            std::ignore = join_server;

            WHEN("the PDU is ingested")
            {
                auto const result = merovingian::homeserver::ingest_pdu_event(runtime, pdu);

                THEN("the PDU is retained for a retry (deferred), not stored because the snapshot is malformed")
                {
                    REQUIRE(result.status == PduIngestionStatus::deferred);
                }

                THEN("the backfilled event was not stored from the malformed snapshot")
                {
                    auto const group =
                        merovingian::database::find_event_state_group(runtime.database.persistent_store, mid_event_id);
                    REQUIRE(!group.has_value());
                }
            }

            std::filesystem::remove(path);
        }
    }
}

// Spec: Matrix Server-Server API v1.19
// Endpoint / Section: Backfilling and retrieving missing events
// URL: ../../docs/matrix-v1.19-spec/server-server-api.md#backfilling-and-retrieving-missing-events
//
// A /state_ids response is a state map and must only name state events. A
// non-state entry is malformed and must cause the whole response to be
// rejected, not silently skipped.
SCENARIO("ingest_pdu_event rejects a /state_ids snapshot containing a non-state event",
         "[pdu_ingestion][backfill][conformance]")
{
    GIVEN("a fresh runtime seeded with a room that has a non-state outlier")
    {
        auto const path = unique_sqlite_path();
        std::filesystem::remove(path);
        auto started = merovingian::homeserver::start_runtime(config_with_sqlite(path));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        merovingian::homeserver::wire_federation_callbacks(runtime);

        auto const room_id = std::string{"!backfill-state-ids-nonstate:local.example.org"};
        seed_room_with_genesis_state_group(runtime, room_id);

        auto const create_id = room_id + ":create";
        auto const pl_id = room_id + ":pl";
        auto const member_bob_id = room_id + ":member:bob";
        auto const auth_event_ids = std::vector<std::string>{create_id, pl_id, member_bob_id};

        // Seed a non-state (message) event that has been stored as an outlier
        // with a state group, so the snapshot builder finds it in the store.
        auto const outlier_message_json = make_remote_message_json(room_id, {member_bob_id}, auth_event_ids, 4, 10);
        auto const outlier_message_id =
            merovingian::federation::parse_inbound_pdu_envelope(outlier_message_json, room_version)->event_id;
        runtime.database.persistent_store.events.push_back({outlier_message_id,
                                                            room_id,
                                                            "@bob:remote.example.org",
                                                            outlier_message_json,
                                                            4U,
                                                            0U,
                                                            {member_bob_id},
                                                            auth_event_ids,
                                                            {},
                                                            "outlier"});
        auto const genesis_group =
            merovingian::database::find_event_state_group(runtime.database.persistent_store, member_bob_id);
        REQUIRE(genesis_group.has_value());
        REQUIRE(merovingian::database::set_event_state_group(runtime.database.persistent_store, outlier_message_id,
                                                             *genesis_group));

        auto const old_event = make_remote_message_pdu(room_id, {member_bob_id}, auth_event_ids, 5, 11);
        auto const old_event_id = old_event.event_id;
        auto const mid_event = make_remote_message_pdu(room_id, {old_event_id}, auth_event_ids, 6, 12);
        auto const mid_event_id = mid_event.event_id;

        auto const pdu = make_remote_message_pdu(room_id, {mid_event_id}, auth_event_ids, 7, 20);

        AND_GIVEN("a mock sending server that returns a /state_ids snapshot including the non-state event")
        {
            auto certificate = merovingian::tests::tls_mock::write_test_tls_certificate("localhost");
            auto tls_context_result = merovingian::homeserver::make_tls_server_context(certificate.certificate_file,
                                                                                       certificate.private_key_file);
            REQUIRE(tls_context_result.ok());
            auto tls_context = std::move(*tls_context_result.context);
            auto acceptor = merovingian::net::TcpAcceptor{};
            REQUIRE(acceptor.bind("127.0.0.1", 0U).ok);
            auto const port = acceptor.bound_port();
            REQUIRE(port > 0U);

            runtime.test_forced_outbound_resolution[remote_server] =
                merovingian::homeserver::TestOnlyForcedOutboundResolution{
                    "localhost", port, {"127.0.0.1"}, certificate.certificate_pem};

            runtime.federation.remote_key_resolver =
                [](std::string_view server_name,
                   std::string_view key_id) -> std::optional<merovingian::federation::FederationRemoteRuntime> {
                if (server_name != remote_server || key_id != remote_key_id)
                {
                    return std::nullopt;
                }
                return remote_runtime();
            };

            auto const snapshot_pdu_ids = std::vector<std::string>{create_id, pl_id, member_bob_id, outlier_message_id};
            auto const state_ids_body = make_state_ids_response(snapshot_pdu_ids, auth_event_ids);
            auto const mid_event_body = make_event_transaction_response(mid_event.json, remote_server);
            auto const path_responses = std::vector<std::pair<std::string, std::string>>{
                {"POST /_matrix/federation/v1/get_missing_events/",
                 merovingian::tests::tls_mock::json_http_response("200 OK", make_empty_get_missing_events_response())},
                {"GET /_matrix/federation/v1/event/",
                 merovingian::tests::tls_mock::json_http_response("200 OK", mid_event_body)                          },
                {"GET /_matrix/federation/v1/state_ids/",
                 merovingian::tests::tls_mock::json_http_response("200 OK", state_ids_body)                          },
                {"GET /_matrix/federation/v1/event/",
                 merovingian::tests::tls_mock::json_http_response("200 OK", mid_event_body)                          },
            };
            auto captured_requests = std::vector<std::string>{};
            auto server_thread = std::thread{[&]() {
                run_body_aware_dispatch_tls_server(acceptor, tls_context, path_responses, &captured_requests);
            }};
            auto const join_server = merovingian::tests::tls_mock::ScopedThreadJoin{server_thread};
            std::ignore = join_server;

            WHEN("the PDU is ingested")
            {
                auto const result = merovingian::homeserver::ingest_pdu_event(runtime, pdu);

                THEN("the PDU is retained for a retry (deferred), not stored because the snapshot is malformed")
                {
                    REQUIRE(result.status == PduIngestionStatus::deferred);
                }

                THEN("the backfilled event was not stored from the malformed snapshot")
                {
                    auto const group =
                        merovingian::database::find_event_state_group(runtime.database.persistent_store, mid_event_id);
                    REQUIRE(!group.has_value());
                }
            }

            std::filesystem::remove(path);
        }
    }
}

// Spec: Matrix Server-Server API v1.19
// Endpoint / Section: Backfilling and retrieving missing events
// URL: ../../docs/matrix-v1.19-spec/server-server-api.md#backfilling-and-retrieving-missing-events
//
// ADR-0069: when a /state_ids snapshot names a historical state event whose
// prev_events have no recorded state groups, the fallback must still be able
// to verify and store that state event. It does so by fetching the event with
// GET /event/{eventId} and verifying it as an outlier against its own
// auth_events (whose events are stored), and using the verified state as the
// snapshot for the missing target event. A peer that does not serve /event_auth
// is no obstacle (A8); the last resort that does use it is covered by
// [a8_event_auth_last_resort].
SCENARIO("ingest_pdu_event verifies a /state_ids snapshot state event against its own auth_events when its "
         "prev_events have no state groups",
         "[pdu_ingestion][backfill][conformance]")
{
    GIVEN("a fresh runtime seeded with a room genesis state group")
    {
        auto const path = unique_sqlite_path();
        std::filesystem::remove(path);
        auto started = merovingian::homeserver::start_runtime(config_with_sqlite(path));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        merovingian::homeserver::wire_federation_callbacks(runtime);

        auto const room_id = std::string{"!backfill-state-ids-event-auth:local.example.org"};
        seed_room_with_genesis_state_group(runtime, room_id);

        auto const create_id = room_id + ":create";
        auto const pl_id = room_id + ":pl";
        auto const member_id = room_id + ":member";
        auto const member_bob_id = room_id + ":member:bob";
        auto const auth_event_ids = std::vector<std::string>{create_id, pl_id, member_bob_id};

        // `old_event` is missing and has no recorded state group, so a normal
        // /event/{id} fetch for `historical_state` would fail: its prev_event
        // cannot supply a state-before. Its own auth_events are all stored, so it is verified
        // against them alone and stored as an outlier anyway, without /event_auth.
        auto const old_event = make_remote_message_pdu(room_id, {member_bob_id}, auth_event_ids, 4, 10);
        auto const old_event_id = old_event.event_id;

        auto historical_state_content = canonicaljson::Object{};
        historical_state_content.push_back(
            canonicaljson::make_member("topic", canonicaljson::Value{std::string{"historical topic"}}));
        auto const historical_state_pdu =
            make_remote_event_pdu(room_id, "m.room.topic", std::string{}, "@bob:remote.example.org",
                                  std::move(historical_state_content), {old_event_id}, auth_event_ids, 5, 11);
        auto const historical_state_id = historical_state_pdu.event_id;

        auto const mid_event = make_remote_message_pdu(room_id, {historical_state_id}, auth_event_ids, 6, 12);
        auto const mid_event_id = mid_event.event_id;

        auto const pdu = make_remote_message_pdu(room_id, {mid_event_id}, auth_event_ids, 7, 20);

        AND_GIVEN("a mock sending server that returns /state_ids and the snapshot state event, and does not serve "
                  "/event_auth")
        {
            auto certificate = merovingian::tests::tls_mock::write_test_tls_certificate("localhost");
            auto tls_context_result = merovingian::homeserver::make_tls_server_context(certificate.certificate_file,
                                                                                       certificate.private_key_file);
            REQUIRE(tls_context_result.ok());
            auto tls_context = std::move(*tls_context_result.context);
            auto acceptor = merovingian::net::TcpAcceptor{};
            REQUIRE(acceptor.bind("127.0.0.1", 0U).ok);
            auto const port = acceptor.bound_port();
            REQUIRE(port > 0U);

            runtime.test_forced_outbound_resolution[remote_server] =
                merovingian::homeserver::TestOnlyForcedOutboundResolution{
                    "localhost", port, {"127.0.0.1"}, certificate.certificate_pem};

            runtime.federation.remote_key_resolver =
                [](std::string_view server_name,
                   std::string_view key_id) -> std::optional<merovingian::federation::FederationRemoteRuntime> {
                if (server_name != remote_server || key_id != remote_key_id)
                {
                    return std::nullopt;
                }
                return remote_runtime();
            };

            // /state_ids returns the complete resolved state at the target event,
            // not just the single state event that changed. The auth_chain is the
            // chain needed to authenticate those state events.
            auto const snapshot_pdu_ids =
                std::vector<std::string>{create_id, pl_id, member_bob_id, historical_state_id};
            auto const state_ids_body = make_state_ids_response(snapshot_pdu_ids, auth_event_ids);
            auto const historical_state_body =
                make_event_transaction_response(historical_state_pdu.json, remote_server);
            auto const mid_event_body = make_event_transaction_response(mid_event.json, remote_server);
            // The first /event fetch, for `mid` in the per-reference stage, is
            // answered 404, so `mid` is not in hand when the state is asked at it.
            auto const not_found = merovingian::tests::tls_mock::json_http_response(
                "404 Not Found", R"({"errcode":"M_NOT_FOUND","error":"not found"})");
            auto const path_responses = std::vector<std::pair<std::string, std::string>>{
                {"POST /_matrix/federation/v1/get_missing_events/",
                 merovingian::tests::tls_mock::json_http_response("200 OK", make_empty_get_missing_events_response())},
                {"GET /_matrix/federation/v1/event/", not_found},
                {"GET /_matrix/federation/v1/state_ids/",
                 merovingian::tests::tls_mock::json_http_response("200 OK", state_ids_body)},
                {"GET /_matrix/federation/v1/event/",
                 merovingian::tests::tls_mock::json_http_response("200 OK", historical_state_body)},
                {"GET /_matrix/federation/v1/event/",
                 merovingian::tests::tls_mock::json_http_response("200 OK", mid_event_body)},
            };
            auto captured_requests = std::vector<std::string>{};
            auto server_thread = std::thread{[&]() {
                run_body_aware_dispatch_tls_server(acceptor, tls_context, path_responses, &captured_requests);
            }};
            auto const join_server = merovingian::tests::tls_mock::ScopedThreadJoin{server_thread};
            std::ignore = join_server;

            WHEN("the PDU is ingested")
            {
                auto const result = merovingian::homeserver::ingest_pdu_event(runtime, pdu);

                THEN("the PDU is accepted")
                {
                    REQUIRE(result.status == PduIngestionStatus::accepted);
                }

                // ADR-0070: an event verified only against its own auth_events
                // has no known state-before, so no after-state may be recorded
                // for it. It stays a true outlier.
                THEN("the snapshot state event is stored as an outlier with no recorded state group")
                {
                    auto const* event = [&]() -> merovingian::database::PersistentEvent const* {
                        for (auto const& e : runtime.database.persistent_store.events)
                        {
                            if (e.event_id == historical_state_id)
                            {
                                return &e;
                            }
                        }
                        return nullptr;
                    }();
                    REQUIRE(event != nullptr);
                    REQUIRE(event->status == "outlier");
                    REQUIRE_FALSE(merovingian::database::find_event_state_group(runtime.database.persistent_store,
                                                                                historical_state_id)
                                      .has_value());
                }

                THEN("the backfilled target event is stored as an outlier with a state group")
                {
                    auto const* event = [&]() -> merovingian::database::PersistentEvent const* {
                        for (auto const& e : runtime.database.persistent_store.events)
                        {
                            if (e.event_id == mid_event_id)
                            {
                                return &e;
                            }
                        }
                        return nullptr;
                    }();
                    REQUIRE(event != nullptr);
                    REQUIRE(event->status == "outlier");
                    REQUIRE(
                        merovingian::database::find_event_state_group(runtime.database.persistent_store, mid_event_id)
                            .has_value());
                }

                THEN("/event_auth was not needed")
                {
                    REQUIRE(std::ranges::none_of(captured_requests, [](std::string const& req) {
                        return req.find("GET /_matrix/federation/v1/event_auth/") != std::string::npos;
                    }));
                }
            }

            std::filesystem::remove(path);
        }
    }
}

// ADR-0070: an event stored against its own auth_events only (a /state_ids
// snapshot state event whose prev_events are unknown) was checked against its
// own auth_events only; the state before it is unknown. A later PDU that
// names it as a prev_event must therefore not inherit a state built from that
// event's auth_events. Spec: server-server-api.md, "Checks performed on receipt
// of a PDU", step 5 — the PDU must pass auth against the state before it, which
// is the state after its prev_events.
SCENARIO("ingest_pdu_event does not authorise a PDU against the auth_events of an auth-events-only outlier",
         "[pdu_ingestion][backfill][event_auth_outlier]")
{
    GIVEN("a runtime that has stored a /state_ids snapshot state event verified against its own auth_events only")
    {
        auto const path = unique_sqlite_path();
        std::filesystem::remove(path);
        auto started = merovingian::homeserver::start_runtime(config_with_sqlite(path));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        merovingian::homeserver::wire_federation_callbacks(runtime);

        auto const room_id = std::string{"!backfill-event-auth-outlier:local.example.org"};
        seed_room_with_genesis_state_group(runtime, room_id);

        auto const create_id = room_id + ":create";
        auto const pl_id = room_id + ":pl";
        auto const member_bob_id = room_id + ":member:bob";
        auto const auth_event_ids = std::vector<std::string>{create_id, pl_id, member_bob_id};

        auto const old_event = make_remote_message_pdu(room_id, {member_bob_id}, auth_event_ids, 4, 10);
        auto historical_state_content = canonicaljson::Object{};
        historical_state_content.push_back(
            canonicaljson::make_member("topic", canonicaljson::Value{std::string{"historical topic"}}));
        auto const historical_state_pdu =
            make_remote_event_pdu(room_id, "m.room.topic", std::string{}, "@bob:remote.example.org",
                                  std::move(historical_state_content), {old_event.event_id}, auth_event_ids, 5, 11);
        auto const historical_state_id = historical_state_pdu.event_id;
        auto const mid_event = make_remote_message_pdu(room_id, {historical_state_id}, auth_event_ids, 6, 12);
        auto const first_pdu = make_remote_message_pdu(room_id, {mid_event.event_id}, auth_event_ids, 7, 20);

        // A second PDU whose only prev_event is the auth-events-only outlier.
        auto const second_pdu = make_remote_message_pdu(room_id, {historical_state_id}, auth_event_ids, 6, 30);

        auto certificate = merovingian::tests::tls_mock::write_test_tls_certificate("localhost");
        auto tls_context_result = merovingian::homeserver::make_tls_server_context(certificate.certificate_file,
                                                                                   certificate.private_key_file);
        REQUIRE(tls_context_result.ok());
        auto tls_context = std::move(*tls_context_result.context);
        auto acceptor = merovingian::net::TcpAcceptor{};
        REQUIRE(acceptor.bind("127.0.0.1", 0U).ok);
        auto const port = acceptor.bound_port();
        REQUIRE(port > 0U);

        runtime.test_forced_outbound_resolution[remote_server] =
            merovingian::homeserver::TestOnlyForcedOutboundResolution{
                "localhost", port, {"127.0.0.1"}, certificate.certificate_pem};
        runtime.federation.remote_key_resolver =
            [](std::string_view server_name,
               std::string_view key_id) -> std::optional<merovingian::federation::FederationRemoteRuntime> {
            if (server_name != remote_server || key_id != remote_key_id)
            {
                return std::nullopt;
            }
            return remote_runtime();
        };

        using merovingian::tests::tls_mock::json_http_response;
        using PathResponses = std::vector<std::pair<std::string, std::string>>;
        auto const ok = [](std::string const& body) {
            return json_http_response("200 OK", body);
        };
        auto const not_found = json_http_response("404 Not Found", R"({"errcode":"M_NOT_FOUND","error":"not found"})");
        // Serves `responses` for exactly one ingestion, then joins the mock so
        // `requests` is read on this thread only after the mock has finished.
        auto const ingest_with_origin = [&](InboundPduEnvelope const& pdu, PathResponses const& responses,
                                            std::vector<std::string>& requests) {
            auto server_thread = std::thread{[&]() {
                run_body_aware_dispatch_tls_server(acceptor, tls_context, responses, &requests);
            }};
            auto const join_server = merovingian::tests::tls_mock::ScopedThreadJoin{server_thread};
            std::ignore = join_server;
            return merovingian::homeserver::ingest_pdu_event(runtime, pdu);
        };
        auto const count_requests = [](std::vector<std::string> const& requests, std::string_view prefix) {
            return static_cast<std::size_t>(std::ranges::count_if(requests, [&](std::string const& req) {
                return req.find(prefix) != std::string::npos;
            }));
        };

        auto const snapshot_with_outlier_body = make_state_ids_response(
            std::vector<std::string>{create_id, pl_id, member_bob_id, historical_state_id}, auth_event_ids);
        auto const historical_state_body = make_event_transaction_response(historical_state_pdu.json, remote_server);
        auto const mid_event_body = make_event_transaction_response(mid_event.json, remote_server);

        auto first_requests = std::vector<std::string>{};
        auto const first_result = ingest_with_origin(
            first_pdu,
            PathResponses{
                {"POST /_matrix/federation/v1/get_missing_events/", ok(make_empty_get_missing_events_response())},
                {"GET /_matrix/federation/v1/event/",               not_found                                   },
                {"GET /_matrix/federation/v1/state_ids/",           ok(snapshot_with_outlier_body)              },
                {"GET /_matrix/federation/v1/event/",               ok(historical_state_body)                   },
                {"GET /_matrix/federation/v1/event/",               ok(mid_event_body)                          },
        },
            first_requests);
        REQUIRE(first_result.status == PduIngestionStatus::accepted);
        REQUIRE(count_requests(first_requests, "GET /_matrix/federation/v1/event_auth/") == 0U);
        REQUIRE(stored_status(runtime, historical_state_id).value_or(std::string{}) == "outlier");
        REQUIRE_FALSE(
            merovingian::database::find_event_state_group(runtime.database.persistent_store, historical_state_id)
                .has_value());

        WHEN("a PDU naming that outlier as its only prev_event is ingested and the origin cannot supply its state")
        {
            auto requests = std::vector<std::string>{};
            auto const result = ingest_with_origin(second_pdu,
                                                   PathResponses{
                                                       {"POST /_matrix/federation/v1/get_missing_events/", not_found},
                                                       {"GET /_matrix/federation/v1/event/",               not_found},
                                                       {"GET /_matrix/federation/v1/state_ids/",           not_found},
            },
                                                   requests);

            THEN("the PDU is retained for a retry rather than accepted on the outlier's auth_events")
            {
                REQUIRE(result.status == PduIngestionStatus::deferred);
            }

            THEN("the server asked the origin for the state at the outlier")
            {
                REQUIRE(count_requests(requests, "GET /_matrix/federation/v1/state_ids/") == 1U);
            }
        }

        WHEN("a PDU naming that outlier as its only prev_event is ingested and the origin supplies its state")
        {
            // The state before the topic event: the genesis state.
            auto const state_before_outlier_body =
                make_state_ids_response(std::vector<std::string>{create_id, pl_id, member_bob_id}, auth_event_ids);
            auto requests = std::vector<std::string>{};
            auto const result = ingest_with_origin(
                second_pdu,
                PathResponses{
                    {"POST /_matrix/federation/v1/get_missing_events/", ok(make_empty_get_missing_events_response())},
                    {"GET /_matrix/federation/v1/event/",               ok(historical_state_body)                   },
                    {"GET /_matrix/federation/v1/state_ids/",           ok(state_before_outlier_body)               },
                    {"GET /_matrix/federation/v1/event/",               ok(historical_state_body)                   },
            },
                requests);

            THEN("the PDU is accepted")
            {
                REQUIRE(result.status == PduIngestionStatus::accepted);
            }

            THEN("the outlier now has a recorded state group")
            {
                REQUIRE(merovingian::database::find_event_state_group(runtime.database.persistent_store,
                                                                      historical_state_id)
                            .has_value());
            }
        }

        WHEN("a later /state_ids snapshot names the stored outlier again")
        {
            auto const later_mid_event = make_remote_message_pdu(room_id, {historical_state_id}, auth_event_ids, 6, 40);
            auto const third_pdu = make_remote_message_pdu(room_id, {later_mid_event.event_id}, auth_event_ids, 7, 41);
            auto const later_mid_body = make_event_transaction_response(later_mid_event.json, remote_server);
            auto requests = std::vector<std::string>{};
            auto const result = ingest_with_origin(
                third_pdu,
                PathResponses{
                    {"POST /_matrix/federation/v1/get_missing_events/", ok(make_empty_get_missing_events_response())},
                    {"GET /_matrix/federation/v1/event/",               not_found                                   },
                    {"GET /_matrix/federation/v1/state_ids/",           ok(snapshot_with_outlier_body)              },
                    {"GET /_matrix/federation/v1/event/",               ok(later_mid_body)                          },
            },
                requests);

            THEN("the PDU is accepted")
            {
                REQUIRE(result.status == PduIngestionStatus::accepted);
            }

            THEN("the stored outlier is not fetched or verified through /event_auth again")
            {
                REQUIRE(count_requests(requests, "GET /_matrix/federation/v1/event_auth/") == 0U);
                REQUIRE(requests.size() == 4U);
            }
        }

        std::filesystem::remove(path);
    }
}

// Spec: Matrix Server-Server API v1.19
// Endpoint / Section: POST /_matrix/federation/v1/get_missing_events/{roomId}; Client-Server API
// "Size limits"; Appendices "Canonical JSON"
// URL: ../../docs/matrix-v1.19-spec/server-server-api.md#post_matrixfederationv1get_missing_eventsroomid
//
// An event returned by /get_missing_events is a PDU like any other: "The event ... MUST NOT be
// larger than 65536 bytes", a `state_key` "MUST NOT exceed 255 bytes", and the JSON must be canonical
// (no floats). One that is not is rejected, and the origin's answer is not worked around: the same
// history is not fetched again through /event and /state_ids.
SCENARIO("Backfill rejects an invalid event from /get_missing_events and fetches nothing else",
         "[pdu_ingestion][backfill][fed-endpoints]")
{
    GIVEN("a room with a genesis state group and a sending server that answers /get_missing_events with one bad event")
    {
        auto const path = unique_sqlite_path();
        std::filesystem::remove(path);
        auto started = merovingian::homeserver::start_runtime(config_with_sqlite(path));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        merovingian::homeserver::wire_federation_callbacks(runtime);
        auto const room_id = std::string{"!backfill-bad-returned:local.example.org"};
        seed_room_with_genesis_state_group(runtime, room_id);
        runtime.federation.remote_key_resolver = both_servers_key_resolver();

        auto certificate = merovingian::tests::tls_mock::write_test_tls_certificate("localhost");
        auto tls = merovingian::homeserver::make_tls_server_context(certificate.certificate_file,
                                                                    certificate.private_key_file);
        REQUIRE(tls.ok());
        auto tls_context = std::move(*tls.context);
        auto acceptor = merovingian::net::TcpAcceptor{};
        REQUIRE(acceptor.bind("127.0.0.1", 0U).ok);
        runtime.test_forced_outbound_resolution[remote_server] =
            merovingian::homeserver::TestOnlyForcedOutboundResolution{
                "localhost", acceptor.bound_port(), {"127.0.0.1"}, certificate.certificate_pem};

        auto const bad_event_json = [&](std::string const& state_key, std::string const& content) {
            return std::string{R"({"type":"my.room.breaker","state_key":")"} + state_key + R"(","sender":"@bad:)" +
                   std::string{remote_server} + R"(","room_id":")" + room_id +
                   R"(","origin_server_ts":1,"depth":4,"prev_events":[],"auth_events":[],"content":)" + content +
                   R"(,"hashes":{"sha256":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},"signatures":{}})";
        };
        auto const ingest_returning = [&](std::string const& event_json) {
            auto const pdu = make_remote_message_pdu(
                room_id, {room_id + ":member"}, {room_id + ":create", room_id + ":pl", room_id + ":member:bob"}, 5, 90);
            // The PDU's prev_event is one the peer does not have either, so the gap stays open.
            auto gap_pdu = pdu;
            gap_pdu.prev_event_ids = {"$never-stored-anywhere"};
            auto const response = tests::tls_mock::json_http_response("200 OK", R"({"events":[)" + event_json + "]}");
            auto request_lines = std::vector<std::string>{};
            auto result =
                ingest_with_bounded_backfill_peer(runtime, gap_pdu, acceptor, tls_context, response, request_lines);
            return std::make_pair(std::move(result), std::move(request_lines));
        };
        auto const fetched_another_way = [](std::vector<std::string> const& lines) {
            return std::ranges::any_of(lines, [](std::string const& line) {
                return line.starts_with("GET /_matrix/federation/v1/event/") ||
                       line.starts_with("GET /_matrix/federation/v1/state_ids/") ||
                       line.starts_with("GET /_matrix/federation/v1/event_auth/");
            });
        };

        WHEN("the returned event has a 280-byte state_key")
        {
            auto const [result, lines] = ingest_returning(bad_event_json(std::string(280U, 'k'), "{}"));

            THEN("the event is not used and no /event, /state_ids or /event_auth request is made")
            {
                REQUIRE(result.status != PduIngestionStatus::accepted);
                REQUIRE_FALSE(fetched_another_way(lines));
            }
        }

        WHEN("the returned event carries a floating-point number in its content")
        {
            auto const [result, lines] = ingest_returning(bad_event_json("k", R"({"bad_val":1.1})"));

            THEN("the event is not used and no /event, /state_ids or /event_auth request is made")
            {
                REQUIRE(result.status != PduIngestionStatus::accepted);
                REQUIRE_FALSE(fetched_another_way(lines));
            }
        }

        WHEN("the returned event is larger than 65536 bytes")
        {
            auto const [result, lines] =
                ingest_returning(bad_event_json("k", R"({"body":")" + std::string(70000U, 'x') + R"("})"));

            THEN("the event is not used and no /event, /state_ids or /event_auth request is made")
            {
                REQUIRE(result.status != PduIngestionStatus::accepted);
                REQUIRE_FALSE(fetched_another_way(lines));
            }
        }

        std::filesystem::remove(path);
    }
}

// Spec: Matrix v1.19 rooms/v10.md, auth rule 4.2.1 (v8 the same; v12 rule
// 5.2.1): "If content has a join_authorised_via_users_server key: If the
// event is not validly signed by the homeserver of the user ID denoted by the
// key, reject." A join fetched as a missing prev_event is checked like one
// received over /send; a structurally present but forged signature from the
// authorising server must not get it stored.
SCENARIO("Backfill refuses a fetched join whose authorising server signature is not valid",
         "[pdu_ingestion][backfill][security][evt1]")
{
    GIVEN("a v10 room with a joined authorising user on another server, and a sending server that returns a join as "
          "the missing predecessor")
    {
        auto const path = unique_sqlite_path();
        std::filesystem::remove(path);
        auto started = merovingian::homeserver::start_runtime(config_with_sqlite(path));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        merovingian::homeserver::wire_federation_callbacks(runtime);
        auto const room_id = std::string{"!backfill-evt1:local.example.org"};
        seed_room_with_genesis_state_group(runtime, room_id);
        seed_authorising_user(runtime, room_id);
        runtime.federation.remote_key_resolver = both_servers_key_resolver();

        auto certificate = merovingian::tests::tls_mock::write_test_tls_certificate("localhost");
        auto tls = merovingian::homeserver::make_tls_server_context(certificate.certificate_file,
                                                                    certificate.private_key_file);
        REQUIRE(tls.ok());
        auto tls_context = std::move(*tls.context);
        auto acceptor = merovingian::net::TcpAcceptor{};
        REQUIRE(acceptor.bind("127.0.0.1", 0U).ok);
        runtime.test_forced_outbound_resolution[remote_server] =
            merovingian::homeserver::TestOnlyForcedOutboundResolution{
                "localhost", acceptor.bound_port(), {"127.0.0.1"}, certificate.certificate_pem};

        struct Ingested final
        {
            federation::PduIngestionResult result;
            std::string join_event_id;
        };
        // Ingests a later message whose prev_event is the join, which the peer
        // returns from /get_missing_events with the given authorising signature.
        auto const ingest_with_join = [&](AuthorisingSignature kind) {
            auto const join_json = authorised_join_json(room_id, kind);
            auto const join = federation::parse_inbound_pdu_envelope(join_json, room_version);
            REQUIRE(join.has_value());
            auto const pdu = make_remote_message_pdu(
                room_id, {join->event_id}, {room_id + ":create", room_id + ":pl", room_id + ":member:bob"}, 7, 80);
            auto const response = tests::tls_mock::json_http_response("200 OK", get_missing_events_response(join_json));
            auto request_lines = std::vector<std::string>{};
            auto result =
                ingest_with_bounded_backfill_peer(runtime, pdu, acceptor, tls_context, response, request_lines);
            return Ingested{std::move(result), join->event_id};
        };

        WHEN("the fetched join carries a signature from the authorising server made with another key")
        {
            auto const ingested = ingest_with_join(AuthorisingSignature::signed_by_wrong_key);

            THEN("the join is not stored, has no state group, and the PDU that builds on it is not accepted")
            {
                CHECK_FALSE(stored_status(runtime, ingested.join_event_id).has_value());
                CHECK_FALSE(database::find_event_state_group(runtime.database.persistent_store, ingested.join_event_id)
                                .has_value());
                CHECK(ingested.result.status != PduIngestionStatus::accepted);
            }
        }

        WHEN("the fetched join's authorising server entry is a non-empty garbage signature")
        {
            auto const ingested = ingest_with_join(AuthorisingSignature::garbage);

            THEN("the join is not stored, has no state group, and the PDU that builds on it is not accepted")
            {
                CHECK_FALSE(stored_status(runtime, ingested.join_event_id).has_value());
                CHECK_FALSE(database::find_event_state_group(runtime.database.persistent_store, ingested.join_event_id)
                                .has_value());
                CHECK(ingested.result.status != PduIngestionStatus::accepted);
            }
        }

        WHEN("the fetched join is validly signed by the authorising server")
        {
            auto const ingested = ingest_with_join(AuthorisingSignature::genuine);

            THEN("the join is stored as an outlier with a state group and the PDU that builds on it is accepted")
            {
                CHECK(stored_status(runtime, ingested.join_event_id).value_or(std::string{}) == "outlier");
                CHECK(database::find_event_state_group(runtime.database.persistent_store, ingested.join_event_id)
                          .has_value());
                CHECK(ingested.result.status == PduIngestionStatus::accepted);
            }
        }

        std::filesystem::remove(path);
    }
}

// ---------------------------------------------------------------------------
// A8 (Complement run 9): placing a PDU whose prev_events and auth_events this
// server lacks, using only what the Server-Server API guarantees a peer serves.
//
// Spec: docs/matrix-v1.19-spec/server-server-api.md — "Backfilling and
// retrieving missing events" (POST /get_missing_events: `latest_events` are the
// events to retrieve the previous events for, `earliest_events` the latest
// events the sender already has), GET /state_ids (`pdu_ids`, `auth_chain_ids`),
// GET /event/{eventId}, "Rejection", "Checks performed on receipt of a PDU" and
// "Soft failure". A peer is not required to serve GET /event_auth to a server
// that can fetch the same events one at a time.
// ---------------------------------------------------------------------------

namespace
{

// A federation peer that answers every request with whatever `respond` returns,
// until it is destroyed, and records each request. `respond` runs on the peer's
// thread: it must not use Catch2 assertions.
class ScriptedFederationPeer final
{
public:
    using Responder = std::function<std::string(std::string const&)>;

    ScriptedFederationPeer(net::TcpAcceptor& acceptor, homeserver::TlsServerContext& tls_context, Responder responder)
        : thread_{[this, &acceptor, &tls_context, responder = std::move(responder)] {
            serve(acceptor, tls_context, responder);
        }}
    {
    }

    ~ScriptedFederationPeer()
    {
        stop_.store(true);
        if (thread_.joinable())
        {
            thread_.join();
        }
    }

    ScriptedFederationPeer(ScriptedFederationPeer const&) = delete;
    auto operator=(ScriptedFederationPeer const&) -> ScriptedFederationPeer& = delete;
    ScriptedFederationPeer(ScriptedFederationPeer&&) = delete;
    auto operator=(ScriptedFederationPeer&&) -> ScriptedFederationPeer& = delete;

    // Every request received so far, each the raw request text.
    [[nodiscard]] auto requests() const -> std::vector<std::string>
    {
        auto const lock = std::scoped_lock{mutex_};
        return requests_;
    }

private:
    auto serve(net::TcpAcceptor& acceptor, homeserver::TlsServerContext& tls_context, Responder const& responder)
        -> void
    {
        while (!stop_.load())
        {
            auto const fd = tests::tls_mock::accept_loopback(acceptor, 50);
            if (fd < 0)
            {
                continue;
            }
            auto const owned_fd = core::SocketHandle{fd};
            auto tls = homeserver::accept_tls_connection(tls_context, fd, 1000);
            if (!tls.connection.has_value())
            {
                continue;
            }
            auto& connection = *tls.connection;
            auto const request = read_full_http_request(connection);
            {
                auto const lock = std::scoped_lock{mutex_};
                requests_.push_back(request);
            }
            std::ignore = connection.write(responder(request));
        }
    }

    std::atomic<bool> stop_{false};
    mutable std::mutex mutex_{};
    std::vector<std::string> requests_{};
    std::thread thread_;
};

// What the scripted peer serves. Anything not listed is a 404, as it is from a
// server that does not implement the endpoint.
struct PeerScript final
{
    // event ID -> PDU JSON, served by GET /event/{eventId}.
    std::map<std::string, std::string> events{};
    // event ID asked about -> the /state_ids response body.
    std::map<std::string, std::string> state_ids{};
    // The /get_missing_events response body for a request whose first
    // `latest_events` entry is the argument; an empty body is a 404.
    std::function<std::string(std::string const&)> missing_events{};
    // The GET /event_auth response body; empty is a 404.
    std::string event_auth{};
};

[[nodiscard]] auto events_array_body(std::vector<std::string> const& event_jsons) -> std::string
{
    auto body = std::string{R"({"events":[)"};
    for (auto index = std::size_t{0U}; index < event_jsons.size(); ++index)
    {
        body += (index == 0U ? "" : ",") + event_jsons[index];
    }
    return body + "]}";
}

[[nodiscard]] auto scripted_response(PeerScript const& script, std::string const& request) -> std::string
{
    auto const not_found = tests::tls_mock::json_http_response("404 Not Found", R"({"errcode":"M_NOT_FOUND"})");
    auto const line = request.substr(0U, request.find("\r\n"));
    if (line.starts_with("POST /_matrix/federation/v1/get_missing_events/"))
    {
        auto const body_start = request.find("\r\n\r\n");
        constexpr auto marker = std::string_view{R"("latest_events":[")"};
        if (!script.missing_events || body_start == std::string::npos)
        {
            return not_found;
        }
        auto const at = request.find(marker, body_start);
        if (at == std::string::npos)
        {
            return not_found;
        }
        auto const first = at + marker.size();
        auto const body = script.missing_events(request.substr(first, request.find('"', first) - first));
        return body.empty() ? not_found : tests::tls_mock::json_http_response("200 OK", body);
    }
    if (line.starts_with("GET /_matrix/federation/v1/state_ids/"))
    {
        for (auto const& [target, body] : script.state_ids)
        {
            if (line.find("event_id=" + core::percent_encode_path_component(target) + " ") != std::string::npos)
            {
                return tests::tls_mock::json_http_response("200 OK", body);
            }
        }
        return not_found;
    }
    if (line.starts_with("GET /_matrix/federation/v1/event_auth/"))
    {
        return script.event_auth.empty() ? not_found : tests::tls_mock::json_http_response("200 OK", script.event_auth);
    }
    for (auto const& [id, json] : script.events)
    {
        if (line.starts_with("GET /_matrix/federation/v1/event/" + core::percent_encode_path_component(id) + " "))
        {
            return tests::tls_mock::json_http_response("200 OK", std::string{R"({"origin":")"} + remote_server +
                                                                     R"(","origin_server_ts":0,"pdus":[)" + json +
                                                                     "]}");
        }
    }
    return not_found;
}

[[nodiscard]] auto count_requests_starting_with(std::vector<std::string> const& requests, std::string_view prefix)
    -> std::size_t
{
    return static_cast<std::size_t>(std::ranges::count_if(requests, [&](std::string const& request) {
        return request.starts_with(prefix);
    }));
}

// True when a /state_ids request asked about `event_id`.
[[nodiscard]] auto state_asked_at(std::vector<std::string> const& requests, std::string const& event_id) -> bool
{
    return std::ranges::any_of(requests, [&](std::string const& request) {
        return request.starts_with("GET /_matrix/federation/v1/state_ids/") &&
               request.find("event_id=" + core::percent_encode_path_component(event_id) + " ") != std::string::npos;
    });
}

[[nodiscard]] auto member_content(std::string const& displayname) -> canonicaljson::Object
{
    auto content = canonicaljson::Object{};
    content.push_back(canonicaljson::make_member("membership", canonicaljson::Value{std::string{"join"}}));
    content.push_back(canonicaljson::make_member("displayname", canonicaljson::Value{displayname}));
    return content;
}

// A seeded room (create, power_levels, two joins, one state group) on a runtime
// that reaches a scripted remote server over loopback TLS.
class RecoveryFixture final
{
public:
    explicit RecoveryFixture(std::string room)
        : room_id{std::move(room)}
        , certificate_{tests::tls_mock::write_test_tls_certificate("localhost")}
        , started_{homeserver::start_runtime(config_with_sqlite(certificate_.directory / "recovery.sqlite"))}
        , tls_{homeserver::make_tls_server_context(certificate_.certificate_file, certificate_.private_key_file)}
    {
        REQUIRE(started_.started);
        REQUIRE(tls_.ok());
        REQUIRE(acceptor_.bind("127.0.0.1", 0U).ok);
        homeserver::wire_federation_callbacks(started_.runtime);
        started_.runtime.federation.remote_key_resolver = genuine_key_resolver();
        // The remote server's key is already cached, as it is in production once
        // any of its events has been verified: a recovery verifies many events,
        // and resolving the key for each would exhaust the unknown-source
        // key-resolution rate, which is not what these scenarios are about.
        auto const public_key = remote_runtime().signing_key;
        REQUIRE(database::store_server_signing_key(started_.runtime.database.persistent_store,
                                                   {std::string{remote_server}, std::string{remote_key_id},
                                                    events::matrix_base64_from_bytes(public_key.public_key_bytes),
                                                    public_key.valid_until_ts}));
        seed_room_with_genesis_state_group(started_.runtime, room_id);
        started_.runtime.test_forced_outbound_resolution[remote_server] = homeserver::TestOnlyForcedOutboundResolution{
            "localhost", acceptor_.bound_port(), {"127.0.0.1"}, certificate_.certificate_pem};
    }

    RecoveryFixture(RecoveryFixture const&) = delete;
    auto operator=(RecoveryFixture const&) -> RecoveryFixture& = delete;
    RecoveryFixture(RecoveryFixture&&) = delete;
    auto operator=(RecoveryFixture&&) -> RecoveryFixture& = delete;
    ~RecoveryFixture() = default;

    [[nodiscard]] auto runtime() -> HomeserverRuntime&
    {
        return started_.runtime;
    }

    [[nodiscard]] auto create_id() const -> std::string
    {
        return room_id + ":create";
    }
    [[nodiscard]] auto pl_id() const -> std::string
    {
        return room_id + ":pl";
    }
    [[nodiscard]] auto admin_member_id() const -> std::string
    {
        return room_id + ":member";
    }
    [[nodiscard]] auto bob_member_id() const -> std::string
    {
        return room_id + ":member:bob";
    }
    // The auth_events a remote user's ordinary event names in this room.
    [[nodiscard]] auto auth_ids() const -> std::vector<std::string>
    {
        return {create_id(), pl_id(), bob_member_id()};
    }
    // The seeded state: what /state_ids reports for an event that changed nothing.
    [[nodiscard]] auto genesis_state_ids() const -> std::vector<std::string>
    {
        return {create_id(), pl_id(), admin_member_id(), bob_member_id()};
    }

    // Starts a peer answering from `script`, which must outlive the returned peer.
    [[nodiscard]] auto serve(PeerScript const& script) -> std::unique_ptr<ScriptedFederationPeer>
    {
        return std::make_unique<ScriptedFederationPeer>(acceptor_, *tls_.context,
                                                        [&script](std::string const& request) {
                                                            return scripted_response(script, request);
                                                        });
    }

    [[nodiscard]] auto ingest(InboundPduEnvelope const& pdu) -> federation::PduIngestionResult
    {
        return homeserver::ingest_pdu_event(started_.runtime, pdu);
    }

    [[nodiscard]] auto has_state_group(std::string_view event_id) -> bool
    {
        return database::find_event_state_group(started_.runtime.database.persistent_store, event_id).has_value();
    }

    std::string room_id;

private:
    tests::tls_mock::TlsTestCertificate certificate_;
    homeserver::RuntimeStartResult started_;
    homeserver::TlsServerContextResult tls_;
    net::TcpAcceptor acceptor_{};
};

// Spec: server-server-api.md POST /get_missing_events — `latest_events` are
// "the event IDs to retrieve the previous events for": the PDU whose ancestry is
// incomplete, which the origin walks back from and does not return itself.
// `earliest_events` are "the latest event IDs that the sender already has".
// Naming the PDU's prev_events as the former makes the origin skip them, and
// naming the events this server lacks as the latter makes it skip the very
// events that were asked for.
SCENARIO("Backfill asks /get_missing_events about the PDU itself and names the events it already has",
         "[pdu_ingestion][backfill][a8_get_missing_events]")
{
    GIVEN("a room this server holds and a PDU whose prev_event it has never seen")
    {
        auto fixture = RecoveryFixture{"!a8-gme-request:local.example.org"};
        auto const gap = make_remote_message_pdu(fixture.room_id, {fixture.bob_member_id()}, fixture.auth_ids(), 4, 10);
        auto const pdu = make_remote_message_pdu(fixture.room_id, {gap.event_id}, fixture.auth_ids(), 5, 11);

        AND_GIVEN("a sending server that serves nothing")
        {
            auto const script = PeerScript{};
            auto const peer = fixture.serve(script);

            WHEN("the PDU is ingested")
            {
                std::ignore = fixture.ingest(pdu);

                THEN("the first request is /get_missing_events with the PDU as latest_events and this server's "
                     "forward extremity as earliest_events")
                {
                    auto const requests = peer->requests();
                    auto const first = std::ranges::find_if(requests, [](std::string const& request) {
                        return request.starts_with("POST /_matrix/federation/v1/get_missing_events/");
                    });
                    REQUIRE(first != requests.end());
                    auto const body = first->substr(first->find("\r\n\r\n") + 4U);
                    CHECK(body.find(R"("latest_events":[")" + pdu.event_id + R"("])") != std::string::npos);
                    CHECK(body.find(R"("earliest_events":[")" + fixture.admin_member_id() + R"("])") !=
                          std::string::npos);
                    CHECK(body.find(gap.event_id) == std::string::npos);
                }
            }
        }
    }
}

// Spec: server-server-api.md GET /state_ids and "Backfilling and retrieving
// missing events". /get_missing_events returned one event whose own prev_event
// is still unknown: the gap is that prev_event, so that is the event the state
// is asked at, not the event /get_missing_events returned.
SCENARIO("Backfill asks for the state at the prev_event that a fetched event is itself missing",
         "[pdu_ingestion][backfill][a8_state_at_gap]")
{
    GIVEN("a PDU, its prev_event, and that event's own prev_event, only the first of which the origin lists")
    {
        auto fixture = RecoveryFixture{"!a8-state-at-gap:local.example.org"};
        auto const older =
            make_remote_message_pdu(fixture.room_id, {fixture.bob_member_id()}, fixture.auth_ids(), 4, 10);
        auto const newer = make_remote_message_pdu(fixture.room_id, {older.event_id}, fixture.auth_ids(), 5, 11);
        auto const pdu = make_remote_message_pdu(fixture.room_id, {newer.event_id}, fixture.auth_ids(), 6, 20);

        AND_GIVEN("an origin that answers /get_missing_events with only the newer event, and serves /state_ids "
                  "and /event but not /event_auth")
        {
            auto script = PeerScript{};
            script.events = {
                {older.event_id, older.json},
                {newer.event_id, newer.json}
            };
            script.state_ids[older.event_id] = make_state_ids_response(fixture.genesis_state_ids(), fixture.auth_ids());
            script.missing_events = [&](std::string const& latest) {
                return latest == pdu.event_id ? events_array_body({newer.json}) : std::string{};
            };
            auto const peer = fixture.serve(script);

            WHEN("the PDU is ingested")
            {
                auto const result = fixture.ingest(pdu);
                auto const requests = peer->requests();

                THEN("the PDU is accepted and both earlier events are placed")
                {
                    CHECK(result.status == PduIngestionStatus::accepted);
                    CHECK(fixture.has_state_group(older.event_id));
                    CHECK(fixture.has_state_group(newer.event_id));
                }

                THEN("the state was asked at the event nothing could supply, once, and never at the event that "
                     "was already in hand")
                {
                    CHECK(count_requests_starting_with(requests, "GET /_matrix/federation/v1/state_ids/") == 1U);
                    CHECK(state_asked_at(requests, older.event_id));
                    CHECK_FALSE(state_asked_at(requests, newer.event_id));
                }

                THEN("/event_auth was not needed")
                {
                    CHECK(count_requests_starting_with(requests, "GET /_matrix/federation/v1/event_auth/") == 0U);
                }
            }
        }
    }
}

// Exercises a /state_ids snapshot that names events this server has never seen:
// an auth chain event B1 (member), and the state event Z whose auth_events name
// B1 and whose own prev_event Y is unavailable, so Z's state-before is unknown.
// Only GET /event/{eventId} is served, never /event_auth. B1 is served only when
// `serve_b1` is set.
auto exercise_snapshot_auth_chain(bool serve_b1) -> void
{
    auto fixture =
        RecoveryFixture{serve_b1 ? "!a8-chain-served:local.example.org" : "!a8-chain-missing:local.example.org"};
    auto const& room = fixture.room_id;
    auto const b1 = make_remote_event_pdu(room, "m.room.member", std::string{remote_member}, remote_member,
                                          member_content("A"), {fixture.bob_member_id()}, fixture.auth_ids(), 4, 10);
    auto const y = make_remote_message_pdu(room, {b1.event_id}, fixture.auth_ids(), 5, 11);
    auto const z =
        make_remote_event_pdu(room, "m.room.member", std::string{remote_member}, remote_member, member_content("B"),
                              {y.event_id}, {fixture.create_id(), fixture.pl_id(), b1.event_id}, 6, 12);
    auto const u = make_remote_message_pdu(room, {z.event_id}, fixture.auth_ids(), 7, 13);
    auto const t = make_remote_message_pdu(room, {u.event_id}, fixture.auth_ids(), 8, 14);
    auto const pdu = make_remote_message_pdu(room, {t.event_id}, fixture.auth_ids(), 9, 20);
    auto const sentinel = make_remote_message_pdu(room, {fixture.bob_member_id()}, fixture.auth_ids(), 4, 30);

    auto script = PeerScript{};
    script.events = {
        {z.event_id, z.json},
        {u.event_id, u.json},
        {t.event_id, t.json}
    };
    if (serve_b1)
    {
        script.events[b1.event_id] = b1.json;
    }
    auto pdu_ids = fixture.genesis_state_ids();
    std::erase(pdu_ids, fixture.bob_member_id());
    pdu_ids.push_back(z.event_id);
    auto auth_chain_ids = fixture.auth_ids();
    auth_chain_ids.push_back(b1.event_id);
    script.state_ids[u.event_id] = make_state_ids_response(pdu_ids, auth_chain_ids);
    auto const peer = fixture.serve(script);

    auto const result = fixture.ingest(pdu);
    auto const requests = peer->requests();
    auto const& runtime = fixture.runtime();

    CHECK(count_requests_starting_with(requests, "GET /_matrix/federation/v1/event_auth/") == 0U);
    CHECK(std::ranges::any_of(requests, [&](std::string const& request) {
        return request.starts_with("GET /_matrix/federation/v1/event/" +
                                   core::percent_encode_path_component(b1.event_id) + " ");
    }));

    if (serve_b1)
    {
        CHECK(result.status == PduIngestionStatus::accepted);
        CHECK(stored_status(runtime, b1.event_id).value_or(std::string{}) == "outlier");
        // ADR-0070: Z was judged against its own auth_events only, so no
        // after-state is recorded for it.
        CHECK(stored_status(runtime, z.event_id).value_or(std::string{}) == "outlier");
        CHECK_FALSE(fixture.has_state_group(z.event_id));
        CHECK(fixture.has_state_group(u.event_id));
        CHECK(fixture.has_state_group(t.event_id));
    }
    else
    {
        // The auth chain the origin listed cannot be completed, so none of the
        // events that depend on it is stored: not Z, not the events above it.
        CHECK(result.status != PduIngestionStatus::accepted);
        for (auto const* id : {&b1.event_id, &z.event_id, &u.event_id, &t.event_id})
        {
            CHECK_FALSE(stored_status(runtime, *id).has_value());
        }
        // The failed attempt leaves the room as it was: an event on the known
        // history is still placed and accepted.
        auto const after = fixture.ingest(sentinel);
        CHECK(after.status == PduIngestionStatus::accepted);
    }
}

SCENARIO("A /state_ids snapshot's auth chain and state events are fetched with /event, not /event_auth",
         "[pdu_ingestion][backfill][a8_snapshot_by_event]")
{
    GIVEN("a snapshot naming an auth chain event and a state event this server has never seen")
    {
        exercise_snapshot_auth_chain(true);
    }
}

SCENARIO("A snapshot whose auth chain the origin will not supply stores nothing that depends on it",
         "[pdu_ingestion][backfill][a8_snapshot_by_event]")
{
    GIVEN("a snapshot naming an auth chain event the origin answers 404 for")
    {
        exercise_snapshot_auth_chain(false);
    }
}

// Spec: server-server-api.md "Rejection": "Subsequent events from other servers
// that reference rejected events should be allowed if they still pass the auth
// rules"; and room version auth rule 2.3 (rooms/v10.md): an event whose
// auth_events include one that was itself rejected is rejected. A rejected event
// is stored, not dropped, so that events naming it as a prev_event can be placed.
SCENARIO("An event with a rejected auth event is stored rejected and a later event on top of it is accepted",
         "[pdu_ingestion][backfill][a8_rejected_auth_event]")
{
    GIVEN("a power_levels event this server rejected and an outlier that names it as an auth event")
    {
        auto fixture = RecoveryFixture{"!a8-rejected-auth:local.example.org"};
        auto const& room = fixture.room_id;

        auto raised = canonicaljson::Object{};
        raised.push_back(canonicaljson::make_member(std::string{local_admin}, canonicaljson::Value{std::int64_t{100}}));
        raised.push_back(
            canonicaljson::make_member(std::string{remote_member}, canonicaljson::Value{std::int64_t{100}}));
        auto levels = canonicaljson::Object{};
        levels.push_back(canonicaljson::make_member("users", canonicaljson::Value{std::move(raised)}));
        auto const rejected_levels =
            make_remote_event_pdu(room, "m.room.power_levels", std::string{}, remote_member, std::move(levels),
                                  {fixture.bob_member_id()}, fixture.auth_ids(), 4, 10);
        auto const outlier = make_remote_event_pdu(
            room, "m.room.member", std::string{remote_member}, remote_member, member_content("outlier"),
            {fixture.bob_member_id()}, {fixture.create_id(), rejected_levels.event_id, fixture.bob_member_id()}, 5, 11);
        auto const outlier_auth = std::vector<std::string>{fixture.create_id(), fixture.pl_id(), outlier.event_id};
        auto const first = make_remote_message_pdu(room, {fixture.bob_member_id()}, outlier_auth, 6, 12);
        auto const second = make_remote_message_pdu(room, {first.event_id}, outlier_auth, 7, 13);
        auto const sentinel = make_remote_message_pdu(room, {second.event_id}, fixture.auth_ids(), 8, 14);

        AND_GIVEN("a sending server that serves /event for the outlier and nothing else")
        {
            auto script = PeerScript{};
            script.events = {
                {outlier.event_id, outlier.json}
            };
            auto const peer = fixture.serve(script);
            REQUIRE(fixture.ingest(rejected_levels).status == PduIngestionStatus::rejected_auth);

            WHEN("two events that name the outlier arrive, then an event on top of them")
            {
                auto const first_result = fixture.ingest(first);
                auto const second_result = fixture.ingest(second);
                auto const sentinel_result = fixture.ingest(sentinel);
                auto const requests = peer->requests();
                auto const& runtime = fixture.runtime();

                THEN("the outlier and both events that name it are stored as rejected")
                {
                    CHECK(stored_status(runtime, outlier.event_id).value_or(std::string{}) == "rejected");
                    CHECK(stored_status(runtime, first.event_id).value_or(std::string{}) == "rejected");
                    CHECK(stored_status(runtime, second.event_id).value_or(std::string{}) == "rejected");
                    CHECK(first_result.status == PduIngestionStatus::rejected_auth);
                    CHECK(second_result.status == PduIngestionStatus::rejected_auth);
                }

                THEN("the event on top of a rejected prev_event is placed and accepted")
                {
                    CHECK(sentinel_result.status == PduIngestionStatus::accepted);
                    CHECK(stored_status(runtime, sentinel.event_id).value_or(std::string{}) == "accepted");
                }

                THEN("no rejected event changed the room's power levels")
                {
                    auto const& state = runtime.database.persistent_store.state;
                    auto const levels_entry =
                        std::ranges::find_if(state, [&](database::PersistentStateEvent const& entry) {
                            return entry.room_id == room && entry.event_type == "m.room.power_levels";
                        });
                    REQUIRE(levels_entry != state.end());
                    CHECK(levels_entry->event_id == fixture.pl_id());
                }

                THEN("the only request the sending server saw was the /event fetch of the outlier")
                {
                    CHECK(requests.size() == 1U);
                    CHECK(count_requests_starting_with(requests, "GET /_matrix/federation/v1/event/") == 1U);
                }
            }
        }
    }
}

// Spec: server-server-api.md POST /get_missing_events, GET /state_ids.
// /get_missing_events returns a window of the events before the PDU; the window
// does not reach history this server has, so its oldest event's prev_event is
// the gap and the state is asked there, once. Every event in the window is then
// placed oldest first and the PDU is accepted.
SCENARIO("Backfill places a /get_missing_events window that does not reach known history through one state request",
         "[pdu_ingestion][backfill][a8_window_beyond_gme]")
{
    GIVEN("a chain of thirty events of which /get_missing_events returns the newest twenty")
    {
        auto fixture = RecoveryFixture{"!a8-window:local.example.org"};
        auto const& room = fixture.room_id;
        auto chain = std::vector<InboundPduEnvelope>{};
        auto prev = fixture.bob_member_id();
        for (auto index = 1; index <= 30; ++index)
        {
            chain.push_back(make_remote_message_pdu(room, {prev}, fixture.auth_ids(), 3 + index, 10 + index));
            prev = chain.back().event_id;
        }
        auto const pdu = make_remote_message_pdu(room, {prev}, fixture.auth_ids(), 40, 60);
        // The tenth event is the newest one the window does not reach.
        auto const& gap = chain[9];

        auto script = PeerScript{};
        script.events = {
            {gap.event_id, gap.json}
        };
        script.state_ids[gap.event_id] = make_state_ids_response(fixture.genesis_state_ids(), fixture.auth_ids());
        script.missing_events = [&](std::string const& latest) {
            if (latest != pdu.event_id)
            {
                return std::string{};
            }
            auto window = std::vector<std::string>{};
            for (auto index = std::size_t{30U}; index > 10U; --index)
            {
                window.push_back(chain[index - 1U].json);
            }
            return events_array_body(window);
        };
        auto const peer = fixture.serve(script);

        WHEN("the PDU is ingested")
        {
            auto const result = fixture.ingest(pdu);
            auto const requests = peer->requests();

            THEN("the PDU is accepted and every event of the chain from the gap up is placed")
            {
                CHECK(result.status == PduIngestionStatus::accepted);
                for (auto index = std::size_t{9U}; index < chain.size(); ++index)
                {
                    CHECK(fixture.has_state_group(chain[index].event_id));
                }
            }

            THEN("one state request was made, at the gap, and /event_auth was not used")
            {
                CHECK(count_requests_starting_with(requests, "GET /_matrix/federation/v1/state_ids/") == 1U);
                CHECK(count_requests_starting_with(requests, "GET /_matrix/federation/v1/event_auth/") == 0U);
                CHECK(state_asked_at(requests, gap.event_id));
            }
        }
    }
}

// The last resort. A snapshot's state event Z has no known state-before and
// names an auth event B1 that neither the snapshot's auth chain nor the origin's
// /event lists, so Z cannot be judged against its own auth_events. GET /event_auth
// returns the auth chain in one call. `forged` makes that chain carry, alongside
// B1, a copy of a stored event under the stored event's "event_id" with its join
// turned into a ban: a field the signature covers, so it no longer verifies.
// Only an event identical to the stored one may skip verification.
auto exercise_event_auth_last_resort(bool forged) -> void
{
    auto fixture = RecoveryFixture{forged ? "!a8-event-auth-forged:local.example.org"
                                          : "!a8-event-auth-genuine:local.example.org"};
    auto const& room = fixture.room_id;
    auto const b1 = make_remote_event_pdu(room, "m.room.member", std::string{remote_member}, remote_member,
                                          member_content("A"), {fixture.bob_member_id()}, fixture.auth_ids(), 4, 10);
    auto const y = make_remote_message_pdu(room, {b1.event_id}, fixture.auth_ids(), 5, 11);
    auto const z =
        make_remote_event_pdu(room, "m.room.member", std::string{remote_member}, remote_member, member_content("B"),
                              {y.event_id}, {fixture.create_id(), fixture.pl_id(), b1.event_id}, 6, 12);
    auto const u = make_remote_message_pdu(room, {z.event_id}, fixture.auth_ids(), 7, 13);
    auto const t = make_remote_message_pdu(room, {u.event_id}, fixture.auth_ids(), 8, 14);
    auto const pdu = make_remote_message_pdu(room, {t.event_id}, fixture.auth_ids(), 9, 20);

    auto chain = std::vector<std::string>{};
    if (forged)
    {
        auto const& stored = fixture.runtime().database.persistent_store.events;
        auto const member_bob = std::ranges::find_if(stored, [&](database::PersistentEvent const& event) {
            return event.event_id == fixture.bob_member_id();
        });
        REQUIRE(member_bob != stored.end());
        auto forged_member_bob = member_bob->json;
        auto const membership_at = forged_member_bob.find(R"("membership":"join")");
        REQUIRE(membership_at != std::string::npos);
        forged_member_bob.replace(membership_at, std::string_view{R"("membership":"join")"}.size(),
                                  R"("membership":"ban")");
        chain.push_back(forged_member_bob);
    }
    chain.push_back(b1.json);

    auto script = PeerScript{};
    script.events = {
        {z.event_id, z.json},
        {u.event_id, u.json},
        {t.event_id, t.json}
    };
    auto pdu_ids = fixture.genesis_state_ids();
    std::erase(pdu_ids, fixture.bob_member_id());
    pdu_ids.push_back(z.event_id);
    script.state_ids[u.event_id] = make_state_ids_response(pdu_ids, fixture.auth_ids());
    script.event_auth = make_event_auth_response(chain);
    auto const peer = fixture.serve(script);

    auto const result = fixture.ingest(pdu);
    auto const requests = peer->requests();
    auto const& runtime = fixture.runtime();

    CHECK(count_requests_starting_with(requests, "GET /_matrix/federation/v1/event_auth/") == 1U);
    if (forged)
    {
        CHECK(result.status != PduIngestionStatus::accepted);
        CHECK_FALSE(stored_status(runtime, z.event_id).has_value());
        CHECK_FALSE(stored_status(runtime, b1.event_id).has_value());
        CHECK_FALSE(stored_status(runtime, u.event_id).has_value());
    }
    else
    {
        CHECK(result.status == PduIngestionStatus::accepted);
        CHECK(stored_status(runtime, z.event_id).value_or(std::string{}) == "outlier");
        CHECK_FALSE(fixture.has_state_group(z.event_id));
        CHECK(fixture.has_state_group(u.event_id));
    }
}

SCENARIO("A snapshot state event whose auth events nobody listed is verified through /event_auth as a last resort",
         "[pdu_ingestion][backfill][a8_event_auth_last_resort]")
{
    GIVEN("a state event whose auth event is in neither the snapshot's auth chain nor served by /event")
    {
        exercise_event_auth_last_resort(false);
    }
}

SCENARIO("An /event_auth entry reusing a stored event's ID with different content is verified, not trusted",
         "[pdu_ingestion][backfill][event_auth_forged_id][a8_event_auth_last_resort]")
{
    GIVEN("an /event_auth chain carrying a forged copy of a stored event")
    {
        exercise_event_auth_last_resort(true);
    }
}

// Spec: server-server-api.md "Rejection": "The state used in the checks should be
// calculated as normal, except not updating with the rejected event", so a
// rejected event's after-state is its state-before, and later events that
// reference it "should be allowed if they still pass the auth rules" (ADR-0256).
// A rejected event can be stored with no state group: a /state_ids snapshot
// lists it in its auth chain, its prev_event is unknown so its state-before is
// too, and it is judged against its own auth_events only (ADR-0069, ADR-0070).
// When a later snapshot supplies the state before it, it must gain the group, or
// an event that names it as its prev_event stays unplaceable for ever.
SCENARIO("A rejected event stored without a state group gains one when a snapshot supplies its state-before",
         "[pdu_ingestion][backfill][a8_rejected_outlier_promoted]")
{
    GIVEN("a rejected power_levels event, and a snapshot auth chain event that names it, so is stored rejected "
          "with no state group")
    {
        auto fixture = RecoveryFixture{"!a8-rejected-promoted:local.example.org"};
        auto const& room = fixture.room_id;

        auto raised = canonicaljson::Object{};
        raised.push_back(canonicaljson::make_member(std::string{local_admin}, canonicaljson::Value{std::int64_t{100}}));
        raised.push_back(
            canonicaljson::make_member(std::string{remote_member}, canonicaljson::Value{std::int64_t{100}}));
        auto levels = canonicaljson::Object{};
        levels.push_back(canonicaljson::make_member("users", canonicaljson::Value{std::move(raised)}));
        auto const rejected_levels =
            make_remote_event_pdu(room, "m.room.power_levels", std::string{}, remote_member, std::move(levels),
                                  {fixture.bob_member_id()}, fixture.auth_ids(), 4, 10);
        // The rejected event's own prev_event is one nobody can supply.
        auto const unseen = make_remote_message_pdu(room, {fixture.bob_member_id()}, fixture.auth_ids(), 5, 11);
        auto const rejected = make_remote_event_pdu(
            room, "m.room.member", std::string{remote_member}, remote_member, member_content("rejected"),
            {unseen.event_id}, {fixture.create_id(), rejected_levels.event_id, fixture.bob_member_id()}, 6, 12);
        auto const target = make_remote_message_pdu(room, {fixture.bob_member_id()}, fixture.auth_ids(), 7, 13);
        auto const held = make_remote_message_pdu(room, {target.event_id}, fixture.auth_ids(), 8, 14);
        auto const first = make_remote_message_pdu(room, {held.event_id}, fixture.auth_ids(), 9, 15);
        auto const after_rejected = make_remote_message_pdu(room, {rejected.event_id}, fixture.auth_ids(), 7, 20);

        auto auth_chain_ids = fixture.auth_ids();
        auth_chain_ids.push_back(rejected.event_id);
        auto script = PeerScript{};
        script.events = {
            {rejected.event_id, rejected.json},
            {target.event_id,   target.json  },
            {held.event_id,     held.json    }
        };
        script.state_ids[target.event_id] = make_state_ids_response(fixture.genesis_state_ids(), auth_chain_ids);
        script.state_ids[rejected.event_id] = make_state_ids_response(fixture.genesis_state_ids(), fixture.auth_ids());
        auto const peer = fixture.serve(script);
        auto const& runtime = fixture.runtime();

        REQUIRE(fixture.ingest(rejected_levels).status == PduIngestionStatus::rejected_auth);
        REQUIRE(fixture.ingest(first).status == PduIngestionStatus::accepted);
        REQUIRE(stored_status(runtime, rejected.event_id).value_or(std::string{}) == "rejected");
        REQUIRE_FALSE(fixture.has_state_group(rejected.event_id));

        WHEN("an event whose only prev_event is the rejected event arrives and the state is asked at it")
        {
            auto const result = fixture.ingest(after_rejected);
            auto const requests = peer->requests();

            THEN("the rejected event gains a state group and stays rejected")
            {
                CHECK(state_asked_at(requests, rejected.event_id));
                CHECK(fixture.has_state_group(rejected.event_id));
                CHECK(stored_status(runtime, rejected.event_id).value_or(std::string{}) == "rejected");
            }

            THEN("the event on top of it is placed and accepted")
            {
                CHECK(result.status == PduIngestionStatus::accepted);
                CHECK(stored_status(runtime, after_rejected.event_id).value_or(std::string{}) == "accepted");
            }

            THEN("the rejected event changed neither the power levels nor the sender's membership")
            {
                auto const& state = runtime.database.persistent_store.state;
                auto const state_event_id = [&](std::string_view type, std::string_view state_key) {
                    auto const entry = std::ranges::find_if(state, [&](database::PersistentStateEvent const& item) {
                        return item.room_id == room && item.event_type == type && item.state_key == state_key;
                    });
                    return entry == state.end() ? std::string{} : entry->event_id;
                };
                CHECK(state_event_id("m.room.power_levels", "") == fixture.pl_id());
                CHECK(state_event_id("m.room.member", remote_member) == fixture.bob_member_id());
            }
        }
    }
}

} // namespace
