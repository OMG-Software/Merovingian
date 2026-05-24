// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/core/query_params.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/federation/event_query.hpp"
#include "merovingian/federation/inbound_ingestion.hpp"
#include "merovingian/federation/key_query.hpp"
#include "merovingian/federation/remote_key_cache.hpp"
#include "merovingian/homeserver/vertical_slice.hpp"
#include "merovingian/observability/logger.hpp"
#include "merovingian/observability/observability.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

namespace merovingian::homeserver
{
namespace
{

    auto log_diagnostic(std::string_view event, std::vector<observability::StructuredLogField> fields) -> void
    {
        LOG_DEBUG(observability::diagnostic_log_summary("local_router", event, std::move(fields)));
    }

    [[nodiscard]] auto response(std::uint16_t status, std::string body) -> LocalHttpResponse
    {
        return {status, std::move(body)};
    }

    [[nodiscard]] auto response_from_operation(OperationResult const& result, std::uint16_t ok_status = 200U)
        -> LocalHttpResponse
    {
        return result.ok ? response(ok_status, result.value) : response(result.status, result.reason);
    }

    [[nodiscard]] auto response_from_media_operation(OperationResult const& result) -> LocalHttpResponse
    {
        return response(result.status, result.ok ? result.value : result.reason);
    }

    [[nodiscard]] auto starts_with(std::string_view value, std::string_view prefix) noexcept -> bool
    {
        return value.size() >= prefix.size() && value.substr(0U, prefix.size()) == prefix;
    }

    [[nodiscard]] auto split_pipe_2(std::string_view body) -> std::optional<std::array<std::string_view, 2U>>
    {
        auto const first = body.find('|');
        if (first == std::string_view::npos || first == 0U || first + 1U >= body.size())
        {
            return std::nullopt;
        }
        return std::array<std::string_view, 2U>{body.substr(0U, first), body.substr(first + 1U)};
    }

    [[nodiscard]] auto split_pipe_3(std::string_view body) -> std::optional<std::array<std::string_view, 3U>>
    {
        auto const first = body.find('|');
        auto const second = first == std::string_view::npos ? std::string_view::npos : body.find('|', first + 1U);
        if (first == std::string_view::npos || first == 0U || second == std::string_view::npos ||
            second == first + 1U || second + 1U >= body.size())
        {
            return std::nullopt;
        }
        return std::array<std::string_view, 3U>{body.substr(0U, first), body.substr(first + 1U, second - first - 1U),
                                                body.substr(second + 1U)};
    }

    [[nodiscard]] auto split_pipe_4(std::string_view body) -> std::optional<std::array<std::string_view, 4U>>
    {
        auto fields = std::array<std::string_view, 4U>{};
        auto remaining = body;
        for (auto index = std::size_t{0U}; index < fields.size(); ++index)
        {
            if (index + 1U == fields.size())
            {
                fields[index] = remaining;
                break;
            }
            auto const separator = remaining.find('|');
            if (separator == std::string_view::npos)
            {
                return std::nullopt;
            }
            fields[index] = remaining.substr(0U, separator);
            remaining = remaining.substr(separator + 1U);
        }
        for (auto const field : fields)
        {
            if (field.empty())
            {
                return std::nullopt;
            }
        }
        return fields;
    }

    [[nodiscard]] auto split_pipe_6(std::string_view body) -> std::optional<std::array<std::string_view, 6U>>
    {
        auto fields = std::array<std::string_view, 6U>{};
        auto remaining = body;
        for (auto index = std::size_t{0U}; index < fields.size(); ++index)
        {
            auto const separator = remaining.find('|');
            if (index + 1U == fields.size())
            {
                fields[index] = remaining;
                break;
            }
            if (separator == std::string_view::npos)
            {
                return std::nullopt;
            }
            fields[index] = remaining.substr(0U, separator);
            remaining = remaining.substr(separator + 1U);
        }
        for (auto const field : fields)
        {
            if (field.empty())
            {
                return std::nullopt;
            }
        }
        return fields;
    }

    [[nodiscard]] auto parse_u64(std::string_view value) noexcept -> std::optional<std::uint64_t>
    {
        if (value.empty())
        {
            return std::nullopt;
        }
        auto result = std::uint64_t{0U};
        for (auto const character : value)
        {
            if (character < '0' || character > '9')
            {
                return std::nullopt;
            }
            auto const digit = static_cast<std::uint64_t>(character - '0');
            if (result > (std::numeric_limits<std::uint64_t>::max() - digit) / 10U)
            {
                return std::nullopt;
            }
            result = (result * 10U) + digit;
        }
        return result;
    }

    [[nodiscard]] auto parse_bool_flag(std::string_view value) noexcept -> std::optional<bool>
    {
        if (value == "canonical" || value == "true" || value == "clean")
        {
            return true;
        }
        if (value == "uncanonical" || value == "false" || value == "dirty")
        {
            return false;
        }
        return std::nullopt;
    }

    // Pipe-delimited federation auth token used by integration-test fixtures:
    // origin|key_id|signature|destination|now_ts|canonical_json_verified.
    [[nodiscard]] auto parse_signed_federation_request(LocalHttpRequest const& request)
        -> std::optional<federation::SignedFederationRequest>
    {
        auto const fields = split_pipe_6(request.access_token);
        if (!fields.has_value())
        {
            return std::nullopt;
        }
        auto const now_ts = parse_u64((*fields)[4]);
        auto const canonical_json_verified = parse_bool_flag((*fields)[5]);
        if (!now_ts.has_value() || !canonical_json_verified.has_value())
        {
            return std::nullopt;
        }
        auto signed_request = federation::SignedFederationRequest{};
        signed_request.method = request.method;
        signed_request.target = request.target;
        signed_request.origin = std::string{(*fields)[0]};
        signed_request.key_id = std::string{(*fields)[1]};
        signed_request.signature = std::string{(*fields)[2]};
        signed_request.destination = std::string{(*fields)[3]};
        signed_request.now_ts = *now_ts;
        signed_request.canonical_json_verified = *canonical_json_verified;
        signed_request.body = request.body;
        return signed_request;
    }

    [[nodiscard]] auto path_suffix(std::string_view target, std::string_view prefix) noexcept -> std::string_view
    {
        return starts_with(target, prefix) ? target.substr(prefix.size()) : std::string_view{};
    }

    [[nodiscard]] auto local_media_download_parts(std::string_view suffix)
        -> std::optional<std::array<std::string_view, 2U>>
    {
        auto const separator = suffix.find('/');
        if (separator == std::string_view::npos || separator == 0U || separator + 1U >= suffix.size())
        {
            return std::nullopt;
        }
        auto const server_name = suffix.substr(0U, separator);
        auto const media_id = suffix.substr(separator + 1U);
        if (media_id.find('/') != std::string_view::npos)
        {
            return std::nullopt;
        }
        return std::array<std::string_view, 2U>{server_name, media_id};
    }

    // Wires all FederationRuntimeState callbacks to production implementations.
    // Called lazily on the first federation request so the runtime is already
    // at a stable address when the lambdas capture references to its fields.
    // Idempotent: the pdu_sink check guards against double-wiring.
    auto wire_federation_callbacks_impl(HomeserverRuntime& runtime) -> void
    {
        if (!runtime.federation.config.enabled || runtime.federation.pdu_sink)
        {
            return;
        }
        // Capture the runtime by pointer for all lambdas — safe because the
        // callbacks are stored inside the same runtime object, which outlives
        // every call made through handle_federation_http_request.
        auto* rt = &runtime;
        auto* outbound = runtime.outbound_client.get();
        auto* discovery = runtime.discovery_network.get();
        auto const timeout = runtime.federation.config.remote_timeout_seconds;

        runtime.federation.pdu_sink = [rt](federation::InboundPduEnvelope const& envelope)
            -> federation::PduIngestionResult {
            auto event = database::PersistentEvent{};
            event.event_id = envelope.event_id;
            event.room_id = envelope.room_id;
            event.sender_user_id = envelope.sender;
            event.json = envelope.json;
            event.depth = envelope.depth;
            event.stream_ordering = rt->database.next_stream_ordering++;
            event.prev_event_ids = envelope.prev_event_ids;
            event.auth_event_ids = envelope.auth_event_ids;
            event.signatures = envelope.signatures;
            auto state = std::optional<database::PersistentStateEvent>{};
            if (envelope.state_key.has_value())
            {
                state = database::PersistentStateEvent{envelope.room_id, envelope.event_type, *envelope.state_key,
                                                       envelope.event_id};
            }
            if (!database::store_event_with_state(rt->database.persistent_store, std::move(event), state))
            {
                return {federation::PduIngestionStatus::internal_error, "event persistence failed"};
            }
            if (rt->sync_notifier != nullptr)
            {
                rt->sync_notifier->publish(rt->database.persistent_store.next_sync_stream_id);
            }
            return {federation::PduIngestionStatus::accepted, {}};
        };

        runtime.federation.state_conflict_resolver = [rt](federation::PduStateConflictContext const& context)
            -> federation::PduIngestionResult {
            return federation::apply_state_resolution_v2(
                context,
                [rt, room_id = context.incoming_pdu.room_id](
                    std::vector<events::StateEventReference> const& resolved) -> bool {
                    for (auto const& ref : resolved)
                    {
                        if (!database::store_state(rt->database.persistent_store,
                                                   {room_id, ref.key.event_type, ref.key.state_key, ref.event_id}))
                        {
                            return false;
                        }
                    }
                    return true;
                });
        };

        runtime.federation.membership_template_provider =
            [rt](federation::FederationEndpoint endpoint, std::string_view room_id, std::string_view user_id,
                 std::vector<std::string> const& /*supported_versions*/)
            -> std::optional<federation::MembershipEventTemplate> {
            auto const& store = rt->database.persistent_store;
            auto const room_it =
                std::ranges::find_if(store.rooms, [&room_id](database::PersistentRoom const& r) {
                    return r.room_id == room_id;
                });
            if (room_it == store.rooms.end())
            {
                return std::nullopt;
            }
            auto tmpl = federation::MembershipEventTemplate{};
            tmpl.room_id = std::string{room_id};
            tmpl.user_id = std::string{user_id};
            tmpl.room_version = "12";
            if (endpoint == federation::FederationEndpoint::make_join)
            {
                tmpl.membership = "join";
            }
            else if (endpoint == federation::FederationEndpoint::make_leave)
            {
                tmpl.membership = "leave";
            }
            else
            {
                tmpl.membership = "knock";
            }
            for (auto const& evt : store.events)
            {
                if (evt.room_id == room_id)
                {
                    tmpl.prev_events.push_back(evt.event_id);
                }
            }
            tmpl.content_json = "{\"membership\":\"" + tmpl.membership + "\"}";
            return tmpl;
        };

        runtime.federation.membership_acceptor =
            [rt](federation::FederationEndpoint endpoint, std::string_view room_id, std::string_view event_id,
                 federation::InboundPduEnvelope const& envelope) -> federation::MembershipAcceptResult {
            auto& store = rt->database.persistent_store;
            auto const room_it =
                std::ranges::find_if(store.rooms, [&room_id](database::PersistentRoom const& r) {
                    return r.room_id == room_id;
                });
            if (room_it == store.rooms.end())
            {
                return {false, 404U, "room not found", {}, {}};
            }
            auto event = database::PersistentEvent{};
            event.event_id = envelope.event_id;
            event.room_id = envelope.room_id;
            event.sender_user_id = envelope.sender;
            event.json = envelope.json;
            event.depth = envelope.depth;
            auto state = std::optional<database::PersistentStateEvent>{};
            if (envelope.state_key.has_value())
            {
                state = database::PersistentStateEvent{envelope.room_id, envelope.event_type, *envelope.state_key,
                                                       std::string{event_id}};
            }
            if (!database::store_event_with_state(store, std::move(event), state))
            {
                return {false, 500U, "event persistence failed", {}, {}};
            }
            auto auth_chain = std::vector<std::string>{};
            auto state_events = std::vector<std::string>{};
            if (endpoint == federation::FederationEndpoint::send_join)
            {
                for (auto const& evt : store.events)
                {
                    if (evt.room_id == room_id && !evt.json.empty())
                    {
                        auth_chain.push_back(evt.json);
                    }
                }
                for (auto const& s : store.state)
                {
                    if (s.room_id == room_id)
                    {
                        for (auto const& evt : store.events)
                        {
                            if (evt.event_id == s.event_id && !evt.json.empty())
                            {
                                state_events.push_back(evt.json);
                                break;
                            }
                        }
                    }
                }
            }
            return {true, 200U, {}, std::move(auth_chain), std::move(state_events)};
        };

        // Sign the invite event with the local server key. The signing path will be
        // fully wired once the signing service is plumbed through the vertical slice.
        // For now the invite JSON is echoed back unsigned which satisfies v1 invites.
        runtime.federation.invite_handler = [](federation::InviteRequest const& invite)
            -> federation::InviteAcceptResult {
            return {true, 200U, {}, invite.invite_event_json};
        };

        runtime.federation.backfill_provider = [rt](federation::BackfillRequest const& req)
            -> federation::BackfillResult {
            auto const& store = rt->database.persistent_store;
            auto pdus = std::vector<std::string>{};
            for (auto const& requested_id : req.event_ids)
            {
                for (auto const& evt : store.events)
                {
                    if (evt.event_id == requested_id && !evt.json.empty())
                    {
                        pdus.push_back(evt.json);
                        break;
                    }
                }
                if (pdus.size() >= req.limit)
                {
                    break;
                }
            }
            return {true, 200U, {}, std::move(pdus)};
        };

        runtime.federation.profile_query_provider =
            [rt](std::string_view user_id) -> federation::FederationProfile {
            auto const profile = database::find_profile(rt->database.persistent_store, user_id);
            if (!profile.has_value())
            {
                return {};
            }
            return {true, profile->displayname, profile->avatar_url};
        };

        runtime.federation.device_keys_query_provider = [rt](std::string_view body) -> std::string {
            return federation::build_device_keys_query_response(rt->database.persistent_store, body);
        };

        runtime.federation.one_time_keys_claim_provider = [rt](std::string_view body) -> std::string {
            return federation::build_one_time_keys_claim_response(rt->database.persistent_store, body);
        };

        runtime.federation.user_devices_provider = [rt](std::string_view user_id) -> std::string {
            return federation::build_user_devices_response(rt->database.persistent_store, user_id);
        };

        runtime.federation.event_query_provider = [rt](std::string_view event_id) -> std::string {
            return federation::build_event_response(rt->database.persistent_store, event_id,
                                                    rt->config.server().server_name);
        };

        runtime.federation.state_query_provider = [rt](std::string_view room_id) -> std::string {
            return federation::build_state_response(rt->database.persistent_store, room_id);
        };

        runtime.federation.state_ids_query_provider = [rt](std::string_view room_id) -> std::string {
            return federation::build_state_ids_response(rt->database.persistent_store, room_id);
        };

        runtime.federation.missing_events_query_provider =
            [rt](std::string_view room_id, std::string_view body) -> std::string {
            return federation::build_get_missing_events_response(rt->database.persistent_store, room_id, body);
        };

        if (outbound && discovery)
        {
            runtime.federation.remote_key_resolver = federation::make_persistent_remote_key_resolver(
                runtime.database.persistent_store, *outbound, *discovery, timeout, [] {
                    return static_cast<std::uint64_t>(
                        std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::system_clock::now().time_since_epoch())
                            .count());
                });
            std::ignore = ensure_runtime_server_signing_key(runtime);
            auto dispatch_config = federation::DispatchWorkerConfig{};
            dispatch_config.origin = runtime.config.server().server_name;
            dispatch_config.key_id = "ed25519:auto";
            dispatch_config.secret_key =
                std::string{reinterpret_cast<char const*>(runtime.database.signing_secret_key.data()),
                             runtime.database.signing_secret_key.size()};
            auto* discovery_ptr = discovery;
            auto const discovery_timeout = timeout > 0U ? timeout : 30U;
            auto resolver = [discovery_ptr, discovery_timeout](std::string_view server_name)
                -> std::optional<federation::ServerDiscoveryResult> {
                auto result = federation::discover_server(server_name, *discovery_ptr, discovery_timeout);
                if (!result.discovery_allowed)
                {
                    return std::nullopt;
                }
                return result;
            };
            auto clock = []() -> std::uint64_t {
                return static_cast<std::uint64_t>(
                    std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::system_clock::now().time_since_epoch())
                        .count());
            };
            auto sleep_fn = [](std::chrono::milliseconds ms) { std::this_thread::sleep_for(ms); };
            runtime.dispatch_worker = std::make_unique<federation::DispatchWorker>(
                std::move(dispatch_config), *outbound, std::move(resolver), std::move(clock), std::move(sleep_fn),
                &runtime.database.persistent_store);
            runtime.dispatch_worker->start();
        }
    }

} // namespace

auto wire_federation_callbacks(HomeserverRuntime& runtime) -> void
{
    wire_federation_callbacks_impl(runtime);
}

[[nodiscard]] auto handle_local_http_request(HomeserverRuntime& runtime, LocalHttpRequest const& request)
    -> LocalHttpResponse
{
    log_diagnostic("request.received",
                   {
                       {"method",           request.method,                                       false},
                       {"target",           observability::sanitized_http_target(request.target), false},
                       {"body_bytes",       std::to_string(request.body.size()),                  false},
                       {"has_access_token", request.access_token.empty() ? "false" : "true",      false}
    });
    if (!runtime.started)
    {
        log_diagnostic("request.rejected", {
                                               {"method", request.method,                                       false},
                                               {"target", observability::sanitized_http_target(request.target), false},
                                               {"status", "503",                                                false},
                                               {"reason", "runtime not started",                                false}
        });
        return response(503U, "runtime not started");
    }
    if (request.method == "GET" && request.target == "/_merovingian/admin/health")
    {
        return authenticated_admin_user(runtime, request.access_token).has_value()
                   ? response(200U, admin_health_summary(runtime))
                   : response(401U, "admin authentication required");
    }
    if (request.method == "GET" && request.target == "/_merovingian/admin/media/metrics")
    {
        return authenticated_admin_user(runtime, request.access_token).has_value()
                   ? response(200U, media_metrics_summary(runtime))
                   : response(401U, "admin authentication required");
    }
    if (request.method == "GET" && request.target == "/_merovingian/admin/metrics")
    {
        return authenticated_admin_user(runtime, request.access_token).has_value()
                   ? response(200U, admin_metrics_summary(runtime))
                   : response(401U, "admin authentication required");
    }
    if (request.method == "GET" && request.target == "/_merovingian/admin/audit")
    {
        return authenticated_admin_user(runtime, request.access_token).has_value()
                   ? response(200U, admin_audit_summary(runtime))
                   : response(401U, "admin authentication required");
    }
    if (request.method == "GET" && request.target == "/_matrix/key/v2/server")
    {
        return response_from_operation(publish_server_signing_keys(runtime));
    }
    if (starts_with(request.target, "/_matrix/federation/"))
    {
        auto signed_request = parse_signed_federation_request(request);
        if (!signed_request.has_value())
        {
            log_diagnostic("federation.auth.rejected",
                           {
                               {"method", request.method,                                       false},
                               {"target", observability::sanitized_http_target(request.target), false},
                               {"status", "401",                                                false},
                               {"reason", "malformed federation authorization",                 false}
            });
            return response(401U, "malformed federation authorization");
        }
        auto const federation_response =
            federation::handle_inbound_federation_request(runtime.federation, *signed_request);
        log_diagnostic("federation.dispatched",
                       {
                           {"method", request.method,                                       false},
                           {"target", observability::sanitized_http_target(request.target), false},
                           {"origin", signed_request->origin,                               false},
                           {"status", std::to_string(federation_response.status),           false}
        });
        return response(federation_response.status, federation_response.body);
    }
    if (request.method == "POST" && request.target == "/_matrix/client/v3/register")
    {
        if (auto const fields = split_pipe_3(request.body); fields.has_value())
        {
            return response_from_operation(register_local_user(runtime, (*fields)[0], (*fields)[1], (*fields)[2]),
                                           200U);
        }
        auto const fields = split_pipe_2(request.body);
        return fields.has_value()
                   ? response_from_operation(register_local_user(runtime, (*fields)[0], (*fields)[1]), 200U)
                   : response(400U, "registration body must be localpart|password[|token]");
    }
    if (request.method == "POST" && request.target == "/_matrix/client/v3/login")
    {
        auto const fields = split_pipe_3(request.body);
        return fields.has_value()
                   ? response_from_operation(login_local_user(runtime, (*fields)[0], (*fields)[1], (*fields)[2]), 200U)
                   : response(400U, "login body must be user_id|password|device_id");
    }
    if (request.method == "POST" && request.target == "/_matrix/client/v3/logout")
    {
        auto result = logout_local_user(runtime, request.access_token);
        return result.ok ? response(200U, "logged out") : response(401U, result.reason);
    }
    if (request.method == "POST" && request.target == "/_matrix/media/v3/upload")
    {
        auto const fields = split_pipe_4(request.body);
        if (!fields.has_value())
        {
            return response(400U, "upload body must be declared_mime|sniffed_mime|scanner_clean|bytes");
        }
        auto const scanner_clean = parse_bool_flag((*fields)[2]);
        if (!scanner_clean.has_value())
        {
            return response(400U, "scanner_clean must be clean or dirty");
        }
        auto const result =
            upload_local_media(runtime, request.access_token, (*fields)[0], (*fields)[1], *scanner_clean, (*fields)[3]);
        return response_from_media_operation(result);
    }
    auto constexpr download_prefix = std::string_view{"/_matrix/media/v3/download/"};
    if (request.method == "GET" && starts_with(request.target, download_prefix))
    {
        auto const parts = local_media_download_parts(path_suffix(request.target, download_prefix));
        if (!parts.has_value())
        {
            return response(404U, "route not found");
        }
        auto const result = download_local_media(runtime, (*parts)[0], (*parts)[1]);
        return response_from_media_operation(result);
    }
    auto constexpr quarantine_prefix = std::string_view{"/_merovingian/admin/media/quarantine/"};
    if (request.method == "POST" && starts_with(request.target, quarantine_prefix))
    {
        auto const media_id = path_suffix(request.target, quarantine_prefix);
        auto const result = admin_quarantine_local_media(runtime, request.access_token, media_id, request.body);
        return response_from_media_operation(result);
    }
    auto constexpr release_prefix = std::string_view{"/_merovingian/admin/media/release/"};
    if (request.method == "POST" && starts_with(request.target, release_prefix))
    {
        auto const media_id = path_suffix(request.target, release_prefix);
        auto const result = admin_release_local_media(runtime, request.access_token, media_id);
        return response_from_media_operation(result);
    }
    auto constexpr remove_prefix = std::string_view{"/_merovingian/admin/media/remove/"};
    if (request.method == "POST" && starts_with(request.target, remove_prefix))
    {
        auto const media_id = path_suffix(request.target, remove_prefix);
        auto const result = admin_remove_local_media(runtime, request.access_token, media_id, request.body);
        return response_from_media_operation(result);
    }
    if (request.method == "POST" && request.target == "/_matrix/client/v3/createRoom")
    {
        auto result = create_room(runtime, request.access_token);
        return result.ok ? response(200U, result.value)
                         : response(result.status != 0U ? result.status : 403U, result.reason);
    }

    auto constexpr rooms_prefix = std::string_view{"/_matrix/client/v3/rooms/"};
    if (!starts_with(request.target, rooms_prefix))
    {
        log_diagnostic("request.route_not_found",
                       {
                           {"method", request.method,                                       false},
                           {"target", observability::sanitized_http_target(request.target), false},
                           {"status", "404",                                                false}
        });
        return response(404U, "route not found");
    }
    auto const suffix = std::string_view{request.target}.substr(rooms_prefix.size());
    auto constexpr join_suffix = std::string_view{"/join"};
    auto constexpr send_suffix = std::string_view{"/send"};
    auto constexpr state_suffix = std::string_view{"/state"};

    if (request.method == "POST" && suffix.size() > join_suffix.size() &&
        suffix.substr(suffix.size() - join_suffix.size()) == join_suffix)
    {
        auto const room_id = core::percent_decode_path_component(suffix.substr(0U, suffix.size() - join_suffix.size()));
        log_diagnostic("room.join.dispatch", {
                                                 {"room_id", room_id, false}
        });
        auto result = join_room(runtime, request.access_token, room_id);
        log_diagnostic(result.ok ? "room.join.accepted" : "room.join.rejected",
                       {
                           {"room_id", room_id,                                                    false},
                           {"status",  std::to_string(result.status != 0U ? result.status : 403U), false},
                           {"reason",  result.ok ? std::string{"ok"} : result.reason,              false}
        });
        return result.ok ? response(200U, result.value)
                         : response(result.status != 0U ? result.status : 403U, result.reason);
    }
    if (request.method == "POST" && suffix.size() > send_suffix.size() &&
        suffix.substr(suffix.size() - send_suffix.size()) == send_suffix)
    {
        auto const room_id = core::percent_decode_path_component(suffix.substr(0U, suffix.size() - send_suffix.size()));
        log_diagnostic("room.event.dispatch",
                       {
                           {"room_id",    room_id,                             false},
                           {"body_bytes", std::to_string(request.body.size()), false}
        });
        auto result = send_event(runtime, request.access_token, room_id, request.body);
        log_diagnostic(result.ok ? "room.event.accepted" : "room.event.rejected",
                       {
                           {"room_id", room_id,                                                    false},
                           {"status",  std::to_string(result.status != 0U ? result.status : 403U), false},
                           {"reason",  result.ok ? std::string{"ok"} : result.reason,              false}
        });
        return result.ok ? response(200U, result.value)
                         : response(result.status != 0U ? result.status : 403U, result.reason);
    }
    if (request.method == "GET" && suffix.size() > state_suffix.size() &&
        suffix.substr(suffix.size() - state_suffix.size()) == state_suffix)
    {
        auto const room_id =
            core::percent_decode_path_component(suffix.substr(0U, suffix.size() - state_suffix.size()));
        auto result = fetch_room_state(runtime, request.access_token, room_id);
        return result.ok ? response(200U, result.value)
                         : response(result.status != 0U ? result.status : 403U, result.reason);
    }
    log_diagnostic("request.route_not_found",
                   {
                       {"method", request.method,                                       false},
                       {"target", observability::sanitized_http_target(request.target), false},
                       {"status", "404",                                                false}
    });
    return response(404U, "route not found");
}

[[nodiscard]] auto handle_federation_http_request(HomeserverRuntime& runtime, LocalHttpRequest const& request)
    -> LocalHttpResponse
{
    if (!runtime.started)
    {
        return response(503U, "runtime not started");
    }
    wire_federation_callbacks_impl(runtime);
    if (request.method == "GET" && request.target == "/_matrix/key/v2/server")
    {
        return response_from_operation(publish_server_signing_keys(runtime));
    }
    if (starts_with(request.target, "/_matrix/federation/"))
    {
        // Primary path: real X-Matrix Authorization header from production traffic.
        // Fallback path: pipe-delimited token used by integration test fixtures.
        auto signed_request_opt = std::optional<federation::SignedFederationRequest>{};
        auto const x_matrix = federation::parse_x_matrix_authorization_header(request.access_token);
        if (x_matrix.has_value())
        {
            auto req = federation::SignedFederationRequest{};
            req.method = request.method;
            req.target = request.target;
            req.origin = x_matrix->origin;
            // The signed request object binds the destination to this server's
            // own name; the verifier must rebuild the payload with our name,
            // not the (untrusted) header claim, or a request signed for a
            // different server would verify here.
            req.destination = runtime.config.server().server_name;
            req.key_id = x_matrix->key_id;
            req.signature = x_matrix->signature;
            req.now_ts = static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                                        std::chrono::system_clock::now().time_since_epoch())
                                                        .count());
            req.canonical_json_verified = true;
            req.body = request.body;
            signed_request_opt = std::move(req);
        }
        else
        {
            signed_request_opt = parse_signed_federation_request(request);
        }
        if (!signed_request_opt.has_value())
        {
            return response(401U, "malformed federation authorization");
        }
        auto const federation_response =
            federation::handle_inbound_federation_request(runtime.federation, *signed_request_opt);
        return response(federation_response.status, federation_response.body);
    }
    return response(404U, "route not found");
}

} // namespace merovingian::homeserver
