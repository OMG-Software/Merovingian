// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/local_http_router.hpp"

#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/serializer.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/core/query_params.hpp"
#include "merovingian/crypto/ed25519.hpp"
#include "merovingian/crypto/signing_service.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/events/event_signer.hpp"
#include "merovingian/federation/event_query.hpp"
#include "merovingian/federation/inbound_ingestion.hpp"
#include "merovingian/federation/key_query.hpp"
#include "merovingian/federation/remote_key_cache.hpp"
#include "merovingian/homeserver/auth_service.hpp"
#include "merovingian/homeserver/media_service.hpp"
#include "merovingian/homeserver/room_service.hpp"
#include "merovingian/observability/logger.hpp"
#include "merovingian/observability/observability.hpp"
#include "merovingian/rooms/room_version_policy.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <variant>
#include <vector>

#include <sodium.h>

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

    class RuntimeSigningKeyStore final : public crypto::SigningKeyStore
    {
    public:
        RuntimeSigningKeyStore(std::string server_name, database::PersistentServerSigningKey key)
            : server_name_{std::move(server_name)}
            , key_{std::move(key)}
        {
        }

        [[nodiscard]] auto active_key_for_server(std::string_view server_name)
            -> crypto::SigningKeyLookupResult override
        {
            if (server_name != server_name_)
            {
                return {{}, "signing key not found"};
            }
            auto public_key = events::matrix_bytes_from_base64(key_.public_key);
            return {
                crypto::SigningKeyRecord{server_name_, key_.key_id, crypto::Ed25519PublicKey{std::move(public_key)},
                                         true},
                {}
            };
        }

    private:
        std::string server_name_{};
        database::PersistentServerSigningKey key_{};
    };

    class RuntimeEd25519Provider final : public crypto::Ed25519Provider
    {
    public:
        explicit RuntimeEd25519Provider(std::array<unsigned char, crypto_sign_SECRETKEYBYTES> secret_key)
            : secret_key_{std::move(secret_key)}
        {
        }

        [[nodiscard]] auto sign(crypto::Ed25519SecretKeyHandle const& /*key*/, std::string_view message)
            -> crypto::SignatureResult override
        {
            auto signature = std::string(crypto_sign_BYTES, '\0');
            if (crypto_sign_detached(reinterpret_cast<unsigned char*>(signature.data()), nullptr,
                                     reinterpret_cast<unsigned char const*>(message.data()), message.size(),
                                     secret_key_.data()) != 0)
            {
                return {{}, "Ed25519 signing failed"};
            }
            return {crypto::Ed25519Signature{std::move(signature)}, {}};
        }

        [[nodiscard]] auto verify(crypto::Ed25519PublicKey const& public_key, std::string_view message,
                                  crypto::Ed25519Signature const& signature) -> crypto::VerificationResult override
        {
            if (!crypto::ed25519_public_key_shape_is_valid(public_key) ||
                !crypto::ed25519_signature_shape_is_valid(signature))
            {
                return {false, "invalid Ed25519 material"};
            }
            auto const ok =
                crypto_sign_verify_detached(reinterpret_cast<unsigned char const*>(signature.bytes.data()),
                                            reinterpret_cast<unsigned char const*>(message.data()), message.size(),
                                            reinterpret_cast<unsigned char const*>(public_key.bytes.data())) == 0;
            return {ok, ok ? std::string{} : std::string{"signature verification failed"}};
        }

    private:
        std::array<unsigned char, crypto_sign_SECRETKEYBYTES> secret_key_{};
    };

    [[nodiscard]] auto starts_with(std::string_view value, std::string_view prefix) noexcept -> bool
    {
        return value.size() >= prefix.size() && value.substr(0U, prefix.size()) == prefix;
    }

    [[nodiscard]] auto object_member(canonicaljson::Object const& object, std::string_view key) noexcept
        -> canonicaljson::Value const*
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

    [[nodiscard]] auto string_member(canonicaljson::Object const& object, std::string_view key) noexcept
        -> std::string const*
    {
        auto const* value = object_member(object, key);
        return value == nullptr ? nullptr : std::get_if<std::string>(&value->storage());
    }

    [[nodiscard]] auto content_membership(canonicaljson::Object const& event) noexcept -> std::string const*
    {
        auto const* content_value = object_member(event, "content");
        auto const* content =
            content_value == nullptr ? nullptr : std::get_if<canonicaljson::Object>(&content_value->storage());
        return content == nullptr ? nullptr : string_member(*content, "membership");
    }

    [[nodiscard]] auto server_name_from_user_id(std::string_view user_id) -> std::string_view
    {
        auto const colon = user_id.rfind(':');
        return colon == std::string_view::npos ? std::string_view{} : user_id.substr(colon + 1U);
    }

    [[nodiscard]] auto local_user_exists(LocalDatabase const& database, std::string_view user_id) noexcept -> bool
    {
        return std::ranges::any_of(database.users, [&](LocalUser const& user) {
            return user.user_id == user_id;
        });
    }

    // Returns the room_version string from the room's m.room.create state event,
    // falling back to "10" for rooms that pre-date version tracking.
    [[nodiscard]] auto room_version_from_store(database::PersistentStore const& store, std::string_view room_id)
        -> std::string
    {
        for (auto const& state : store.state)
        {
            if (state.room_id != room_id || state.event_type != "m.room.create" || !state.state_key.empty())
            {
                continue;
            }
            for (auto const& evt : store.events)
            {
                if (evt.event_id != state.event_id)
                {
                    continue;
                }
                auto const parsed = canonicaljson::parse_lossless(evt.json);
                auto const* obj = std::get_if<canonicaljson::Object>(&parsed.value.storage());
                if (obj == nullptr)
                {
                    break;
                }
                auto const* content = object_member(*obj, "content");
                if (content == nullptr)
                {
                    break;
                }
                auto const* content_obj = std::get_if<canonicaljson::Object>(&content->storage());
                if (content_obj == nullptr)
                {
                    break;
                }
                auto const* rv = string_member(*content_obj, "room_version");
                if (rv != nullptr && !rv->empty())
                {
                    return *rv;
                }
                break;
            }
            break;
        }
        return "10"; // Oldest advertised version; safe fallback for legacy rooms.
    }

    [[nodiscard]] auto upsert_membership(database::PersistentStore& store, std::string_view room_id,
                                         std::string_view user_id, std::string_view membership,
                                         std::uint64_t stream_ordering) -> bool
    {
        auto const result = database::store_membership(
            store, {std::string{room_id}, std::string{user_id}, std::string{membership}, stream_ordering});
        if (result == database::MembershipStoreResult::stored)
        {
            return true;
        }
        if (result == database::MembershipStoreResult::already_exists)
        {
            return database::update_membership(store, room_id, user_id, membership);
        }
        return false;
    } // end emit_state

    [[nodiscard]] auto membership_for_endpoint(federation::FederationEndpoint endpoint) -> std::string_view
    {
        switch (endpoint)
        {
        case federation::FederationEndpoint::send_join:
            return "join";
        case federation::FederationEndpoint::send_leave:
            return "leave";
        case federation::FederationEndpoint::send_knock:
            return "knock";
        default:
            return {};
        }
    }

    [[nodiscard]] auto sign_invite_event(HomeserverRuntime& runtime, canonicaljson::Value const& event_value,
                                         std::string_view room_version) -> std::optional<std::string>
    {
        auto key = ensure_runtime_server_signing_key(runtime);
        if (!key.has_value() || runtime.database.signing_secret_key.size() != crypto_sign_SECRETKEYBYTES)
        {
            return std::nullopt;
        }
        auto secret_key = std::array<unsigned char, crypto_sign_SECRETKEYBYTES>{};
        std::copy(runtime.database.signing_secret_key.begin(), runtime.database.signing_secret_key.end(),
                  secret_key.begin());
        auto const* policy = rooms::find_room_version_policy(room_version.empty() ? "12" : room_version);
        if (policy == nullptr)
        {
            return std::nullopt;
        }
        auto key_store = RuntimeSigningKeyStore{runtime.config.server().server_name, *key};
        auto provider = RuntimeEd25519Provider{std::move(secret_key)};
        auto signed_event = events::sign_event_for_server(event_value, *policy, key_store, provider,
                                                          runtime.config.server().server_name);
        return signed_event.error.empty() ? std::optional<std::string>{std::move(signed_event.event_json)}
                                          : std::nullopt;
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

    // Tiny, allocation-light query string parser used by the audit-filter
    // handler. Splits on '&', then on '=' once per segment. Empty keys
    // are dropped, empty values are kept. The returned views are
    // substrings of the input — the caller must own the input buffer
    // for the lifetime of the views.
    [[nodiscard]] auto parse_audit_query_string(std::string_view query)
        -> std::vector<std::pair<std::string_view, std::string_view>>
    {
        auto out = std::vector<std::pair<std::string_view, std::string_view>>{};
        auto remaining = query;
        while (!remaining.empty())
        {
            auto const amp = remaining.find('&');
            auto const segment = remaining.substr(0U, amp);
            if (!segment.empty())
            {
                auto const eq = segment.find('=');
                if (eq == std::string_view::npos)
                {
                    out.emplace_back(segment, std::string_view{});
                }
                else
                {
                    out.emplace_back(segment.substr(0U, eq), segment.substr(eq + 1U));
                }
            }
            if (amp == std::string_view::npos)
            {
                break;
            }
            remaining = remaining.substr(amp + 1U);
        }
        return out;
    }

    [[nodiscard]] auto object_member_as_object(canonicaljson::Object const& object, std::string_view key)
        -> canonicaljson::Object const*
    {
        auto const* value = object_member(object, key);
        return value == nullptr ? nullptr : std::get_if<canonicaljson::Object>(&value->storage());
    }

    [[nodiscard]] auto object_member_as_string(canonicaljson::Object const& object, std::string_view key)
        -> std::string const*
    {
        auto const* value = object_member(object, key);
        return value == nullptr ? nullptr : std::get_if<std::string>(&value->storage());
    }

    auto enqueue_direct_to_device_messages(HomeserverRuntime& runtime, std::string_view content_json) -> void
    {
        auto const parsed = canonicaljson::parse_lossless(std::string{content_json});
        if (parsed.error != canonicaljson::ParseError::none)
        {
            return;
        }
        auto const* root = std::get_if<canonicaljson::Object>(&parsed.value.storage());
        if (root == nullptr)
        {
            return;
        }
        auto const* sender = object_member_as_string(*root, "sender");
        auto const* message_type = object_member_as_string(*root, "type");
        auto const* messages = object_member_as_object(*root, "messages");
        if (sender == nullptr || message_type == nullptr || messages == nullptr)
        {
            return;
        }

        for (auto const& user_entry : *messages)
        {
            auto const* device_map = std::get_if<canonicaljson::Object>(&user_entry.value->storage());
            if (device_map == nullptr)
            {
                continue;
            }
            for (auto const& device_entry : *device_map)
            {
                if (device_entry.value == nullptr)
                {
                    continue;
                }
                auto const serialized = canonicaljson::serialize_canonical(*device_entry.value);
                if (serialized.error != canonicaljson::CanonicalJsonError::none)
                {
                    continue;
                }
                auto message = database::PersistentToDeviceMessage{};
                message.sender_user_id = *sender;
                message.target_user_id = user_entry.key;
                message.target_device_id = device_entry.key;
                message.message_type = *message_type;
                message.content_json = serialized.output;
                std::ignore =
                    database::enqueue_to_device_message(runtime.database.persistent_store, std::move(message));
            }
        }
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

        runtime.federation.pdu_sink =
            [rt](federation::InboundPduEnvelope const& envelope) -> federation::PduIngestionResult {
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
                rt->sync_notifier->publish(rt->database.next_stream_ordering - 1U,
                                           rt->database.persistent_store.next_sync_stream_id);
            }
            return {federation::PduIngestionStatus::accepted, {}};
        };

        runtime.federation.edu_sink =
            [rt](federation::InboundEduEnvelope const& envelope) -> federation::EduDispositionResult {
            switch (envelope.type)
            {
            case federation::EduType::typing: {
                // content: {room_id, user_id, typing}
                auto const& content = envelope.content_json;
                auto const room_id_pos = content.find("\"room_id\"");
                auto const user_id_pos = content.find("\"user_id\"");
                if (room_id_pos == std::string::npos || user_id_pos == std::string::npos)
                {
                    return {federation::EduDispositionStatus::rejected_invalid, "missing room_id or user_id"};
                }
                auto typing = content.find("\"typing\":true") != std::string::npos;
                auto room_id = std::string{};
                auto user_id = std::string{};
                // Extract quoted value after "room_id"
                auto const room_val_start = content.find('"', content.find(':', room_id_pos));
                if (room_val_start != std::string::npos)
                {
                    auto const room_val_end = content.find('"', room_val_start + 1U);
                    if (room_val_end != std::string::npos)
                    {
                        room_id = content.substr(room_val_start + 1U, room_val_end - room_val_start - 1U);
                    }
                }
                auto const user_val_start = content.find('"', content.find(':', user_id_pos));
                if (user_val_start != std::string::npos)
                {
                    auto const user_val_end = content.find('"', user_val_start + 1U);
                    if (user_val_end != std::string::npos)
                    {
                        user_id = content.substr(user_val_start + 1U, user_val_end - user_val_start - 1U);
                    }
                }
                if (room_id.empty() || user_id.empty())
                {
                    return {federation::EduDispositionStatus::rejected_invalid, "empty room_id or user_id"};
                }
                auto existing = std::ranges::find_if(rt->typing_users, [&](auto const& t) {
                    return t.room_id == room_id && t.user_id == user_id;
                });
                if (typing)
                {
                    rt->database.persistent_store.next_sync_stream_id += 1U;
                    auto const stream_id = rt->database.persistent_store.next_sync_stream_id;
                    if (existing != rt->typing_users.end())
                    {
                        existing->typing = true;
                        existing->stream_id = stream_id;
                    }
                    else
                    {
                        rt->typing_users.push_back({room_id, user_id, true, stream_id});
                    }
                }
                else
                {
                    rt->database.persistent_store.next_sync_stream_id += 1U;
                    if (existing != rt->typing_users.end())
                    {
                        rt->typing_users.erase(existing);
                    }
                }
                if (rt->sync_notifier != nullptr)
                {
                    rt->sync_notifier->publish(rt->database.next_stream_ordering - 1U,
                                               rt->database.persistent_store.next_sync_stream_id);
                }
                return {federation::EduDispositionStatus::accepted, {}};
            }
            case federation::EduType::receipt: {
                // content: { <room_id>: { "m.read": { <user_id>: { ts } } } }
                auto const& content = envelope.content_json;
                auto const m_read_pos = content.find("\"m.read\"");
                if (m_read_pos == std::string::npos)
                {
                    return {federation::EduDispositionStatus::accepted, {}};
                }
                // Find the room_id key (first quoted string before m.read)
                auto const obj_start = content.find('{');
                if (obj_start == std::string::npos)
                {
                    return {federation::EduDispositionStatus::accepted, {}};
                }
                auto room_id_start = content.find('"', obj_start);
                if (room_id_start == std::string::npos || room_id_start >= m_read_pos)
                {
                    return {federation::EduDispositionStatus::accepted, {}};
                }
                auto room_id_end = content.find('"', room_id_start + 1U);
                if (room_id_end == std::string::npos)
                {
                    return {federation::EduDispositionStatus::accepted, {}};
                }
                auto room_id = content.substr(room_id_start + 1U, room_id_end - room_id_start - 1U);
                // Find user_id after "m.read": {
                auto const user_obj_start = content.find('{', m_read_pos);
                if (user_obj_start == std::string::npos)
                {
                    return {federation::EduDispositionStatus::accepted, {}};
                }
                auto user_id_start = content.find('"', user_obj_start);
                if (user_id_start == std::string::npos)
                {
                    return {federation::EduDispositionStatus::accepted, {}};
                }
                auto user_id_end = content.find('"', user_id_start + 1U);
                if (user_id_end == std::string::npos)
                {
                    return {federation::EduDispositionStatus::accepted, {}};
                }
                auto user_id = content.substr(user_id_start + 1U, user_id_end - user_id_start - 1U);
                // Find event_id inside the user's object
                auto const event_key_pos = content.find("\"event_id\"", user_id_end);
                std::string event_id;
                if (event_key_pos != std::string::npos)
                {
                    auto event_val_start = content.find('"', content.find(':', event_key_pos));
                    if (event_val_start != std::string::npos)
                    {
                        auto event_val_end = content.find('"', event_val_start + 1U);
                        if (event_val_end != std::string::npos)
                        {
                            event_id = content.substr(event_val_start + 1U, event_val_end - event_val_start - 1U);
                        }
                    }
                }
                // Find ts
                auto const ts_key_pos = content.find("\"ts\"", user_id_end);
                auto ts = std::uint64_t{0U};
                if (ts_key_pos != std::string::npos)
                {
                    auto const ts_val_start = content.find_first_of("0123456789", ts_key_pos);
                    if (ts_val_start != std::string::npos)
                    {
                        ts = std::strtoull(content.data() + ts_val_start, nullptr, 10U);
                    }
                }
                auto existing = std::ranges::find_if(rt->receipts, [&](auto const& r) {
                    return r.room_id == room_id && r.user_id == user_id;
                });
                rt->database.persistent_store.next_sync_stream_id += 1U;
                auto const stream_id = rt->database.persistent_store.next_sync_stream_id;
                if (existing != rt->receipts.end())
                {
                    existing->event_id = event_id;
                    existing->ts = ts;
                    existing->stream_id = stream_id;
                }
                else
                {
                    rt->receipts.push_back(
                        {std::string{room_id}, "m.read", std::string{user_id}, event_id, ts, stream_id});
                }
                if (rt->sync_notifier != nullptr)
                {
                    rt->sync_notifier->publish(rt->database.next_stream_ordering - 1U,
                                               rt->database.persistent_store.next_sync_stream_id);
                }
                return {federation::EduDispositionStatus::accepted, {}};
            }
            case federation::EduType::presence: {
                // content: { push: [ { user_id, presence } ] }
                auto const& content = envelope.content_json;
                auto const push_pos = content.find("\"push\"");
                if (push_pos == std::string::npos)
                {
                    return {federation::EduDispositionStatus::accepted, {}};
                }
                // Parse each presence entry in the push array
                auto const arr_start = content.find('[', push_pos);
                if (arr_start == std::string::npos)
                {
                    return {federation::EduDispositionStatus::accepted, {}};
                }
                auto pos = arr_start + 1U;
                while (pos < content.size())
                {
                    auto const obj_pos = content.find('{', pos);
                    if (obj_pos == std::string::npos)
                    {
                        break;
                    }
                    auto const obj_end = content.find('}', obj_pos);
                    if (obj_end == std::string::npos)
                    {
                        break;
                    }
                    auto const obj = content.substr(obj_pos, obj_end - obj_pos + 1U);
                    auto user_id = std::string{};
                    auto presence = std::string{"offline"};
                    auto uid_pos = obj.find("\"user_id\"");
                    if (uid_pos != std::string::npos)
                    {
                        auto uid_val_start = obj.find('"', obj.find(':', uid_pos));
                        if (uid_val_start != std::string::npos)
                        {
                            auto uid_val_end = obj.find('"', uid_val_start + 1U);
                            if (uid_val_end != std::string::npos)
                            {
                                user_id = obj.substr(uid_val_start + 1U, uid_val_end - uid_val_start - 1U);
                            }
                        }
                    }
                    auto pres_pos = obj.find("\"presence\"");
                    if (pres_pos != std::string::npos)
                    {
                        auto pres_val_start = obj.find('"', obj.find(':', pres_pos));
                        if (pres_val_start != std::string::npos)
                        {
                            auto pres_val_end = obj.find('"', pres_val_start + 1U);
                            if (pres_val_end != std::string::npos)
                            {
                                presence = obj.substr(pres_val_start + 1U, pres_val_end - pres_val_start - 1U);
                            }
                        }
                    }
                    if (!user_id.empty())
                    {
                        auto state = database::PersistentPresence{};
                        state.user_id = user_id;
                        state.presence = presence;
                        std::ignore = database::upsert_presence(rt->database.persistent_store, std::move(state));
                    }
                    pos = obj_end + 1U;
                }
                if (rt->sync_notifier != nullptr)
                {
                    rt->sync_notifier->publish(rt->database.next_stream_ordering - 1U,
                                               rt->database.persistent_store.next_sync_stream_id);
                }
                return {federation::EduDispositionStatus::accepted, {}};
            }
            case federation::EduType::direct_to_device: {
                enqueue_direct_to_device_messages(*rt, envelope.content_json);
                if (rt->sync_notifier != nullptr)
                {
                    rt->sync_notifier->publish(rt->database.next_stream_ordering - 1U,
                                               rt->database.persistent_store.next_sync_stream_id);
                }
                return {federation::EduDispositionStatus::accepted, {}};
            }
            case federation::EduType::device_list_update: {
                // content: { user_id, device_id?, stream_id? }
                auto const& content = envelope.content_json;
                auto user_id = std::string{};
                auto uid_pos = content.find("\"user_id\"");
                if (uid_pos != std::string::npos)
                {
                    auto val_start = content.find('"', content.find(':', uid_pos));
                    if (val_start != std::string::npos)
                    {
                        auto val_end = content.find('"', val_start + 1U);
                        if (val_end != std::string::npos)
                        {
                            user_id = content.substr(val_start + 1U, val_end - val_start - 1U);
                        }
                    }
                }
                if (!user_id.empty())
                {
                    // Record for all local users who may need to re-fetch keys
                    for (auto const& user : rt->database.persistent_store.users)
                    {
                        auto change = database::PersistentDeviceListChange{};
                        change.observer_user_id = user.user_id;
                        change.subject_user_id = user_id;
                        change.change_type = "changed";
                        std::ignore =
                            database::record_device_list_change(rt->database.persistent_store, std::move(change));
                    }
                }
                if (rt->sync_notifier != nullptr)
                {
                    rt->sync_notifier->publish(rt->database.next_stream_ordering - 1U,
                                               rt->database.persistent_store.next_sync_stream_id);
                }
                return {federation::EduDispositionStatus::accepted, {}};
            }
            default:
                return {federation::EduDispositionStatus::dropped_unknown_type, "unhandled EDU type"};
            }
        };

        runtime.federation.state_conflict_resolver =
            [rt](federation::PduStateConflictContext const& context) -> federation::PduIngestionResult {
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

        runtime.federation.membership_template_provider = [rt](federation::FederationEndpoint endpoint,
                                                               std::string_view room_id, std::string_view user_id,
                                                               std::vector<std::string> const& supported_versions)
            -> std::optional<federation::MembershipEventTemplate> {
            auto const& store = rt->database.persistent_store;
            auto const room_it = std::ranges::find_if(store.rooms, [&room_id](database::PersistentRoom const& r) {
                return r.room_id == room_id;
            });
            if (room_it == store.rooms.end())
            {
                return std::nullopt;
            }
            auto const room_version = room_version_from_store(store, room_id);

            // If the joining server advertised which versions it supports, verify
            // the room's actual version is among them. Fall back to lower versions
            // only if the remote explicitly supports them; we never downgrade a room.
            if (!supported_versions.empty() &&
                std::ranges::find(supported_versions, room_version) == supported_versions.end())
            {
                // Signal M_INCOMPATIBLE_ROOM_VERSION so the remote can inform its user.
                auto err = canonicaljson::Object{};
                err.push_back(canonicaljson::make_member(
                    "errcode", canonicaljson::Value{std::string{"M_INCOMPATIBLE_ROOM_VERSION"}}));
                err.push_back(canonicaljson::make_member(
                    "error", canonicaljson::Value{std::string{
                                 "Your homeserver does not support the features required to join this room"}}));
                err.push_back(canonicaljson::make_member("room_version", canonicaljson::Value{room_version}));
                auto tmpl = federation::MembershipEventTemplate{};
                tmpl.room_version = room_version;
                tmpl.reason = canonicaljson::serialize_canonical(canonicaljson::Value{std::move(err)}).output;
                return tmpl;
            }

            auto tmpl = federation::MembershipEventTemplate{};
            tmpl.room_id = std::string{room_id};
            tmpl.user_id = std::string{user_id};
            tmpl.room_version = room_version;
            tmpl.origin = rt->config.server().server_name;
            tmpl.origin_server_ts = static_cast<std::int64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                                                  std::chrono::system_clock::now().time_since_epoch())
                                                                  .count());
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
            // Populate auth_events: m.room.join_rules, m.room.power_levels, and
            // the joining user's current membership (e.g. their invite event).
            // For room versions < 12, m.room.create is also included per spec.
            // In room version 12 (MSC4291 / create_event_is_room_id) the create
            // event is the room ID itself and MUST NOT appear in any event's
            // auth_events — Synapse asserts this and crashes with 500 if it does.
            auto const* version_policy = rooms::find_room_version_policy(room_version);
            auto const include_create_in_auth = version_policy == nullptr || !version_policy->create_event_is_room_id;
            for (auto const& s : store.state)
            {
                if (s.room_id != room_id || s.event_id.empty())
                {
                    continue;
                }
                if ((include_create_in_auth && s.event_type == "m.room.create") ||
                    s.event_type == "m.room.join_rules" || s.event_type == "m.room.power_levels" ||
                    (s.event_type == "m.room.member" && s.state_key == user_id))
                {
                    tmpl.auth_events.push_back(s.event_id);
                }
            }
            // Compute the forward extremities: events not referenced as
            // prev_events by any other event in this room. These are the only
            // valid prev_events for a new join template; sending all room events
            // inflates the state snapshot and breaks state resolution at the
            // joining server.
            auto referenced = std::unordered_set<std::string>{};
            for (auto const& evt : store.events)
            {
                if (evt.room_id == room_id)
                {
                    for (auto const& prev_id : evt.prev_event_ids)
                    {
                        referenced.insert(prev_id);
                    }
                }
            }
            auto max_depth = std::int64_t{0};
            for (auto const& evt : store.events)
            {
                if (evt.room_id == room_id && !evt.event_id.empty() &&
                    referenced.find(evt.event_id) == referenced.end())
                {
                    tmpl.prev_events.push_back(evt.event_id);
                    if (static_cast<std::int64_t>(evt.depth) > max_depth)
                    {
                        max_depth = static_cast<std::int64_t>(evt.depth);
                    }
                }
            }
            tmpl.depth = max_depth + 1;
            auto content_obj = canonicaljson::Object{};
            content_obj.push_back(
                canonicaljson::make_member("membership", canonicaljson::Value{std::string{tmpl.membership}}));
            auto const serialized = canonicaljson::serialize_canonical(canonicaljson::Value{std::move(content_obj)});
            tmpl.content_json = serialized.output;
            return tmpl;
        };

        runtime.federation.membership_acceptor =
            [rt](federation::FederationEndpoint endpoint, std::string_view room_id,
                 [[maybe_unused]] std::string_view event_id,
                 federation::InboundPduEnvelope const& envelope) -> federation::MembershipAcceptResult {
            auto& store = rt->database.persistent_store;
            auto const room_it = std::ranges::find_if(store.rooms, [&room_id](database::PersistentRoom const& r) {
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
            event.stream_ordering = rt->database.next_stream_ordering++;
            event.auth_event_ids = envelope.auth_event_ids;
            auto const event_stream_ordering = event.stream_ordering;
            auto state = std::optional<database::PersistentStateEvent>{};
            if (envelope.state_key.has_value())
            {
                // Use envelope.event_id (the computed reference hash) rather
                // than the URL path event_id parameter. Both should be equal for
                // conformant peers, but deriving state from the envelope keeps
                // the stored state consistent with the stored event.
                state = database::PersistentStateEvent{envelope.room_id, envelope.event_type, *envelope.state_key,
                                                       envelope.event_id};
            }
            // Snapshot pre-join state IDs before persistence. The Matrix spec
            // requires the send_join response state to reflect the room *prior
            // to* the new join event. After store_event_with_state the store
            // already contains the join, so we must capture the snapshot first.
            auto pre_join_state_ids = std::vector<std::string>{};
            if (endpoint == federation::FederationEndpoint::send_join)
            {
                for (auto const& s : store.state)
                {
                    if (s.room_id == room_id && !s.event_id.empty())
                    {
                        pre_join_state_ids.push_back(s.event_id);
                    }
                }
            }
            if (!database::store_event_with_state(store, std::move(event), state))
            {
                return {false, 500U, "event persistence failed", {}, {}};
            }
            auto membership_changed = false;
            if (envelope.event_type == "m.room.member" && envelope.state_key.has_value())
            {
                auto const membership = membership_for_endpoint(endpoint);
                if (!membership.empty())
                {
                    if (!upsert_membership(store, room_id, *envelope.state_key, membership, event_stream_ordering))
                    {
                        return {false, 500U, "membership persistence failed", {}, {}};
                    }
                    if ((membership == "join" || membership == "leave" || membership == "ban") &&
                        !database::delete_invite(store, room_id, *envelope.state_key))
                    {
                        return {false, 500U, "invite metadata cleanup failed", {}, {}};
                    }
                    apply_runtime_membership(rt->database, room_id, *envelope.state_key, membership);
                    membership_changed = true;
                }
            }
            if (membership_changed)
            {
                rt->database.persistent_store.next_sync_stream_id += 1U;
            }
            if (rt->sync_notifier != nullptr)
            {
                rt->sync_notifier->publish(rt->database.next_stream_ordering - 1U,
                                           rt->database.persistent_store.next_sync_stream_id);
            }
            auto auth_chain = std::vector<std::string>{};
            auto state_events = std::vector<std::string>{};
            if (endpoint == federation::FederationEndpoint::send_join)
            {
                // Build auth_chain by walking auth_events from PRE-JOIN state.
                // Per Matrix spec §11.5.1 the state in the response must be the
                // room state prior to the join event. We captured pre_join_state_ids
                // before persisting, so the join event itself is never seeded here,
                // preventing the circular auth_events reference Synapse warns about.
                // All auth_chain events must be state events (have state_key);
                // including non-state events crashes Synapse.
                auto visited = std::unordered_set<std::string>{};
                auto queue = std::vector<std::string>{};
                for (auto const& eid : pre_join_state_ids)
                {
                    if (visited.insert(eid).second)
                    {
                        queue.push_back(eid);
                    }
                }
                // Build a lookup from event_id to PersistentEvent for this room
                auto event_by_id = std::unordered_map<std::string, std::size_t>{};
                for (std::size_t i = 0U; i < store.events.size(); ++i)
                {
                    if (store.events[i].room_id == room_id && !store.events[i].event_id.empty())
                    {
                        event_by_id[store.events[i].event_id] = i;
                    }
                }
                // BFS: follow auth_event_ids from each discovered event
                auto cursor = std::size_t{0U};
                while (cursor < queue.size())
                {
                    auto const& eid = queue[cursor];
                    ++cursor;
                    auto const it = event_by_id.find(eid);
                    if (it == event_by_id.end())
                    {
                        continue;
                    }
                    for (auto const& auth_id : store.events[it->second].auth_event_ids)
                    {
                        if (!auth_id.empty() && visited.insert(auth_id).second)
                        {
                            queue.push_back(auth_id);
                        }
                    }
                }
                // Collect JSON for every event in the auth chain
                for (auto const& eid : queue)
                {
                    auto const it = event_by_id.find(eid);
                    if (it != event_by_id.end() && !store.events[it->second].json.empty())
                    {
                        auth_chain.push_back(store.events[it->second].json);
                    }
                }
                // State events: pre-join snapshot, resolved via the same
                // event_by_id map built above.
                for (auto const& eid : pre_join_state_ids)
                {
                    auto const it = event_by_id.find(eid);
                    if (it != event_by_id.end() && !store.events[it->second].json.empty())
                    {
                        state_events.push_back(store.events[it->second].json);
                    }
                }
            }
            // Pass the raw PDU JSON so the federation layer can echo it back
            // in the send_join v2 "event" field as required by the spec.
            return {true,
                    200U,
                    {},
                    std::move(auth_chain),
                    std::move(state_events),
                    room_version_from_store(store, room_id),
                    std::string{envelope.json}};
        };

        runtime.federation.invite_handler =
            [rt](federation::InviteRequest const& invite) -> federation::InviteAcceptResult {
            auto const parsed = canonicaljson::parse_lossless(invite.invite_event_json);
            auto const* event = std::get_if<canonicaljson::Object>(&parsed.value.storage());
            if (parsed.error != canonicaljson::ParseError::none || event == nullptr)
            {
                return {false, 400U, "malformed invite event", {}};
            }
            auto const* target_user = string_member(*event, "state_key");
            auto const* sender = string_member(*event, "sender");
            auto const* event_room_id = string_member(*event, "room_id");
            auto const* event_type = string_member(*event, "type");
            auto const* membership = content_membership(*event);
            if (target_user == nullptr || target_user->empty() || sender == nullptr || sender->empty() ||
                event_room_id == nullptr || *event_room_id != invite.room_id || event_type == nullptr ||
                *event_type != "m.room.member" || membership == nullptr || *membership != "invite")
            {
                return {false, 400U, "invite event must be an m.room.member invite", {}};
            }
            if (server_name_from_user_id(*target_user) != rt->config.server().server_name ||
                !local_user_exists(rt->database, *target_user))
            {
                return {false, 404U, "invited local user not found", {}};
            }
            auto signed_event = sign_invite_event(*rt, parsed.value, invite.room_version);
            if (!signed_event.has_value())
            {
                return {false, 500U, "invite signing failed", {}};
            }
            // If the target user is already persistently "join" in this room, the
            // remote server's view of room state has diverged from ours. We sign the
            // invite event (to remain cooperative) but MUST NOT overwrite the local
            // "join" membership with "invite": doing so corrupts sync — the room
            // disappears from rooms.join and the user enters an infinite invite loop.
            {
                auto const& mems = rt->database.persistent_store.memberships;
                auto const it    = std::ranges::find_if(mems, [&](database::PersistentMembership const& m) {
                    return m.room_id == invite.room_id && m.user_id == *target_user &&
                           m.membership == "join";
                });
                if (it != mems.end())
                {
                    // User is already joined: return the signed event without altering state.
                    return {true, 200U, {}, std::move(*signed_event)};
                }
            }
            auto const stream_ordering = rt->database.next_stream_ordering++;
            if (!upsert_membership(rt->database.persistent_store, invite.room_id, *target_user, "invite",
                                   stream_ordering))
            {
                return {false, 500U, "invite membership persistence failed", {}};
            }
            if (!database::upsert_invite(rt->database.persistent_store,
                                         {invite.room_id, *target_user, *sender, invite.event_id, *signed_event,
                                          invite.invite_room_state_json, stream_ordering}))
            {
                return {false, 500U, "invite metadata persistence failed", {}};
            }
            // Store the invite event in the persistent event graph so it is
            // reachable during auth-chain BFS walks on subsequent send_join
            // calls for this user. Without this, make_join cannot include it
            // in auth_events and send_join cannot return it in the auth_chain.
            {
                auto invite_pdu = database::PersistentEvent{};
                invite_pdu.event_id = invite.event_id;
                invite_pdu.room_id = invite.room_id;
                invite_pdu.sender_user_id = *sender;
                invite_pdu.json = *signed_event;
                invite_pdu.stream_ordering = stream_ordering;
                auto invite_state = std::optional<database::PersistentStateEvent>{
                    database::PersistentStateEvent{invite.room_id, "m.room.member", *target_user, invite.event_id}
                };
                if (!database::store_event_with_state(rt->database.persistent_store, std::move(invite_pdu),
                                                      std::move(invite_state)))
                {
                    return {false, 500U, "invite event persistence failed", {}};
                }
            }
            rt->database.persistent_store.next_sync_stream_id += 1U;
            if (rt->sync_notifier != nullptr)
            {
                rt->sync_notifier->publish(rt->database.next_stream_ordering - 1U,
                                           rt->database.persistent_store.next_sync_stream_id);
            }
            return {true, 200U, {}, std::move(*signed_event)};
        };

        runtime.federation.backfill_provider =
            [rt](federation::BackfillRequest const& req) -> federation::BackfillResult {
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

        runtime.federation.profile_query_provider = [rt](std::string_view user_id) -> federation::FederationProfile {
            auto const profile = database::find_profile(rt->database.persistent_store, user_id);
            if (profile.has_value())
            {
                return {true, profile->displayname, profile->avatar_url};
            }
            auto const user_exists = std::ranges::any_of(rt->database.persistent_store.users,
                                                         [user_id](database::PersistentUser const& user) {
                                                             return user.user_id == user_id;
                                                         });
            return user_exists ? federation::FederationProfile{true, {}, {}} : federation::FederationProfile{};
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

        runtime.federation.missing_events_query_provider = [rt](std::string_view room_id,
                                                                std::string_view body) -> std::string {
            return federation::build_get_missing_events_response(rt->database.persistent_store, room_id, body);
        };

        // Resolve the room version from the stored m.room.create state event so
        // that authorize_federation_pdu uses the correct redaction rules when
        // verifying inbound PDU signatures.  Rooms created before v11 include
        // "origin" in the signing payload; using the wrong (later) version strips
        // it and produces a false signature failure for every inbound event.
        runtime.federation.room_version_resolver = [rt](std::string_view room_id) -> std::string {
            return room_version_from_store(rt->database.persistent_store, room_id);
        };

        if (outbound && discovery)
        {
            runtime.federation.remote_key_resolver = federation::make_persistent_remote_key_resolver(
                runtime.database.persistent_store, *outbound, *discovery, timeout, [] {
                    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                                          std::chrono::system_clock::now().time_since_epoch())
                                                          .count());
                });
            auto key = ensure_runtime_server_signing_key(runtime);
            if (!key.has_value() || runtime.database.signing_secret_key.size() != crypto_sign_SECRETKEYBYTES)
            {
                log_diagnostic("dispatch.start.rejected", {
                                                              {"reason", "server signing key unavailable", false}
                });
                return;
            }
            auto dispatch_config = federation::DispatchWorkerConfig{};
            dispatch_config.origin = runtime.config.server().server_name;
            dispatch_config.key_id = key->key_id;
            dispatch_config.secret_key =
                std::string{reinterpret_cast<char const*>(runtime.database.signing_secret_key.data()),
                            runtime.database.signing_secret_key.size()};
            auto* discovery_ptr = discovery;
            auto const discovery_timeout = timeout > 0U ? timeout : 30U;
            auto resolver = [discovery_ptr, discovery_timeout](
                                std::string_view server_name) -> std::optional<federation::ServerDiscoveryResult> {
                auto result = federation::discover_server(server_name, *discovery_ptr, discovery_timeout);
                if (!result.discovery_allowed)
                {
                    return std::nullopt;
                }
                return result;
            };
            auto clock = []() -> std::uint64_t {
                return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                                      std::chrono::system_clock::now().time_since_epoch())
                                                      .count());
            };
            auto sleep_fn = [](std::chrono::milliseconds ms) {
                std::this_thread::sleep_for(ms);
            };
            if (!runtime.dispatch_worker)
            {
                runtime.dispatch_worker = std::make_unique<federation::DispatchWorker>(
                    std::move(dispatch_config), *outbound, std::move(resolver), std::move(clock), std::move(sleep_fn),
                    &runtime.database.persistent_store);
                std::ignore = runtime.dispatch_worker->replay_pending();
                runtime.dispatch_worker->start();
            }
        }
    }

} // namespace

auto apply_runtime_membership(LocalDatabase& database, std::string_view room_id, std::string_view user_id,
                              std::string_view membership) -> void
{
    auto room = std::ranges::find_if(database.rooms, [&](LocalRoom const& current) {
        return current.room_id == room_id;
    });
    if (room == database.rooms.end())
    {
        return;
    }
    auto const member = std::ranges::find_if(room->members, [&](std::string const& member_id) {
        return member_id == user_id;
    });
    if (membership == "join" && member == room->members.end())
    {
        room->members.emplace_back(user_id);
    }
    else if ((membership == "leave" || membership == "ban") && member != room->members.end())
    {
        room->members.erase(member);
    }
}

auto wire_federation_callbacks(HomeserverRuntime& runtime) -> void
{
    wire_federation_callbacks_impl(runtime);
}

[[nodiscard]] auto handle_local_http_request(HomeserverRuntime& runtime, LocalHttpRequest const& request)
    -> LocalHttpResponse
{
    auto guard = std::unique_lock<std::recursive_mutex>{runtime.mutex};
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
    if (request.method == "GET" && starts_with(request.target, "/_merovingian/admin/audit"))
    {
        // Query string filter for the audit summary (0.5.0). The
        // endpoint accepts `?category=`, `?event_type=` to narrow
        // the result set. Malformed `category=` values return 400;
        // unknown `event_type=` values are treated as a no-match
        // filter and the response is empty (still 200).
        auto const target = std::string_view{request.target};
        auto const query_start = target.find('?');
        auto category_filter = std::optional<observability::AuditCategory>{};
        auto event_type_filter = std::optional<std::string_view>{};
        if (query_start != std::string_view::npos)
        {
            auto const query = target.substr(query_start + 1U);
            for (auto const& kv : parse_audit_query_string(query))
            {
                if (kv.first == "category")
                {
                    auto const parsed = observability::audit_category_from_name(kv.second);
                    if (!parsed.has_value())
                    {
                        return response(400U, std::string{"unknown audit category: "} + std::string{kv.second});
                    }
                    category_filter = *parsed;
                }
                else if (kv.first == "event_type")
                {
                    event_type_filter = kv.second;
                }
            }
        }
        return authenticated_admin_user(runtime, request.access_token).has_value()
                   ? response(200U, admin_audit_summary(runtime, category_filter, event_type_filter))
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
                               {"status", "502",                                                false},
                               {"reason", "malformed federation authorization",                 false}
            });
            // 502 rather than 401: Synapse propagates 401 from federation
            // responses to the client, triggering an automatic logout. Returning
            // 502 signals a server-side failure instead.
            return response(502U, "malformed federation authorization");
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
    auto constexpr thumbnail_prefix = std::string_view{"/_matrix/media/v3/thumbnail/"};
    if (request.method == "GET" && starts_with(request.target, thumbnail_prefix))
    {
        auto const parts = local_media_download_parts(path_suffix(request.target, thumbnail_prefix));
        if (!parts.has_value())
        {
            return response(404U, "route not found");
        }
        auto const result = download_local_media_thumbnail(runtime, (*parts)[0], (*parts)[1]);
        return response_from_media_operation(result);
    }
    auto constexpr v1_thumbnail_prefix = std::string_view{"/_matrix/client/v1/media/thumbnail/"};
    if (request.method == "GET" && starts_with(request.target, v1_thumbnail_prefix))
    {
        auto const parts = local_media_download_parts(path_suffix(request.target, v1_thumbnail_prefix));
        if (!parts.has_value())
        {
            return response(404U, "route not found");
        }
        auto const result = download_local_media_thumbnail(runtime, (*parts)[0], (*parts)[1]);
        return response_from_media_operation(result);
    }
    auto constexpr v1_download_prefix = std::string_view{"/_matrix/client/v1/media/download/"};
    if (request.method == "GET" && starts_with(request.target, v1_download_prefix))
    {
        auto const parts = local_media_download_parts(path_suffix(request.target, v1_download_prefix));
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
    auto suffix = std::string_view{request.target}.substr(rooms_prefix.size());
    // Split any query string off the path so the suffix routing below still matches;
    // the join handler reads via/server_name candidate servers from it.
    auto request_query = std::string_view{};
    if (auto const query_start = suffix.find('?'); query_start != std::string_view::npos)
    {
        request_query = suffix.substr(query_start + 1U);
        suffix = suffix.substr(0U, query_start);
    }
    auto constexpr join_suffix = std::string_view{"/join"};
    auto constexpr send_suffix = std::string_view{"/send"};
    auto constexpr state_suffix = std::string_view{"/state"};

    if (request.method == "POST" && suffix.size() > join_suffix.size() &&
        suffix.substr(suffix.size() - join_suffix.size()) == join_suffix)
    {
        auto const room_id = core::percent_decode_path_component(suffix.substr(0U, suffix.size() - join_suffix.size()));
        auto const via_servers = parse_join_via_servers(request_query);
        log_diagnostic("room.join.dispatch",
                       {
                           {"room_id",   room_id,                            false},
                           {"via_count", std::to_string(via_servers.size()), false}
        });
        guard.unlock();
        auto result = join_room(runtime, request.access_token, room_id, via_servers);
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
    auto guard = std::unique_lock<std::recursive_mutex>{runtime.mutex};
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
            // 502 rather than 401: Synapse propagates 401 from federation
            // responses to the client, triggering an automatic logout. Returning
            // 502 signals a server-side failure instead.
            return response(502U, "malformed federation authorization");
        }
        auto const federation_response =
            federation::handle_inbound_federation_request(runtime.federation, *signed_request_opt);
        return response(federation_response.status, federation_response.body);
    }
    return response(404U, "route not found");
}

} // namespace merovingian::homeserver
