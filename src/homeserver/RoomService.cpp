// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/RoomService.hpp"

#include "merovingian/appservice/MasqueradeToken.hpp"
#include "merovingian/auth/Identity.hpp"
#include "merovingian/canonicaljson/CanonicalJsonError.hpp"
#include "merovingian/canonicaljson/ObjectMember.hpp"
#include "merovingian/canonicaljson/ParseError.hpp"
#include "merovingian/canonicaljson/Parser.hpp"
#include "merovingian/canonicaljson/Serializer.hpp"
#include "merovingian/canonicaljson/Value.hpp"
#include "merovingian/core/BoundedParallel.hpp"
#include "merovingian/core/PortableSemaphore.hpp"
#include "merovingian/core/QueryParams.hpp"
#include "merovingian/core/SecretBuffer.hpp"
#include "merovingian/core/SemaphorePermit.hpp"
#include "merovingian/crypto/Ed25519.hpp"
#include "merovingian/crypto/Ed25519PublicKey.hpp"
#include "merovingian/crypto/Ed25519SecretKeyHandle.hpp"
#include "merovingian/crypto/Ed25519Signature.hpp"
#include "merovingian/crypto/MasterKey.hpp"
#include "merovingian/crypto/SecretBox.hpp"
#include "merovingian/crypto/SecretBoxCiphertext.hpp"
#include "merovingian/database/ExaminedRows.hpp"
#include "merovingian/database/MembershipProjection.hpp"
#include "merovingian/database/PersistentAccountData.hpp"
#include "merovingian/database/PersistentDeviceListChange.hpp"
#include "merovingian/database/PersistentInvite.hpp"
#include "merovingian/database/PersistentMembership.hpp"
#include "merovingian/database/PersistentNotification.hpp"
#include "merovingian/database/PersistentPresence.hpp"
#include "merovingian/database/PersistentProfile.hpp"
#include "merovingian/database/PersistentPusher.hpp"
#include "merovingian/database/PersistentRoom.hpp"
#include "merovingian/database/PersistentServerSigningKey.hpp"
#include "merovingian/database/PersistentStateEvent.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/database/PreparedStateUpdate.hpp"
#include "merovingian/database/RedactionView.hpp"
#include "merovingian/events/AuthEventMap.hpp"
#include "merovingian/events/Authorization.hpp"
#include "merovingian/events/Event.hpp"
#include "merovingian/events/EventId.hpp"
#include "merovingian/events/EventIdResult.hpp"
#include "merovingian/events/EventSignature.hpp"
#include "merovingian/events/EventSigner.hpp"
#include "merovingian/events/Limits.hpp"
#include "merovingian/events/Redaction.hpp"
#include "merovingian/events/SignedEventResult.hpp"
#include "merovingian/events/SigningKeyId.hpp"
#include "merovingian/events/UnsignedData.hpp"
#include "merovingian/federation/CachedServerDiscovery.hpp"
#include "merovingian/federation/DiscoveryCachePolicy.hpp"
#include "merovingian/federation/FederationKeyRecord.hpp"
#include "merovingian/federation/InboundIngestion.hpp"
#include "merovingian/federation/InboundRequest.hpp"
#include "merovingian/federation/InviteRoomState.hpp"
#include "merovingian/federation/OutboundCall.hpp"
#include "merovingian/federation/OutboundMembership.hpp"
#include "merovingian/federation/OutboundTransaction.hpp"
#include "merovingian/federation/OutboundTransactionSupport.hpp"
#include "merovingian/federation/RemoteKeyCache.hpp"
#include "merovingian/federation/ServerDiscovery.hpp"
#include "merovingian/federation/ThirdPartyBindNotification.hpp"
#include "merovingian/federation/ThirdPartyInvite.hpp"
#include "merovingian/federation/ThirdPartyInviteExchange.hpp"
#include "merovingian/federation/VerificationKeyResolution.hpp"
#include "merovingian/homeserver/ActiveServerSigningKeySecret.hpp"
#include "merovingian/homeserver/AppserviceDelivery.hpp"
#include "merovingian/homeserver/AppserviceEphemeral.hpp"
#include "merovingian/homeserver/AuthService.hpp"
#include "merovingian/homeserver/BoundedOutboundLimits.hpp"
#include "merovingian/homeserver/ClientOutboundProxy.hpp"
#include "merovingian/homeserver/CreateRoomOptions.hpp"
#include "merovingian/homeserver/EmailPush.hpp"
#include "merovingian/homeserver/EventBookkeeping.hpp"
#include "merovingian/homeserver/FederationProxy.hpp"
#include "merovingian/homeserver/FetchRelationsRequest.hpp"
#include "merovingian/homeserver/FetchThreadsRequest.hpp"
#include "merovingian/homeserver/HomeserverRuntime.hpp"
#include "merovingian/homeserver/InvitePermission.hpp"
#include "merovingian/homeserver/KeyServerCache.hpp"
#include "merovingian/homeserver/LocalDatabase.hpp"
#include "merovingian/homeserver/LocalHttpRouter.hpp"
#include "merovingian/homeserver/LocalRedactionCheck.hpp"
#include "merovingian/homeserver/LocalRoom.hpp"
#include "merovingian/homeserver/LocalServices.hpp"
#include "merovingian/homeserver/LocalUser.hpp"
#include "merovingian/homeserver/MakeJoinRaceState.hpp"
#include "merovingian/homeserver/NewEventBasis.hpp"
#include "merovingian/homeserver/OperationResult.hpp"
#include "merovingian/homeserver/OutboundCallResult.hpp"
#include "merovingian/homeserver/OutboundDeadline.hpp"
#include "merovingian/homeserver/PendingStreamOrdering.hpp"
#include "merovingian/homeserver/PersistOutcome.hpp"
#include "merovingian/homeserver/PresenceService.hpp"
#include "merovingian/homeserver/PushBadgeCount.hpp"
#include "merovingian/homeserver/PushRetry.hpp"
#include "merovingian/homeserver/PushRoomFacts.hpp"
#include "merovingian/homeserver/PushRuleUnreadClassifier.hpp"
#include "merovingian/homeserver/RedactionService.hpp"
#include "merovingian/homeserver/RemoteInviteResult.hpp"
#include "merovingian/homeserver/RequestLockScope.hpp"
#include "merovingian/homeserver/RestrictedJoin.hpp"
#include "merovingian/homeserver/RestrictedJoinVerdict.hpp"
#include "merovingian/homeserver/RoomPower.hpp"
#include "merovingian/homeserver/RuntimeLockRelease.hpp"
#include "merovingian/homeserver/RuntimeSigningKeyStore.hpp"
#include "merovingian/homeserver/SendJoinAnswerAuthorization.hpp"
#include "merovingian/homeserver/SendJoinStateIngestResult.hpp"
#include "merovingian/homeserver/StateBookkeeping.hpp"
#include "merovingian/homeserver/StateContentCheck.hpp"
#include "merovingian/homeserver/StateContentRefusal.hpp"
#include "merovingian/homeserver/StoredPushRules.hpp"
#include "merovingian/homeserver/StoredRoomVersion.hpp"
#include "merovingian/homeserver/ValidatedMakeJoinResponse.hpp"
#include "merovingian/homeserver/ValidatedMakeLeaveResponse.hpp"
#include "merovingian/http/OutboundClient.hpp"
#include "merovingian/http/OutboundResult.hpp"
#include "merovingian/http/RequestLimits.hpp"
#include "merovingian/identity/IdentityServerClient.hpp"
#include "merovingian/identity/StoreInvitePublicKey.hpp"
#include "merovingian/observability/AuditCategory.hpp"
#include "merovingian/observability/LogEventSeverity.hpp"
#include "merovingian/observability/SingleLog.hpp"
#include "merovingian/observability/StructuredLogField.hpp"
#include "merovingian/push/GatewayCircuitBreakerPolicy.hpp"
#include "merovingian/push/PushBatchAdmission.hpp"
#include "merovingian/push/PushEvaluationResult.hpp"
#include "merovingian/push/PushGatewayClient.hpp"
#include "merovingian/push/PushGatewayDevice.hpp"
#include "merovingian/push/PushGatewayNotification.hpp"
#include "merovingian/push/PushRules.hpp"
#include "merovingian/rooms/EncryptionPolicy.hpp"
#include "merovingian/rooms/EventIdFormat.hpp"
#include "merovingian/rooms/RedactionRules.hpp"
#include "merovingian/rooms/RoomCreationEncryptionRequest.hpp"
#include "merovingian/rooms/RoomEncryptionRequest.hpp"
#include "merovingian/rooms/RoomPreset.hpp"
#include "merovingian/rooms/RoomVersionPolicy.hpp"
#include "merovingian/sync/HistoryVisibility.hpp"
#include "merovingian/sync/RoomReadAccess.hpp"
#include "merovingian/sync/RoomReadKind.hpp"
#include "merovingian/sync/StreamToken.hpp"
#include "merovingian/trust_safety/IgnoreList.hpp"
#include "merovingian/trust_safety/PolicyEngine.hpp"
#include "merovingian/trust_safety/PolicySurface.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <charconv>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <exception>
#include <functional>
#include <future>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <ranges>
#include <set>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <variant>
#include <vector>

namespace merovingian::homeserver
{
namespace
{

    auto log_diagnostic(std::string_view event, std::vector<observability::StructuredLogField> fields,
                        observability::LogEventSeverity severity = observability::LogEventSeverity::debug) -> void
    {
        observability::log_diagnostic("rooms", event, fields, severity);
    }

} // namespace

auto notify_room_changed(HomeserverRuntime& runtime, std::string_view room_id) -> void
{
    if (runtime.federation_proxy)
    {
        runtime.federation_proxy->notify_room_changed(room_id);
    }
    if (runtime.test_room_changed_log != nullptr)
    {
        runtime.test_room_changed_log->emplace_back(room_id);
    }
}

namespace
{

    // Replace an existing object member with the same key, or append if absent.
    // Used when preparing remote membership templates: a resident server's
    // make_join / make_leave response may already contain a `hashes` field,
    // and appending a second one would produce duplicate_object_key during
    // canonical JSON serialization.
    auto replace_or_add_member(canonicaljson::Object& object, std::string key, canonicaljson::Value value) -> void
    {
        auto const it = std::ranges::find_if(object, [&](auto const& member) {
            return member.key == key;
        });
        if (it != object.end())
        {
            *it = canonicaljson::make_member(std::move(key), std::move(value));
        }
        else
        {
            object.push_back(canonicaljson::make_member(std::move(key), std::move(value)));
        }
    }

    [[nodiscard]] auto json_object_member(canonicaljson::Object const& object, std::string_view key) noexcept
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

    [[nodiscard]] auto json_string_member(canonicaljson::Object const& object, std::string_view key) noexcept
        -> std::string const*
    {
        auto const* value = json_object_member(object, key);
        if (value == nullptr)
        {
            return nullptr;
        }
        return std::get_if<std::string>(&value->storage());
    }

    [[nodiscard]] auto json_integer_member(canonicaljson::Object const& object, std::string_view key) noexcept
        -> std::int64_t const*
    {
        auto const* value = json_object_member(object, key);
        if (value == nullptr)
        {
            return nullptr;
        }
        return std::get_if<std::int64_t>(&value->storage());
    }

    [[nodiscard]] auto json_string_array(canonicaljson::Value const& value) -> std::vector<std::string>
    {
        auto out = std::vector<std::string>{};
        auto const* array = std::get_if<canonicaljson::Array>(&value.storage());
        if (array == nullptr)
        {
            return out;
        }
        for (auto const& entry : *array)
        {
            auto const* text = std::get_if<std::string>(&entry.storage());
            if (text != nullptr)
            {
                out.push_back(*text);
            }
        }
        return out;
    }

    struct ComposedEvent final
    {
        std::string event_id{};
        std::string json{};
        std::uint64_t depth{0U};
        std::uint64_t stream_ordering{0U};
        std::vector<std::string> prev_event_ids{};
        std::vector<std::string> auth_event_ids{};
        std::vector<events::EventSignature> signatures{};
        std::string event_type{};
        std::optional<std::string> state_key{};
        // ADR-0064 phase B1: the room version policy resolved while
        // composing this event, carried through to persist_composed_event
        // so it need not (and, for a room's own m.room.create event, cannot
        // yet — the store has no create row for this room while composing
        // it) re-derive it from store.state.
        std::string room_version{};
        // The prev_events chosen while composing, and the state before them,
        // resolved once (ADR-0225); persist_composed_event stores against it.
        NewEventBasis basis{};
    };

    // Queues a stored event for every appservice interested in it (R07, R01). The target of a
    // membership event is its state_key, which is how an appservice is told about an invite to one
    // of its virtual users who is not yet in the room. Every path that stores a client-visible event
    // calls this once the event is stored: send_event, each membership transition, the third-party
    // invite on join, the events createRoom makes, and federation PDUs.
    auto queue_event_for_appservices(HomeserverRuntime& runtime, LocalRoom const& room, ComposedEvent const& composed,
                                     std::string_view sender) -> void
    {
        auto const member_event_target = composed.event_type == "m.room.member" && composed.state_key.has_value()
                                             ? std::string_view{*composed.state_key}
                                             : std::string_view{};
        enqueue_appservice_delivery(runtime, room, composed.event_id, composed.stream_ordering, sender,
                                    member_event_target);
    }

    // Why compose_signed_event produced no event. too_large means the event would
    // break the spec's size limits (CSAZ-9) and is the client's to fix, so callers
    // answer 413 M_TOO_LARGE; rejected covers everything else (malformed input,
    // authorization, signing); invalid_state_key is refused with 400 before
    // composition can allocate any stream ordering or persistence state.
    enum class ComposeFailure : std::uint8_t
    {
        none,
        too_large,
        invalid_state_key,
        rejected,
    };

    struct ComposeResult final
    {
        std::optional<ComposedEvent> event{};
        ComposeFailure failure{ComposeFailure::none};
    };

    // `origin_server_ts`, when given, is stamped on the event instead of the
    // event clock's reading (create_room uses it to keep v12 room IDs unique).
    [[nodiscard]] auto compose_signed_event(HomeserverRuntime& runtime, std::string_view room_id,
                                            std::string_view sender, std::string_view client_event_json,
                                            std::optional<std::int64_t> origin_server_ts = std::nullopt)
        -> ComposeResult;

    // The origin_server_ts this server stamps on an event it composes: the
    // system clock, or the frozen test clock when a test has set one.
    [[nodiscard]] auto event_clock_now_ms(HomeserverRuntime const& runtime) -> std::int64_t
    {
        if (runtime.test_frozen_event_clock_ms.has_value())
        {
            return *runtime.test_frozen_event_clock_ms;
        }
        return static_cast<std::int64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
                .count());
    }

    // Spec v1.19 "Size limits": the refusal (413, the owner's reading: the spec names no
    // status) for an event over 65536 bytes, or
    // whose type or state_key is over 255 bytes.
    [[nodiscard]] auto event_too_large_result() -> OperationResult
    {
        auto result = make_operation_result(false, {}, "event exceeds the Matrix event size limits", 413U);
        result.errcode = "M_TOO_LARGE";
        return result;
    }
    // SS7: 403 M_INVITE_BLOCKED, for an invite to a local user whose m.invite_permission_config blocks invites.
    [[nodiscard]] auto invite_blocked_result() -> OperationResult
    {
        auto result = make_operation_result(false, {}, "the invited user is not accepting invites", 403U);
        result.errcode = std::string{invite_blocked_errcode};
        return result;
    }
    // 400 with the refusal's errcode (F-19).
    [[nodiscard]] auto state_content_refusal_result(StateContentRefusal const& refusal) -> OperationResult
    {
        auto result = make_operation_result(false, {}, refusal.message, 400U);
        result.errcode = std::string{refusal.errcode};
        return result;
    }

    [[nodiscard]] auto invalid_state_key_result() -> OperationResult
    {
        auto result = make_operation_result(false, {}, "state_key must not contain NUL", 400U);
        result.errcode = "M_INVALID_PARAM";
        return result;
    }

    // Defence in depth for ban, kick and unban: the route refuses a missing or malformed `user_id`, but a
    // caller of the service must not be able to compose an m.room.member with an empty or invalid state_key.
    [[nodiscard]] auto refuse_invalid_membership_target(std::string_view target_user_id)
        -> std::optional<OperationResult>
    {
        // F-21: a target may be on another server; the strict rule for new local accounts does not apply.
        if (auth::user_id_is_valid_federated(target_user_id))
        {
            return std::nullopt;
        }
        auto result = make_operation_result(false, {}, "target user_id is not a valid Matrix user ID", 400U);
        result.errcode = "M_INVALID_PARAM";
        return result;
    }

    [[nodiscard]] auto persist_composed_event(HomeserverRuntime& runtime, std::string_view room_id,
                                              std::string_view sender, ComposedEvent const& composed) -> PersistOutcome;
    [[nodiscard]] auto record_room_share_started_device_changes(HomeserverRuntime& runtime, std::string_view room_id,
                                                                std::string_view joining_user_id) -> bool;
    [[nodiscard]] auto record_room_share_ended_device_changes(HomeserverRuntime& runtime, std::string_view room_id,
                                                              std::string_view departing_user_id) -> bool;

    // One hash lookup on a hit (ADR-0496). Every caller holds runtime.mutex.
    [[nodiscard]] auto find_room(LocalDatabase& database, std::string_view room_id) -> LocalRoom*
    {
        return find_local_room(database, room_id);
    }

    [[nodiscard]] auto find_room(LocalDatabase const& database, std::string_view room_id) -> LocalRoom const*
    {
        return find_local_room(database, room_id);
    }

    [[nodiscard]] auto room_has_member(LocalRoom const& room, std::string_view user_id) noexcept -> bool
    {
        return room.members.contains(user_id);
    }

    // Extract the server name from a Matrix room ID (!opaque:server_name): everything after the
    // FIRST ':', since the server name may carry a port. Empty for a room ID with no domain.
    [[nodiscard]] auto server_name_from_room_id(std::string_view room_id) -> std::string_view
    {
        return auth::identifier_server_name(room_id);
    }

    // Extract the home server domain from a Matrix user ID (@localpart:domain).
    [[nodiscard]] auto sender_domain_from_user_id(std::string_view sender) noexcept -> std::string_view
    {
        return auth::user_id_server_name(sender);
    }

    // Load the operator-supplied master key material from the configured file,
    // logging a diagnostic on failure. The file is treated as opaque binary
    // material; it is hashed with domain separation before being used as an
    // encryption key. Delegates to crypto::load_master_key_material — the
    // single source of truth for reading this file, shared with the
    // federation worker and auth service — rather than re-reading it here,
    // so the two copies cannot drift apart on size limits or error handling.
    // Build the database value for an encrypted signing secret:
    //   secretbox:v1:<base64(nonce || mac || ciphertext)>
    [[nodiscard]] auto encode_encrypted_secret_for_storage(crypto::SecretBoxCiphertext const& ciphertext) -> std::string
    {
        auto const encoded = events::matrix_base64_from_bytes(
            std::string_view{reinterpret_cast<char const*>(ciphertext.bytes.data()), ciphertext.bytes.size()});
        return std::string{crypto::secret_box_storage_prefix} + encoded;
    }

    // Reverse encode_encrypted_secret_for_storage.  Returns nullopt if the value
    // does not carry the expected prefix.
    [[nodiscard]] auto decode_encrypted_secret_from_storage(std::string_view stored) noexcept
        -> std::optional<crypto::SecretBoxCiphertext>
    {
        if (!stored.starts_with(crypto::secret_box_storage_prefix))
        {
            return std::nullopt;
        }
        auto const encoded = stored.substr(crypto::secret_box_storage_prefix.size());
        auto const decoded = events::matrix_bytes_from_base64(encoded);
        if (decoded.empty())
        {
            return std::nullopt;
        }
        auto ciphertext = crypto::SecretBoxCiphertext{};
        ciphertext.bytes.assign(decoded.begin(), decoded.end());
        return ciphertext;
    }

    // Encrypt raw Ed25519 secret bytes with the operator's master key.  Returns
    // nullopt if no master key is configured or libsodium is unavailable.
    [[nodiscard]] auto encrypt_signing_secret(HomeserverRuntime const& runtime, std::span<std::uint8_t const> secret)
        -> std::optional<std::string>
    {
        // Cached against the master key file's identity (finding 3): this used
        // to re-read the root secret and re-derive the box key on every call.
        auto const key = crypto::signing_secret_box_key(runtime.config.security().secrets.master_key_file);
        if (!key.has_value())
        {
            log_diagnostic("signing_key.master_key_unavailable",
                           {
                               {"path",   std::string{runtime.config.security().secrets.master_key_file}, false},
                               {"reason",
                                "master key file is missing, unreadable, empty, too large, or could "
                                "not be locked into memory",                                              false}
            });
            return std::nullopt;
        }
        auto const ciphertext = crypto::secret_box_encrypt(secret, *key);
        if (!ciphertext.has_value())
        {
            return std::nullopt;
        }
        return encode_encrypted_secret_for_storage(*ciphertext);
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

    [[nodiscard]] auto integer_member(canonicaljson::Object const& object, std::string_view key) noexcept
        -> std::int64_t const*
    {
        auto const* value = object_member(object, key);
        return value == nullptr ? nullptr : std::get_if<std::int64_t>(&value->storage());
    }

    [[nodiscard]] auto object_copy(canonicaljson::Value const& value) -> canonicaljson::Object
    {
        auto const* object = std::get_if<canonicaljson::Object>(&value.storage());
        return object == nullptr ? canonicaljson::Object{} : *object;
    }

    auto upsert_object_member(canonicaljson::Object& object, canonicaljson::ObjectMember member) -> void
    {
        auto const existing = std::ranges::find_if(object, [&member](canonicaljson::ObjectMember const& current) {
            return current.key == member.key;
        });
        if (existing != object.end())
        {
            *existing = std::move(member);
            return;
        }
        object.push_back(std::move(member));
    }

    [[nodiscard]] auto serialize_canonical_string(canonicaljson::Value const& value) -> std::optional<std::string>
    {
        auto const serialized = canonicaljson::serialize_canonical(value);
        if (serialized.error != canonicaljson::CanonicalJsonError::none)
        {
            return std::nullopt;
        }
        return serialized.output;
    }

    [[nodiscard]] auto serialize_membership_event_json(std::string_view user_id, std::string_view membership,
                                                       std::string_view reason = {}) -> std::optional<std::string>
    {
        auto content = canonicaljson::Object{};
        content.push_back(canonicaljson::make_member("membership", canonicaljson::Value{std::string{membership}}));
        if (!reason.empty())
        {
            content.push_back(canonicaljson::make_member("reason", canonicaljson::Value{std::string{reason}}));
        }

        auto event = canonicaljson::Object{};
        event.push_back(canonicaljson::make_member("type", canonicaljson::Value{std::string{"m.room.member"}}));
        event.push_back(canonicaljson::make_member("state_key", canonicaljson::Value{std::string{user_id}}));
        event.push_back(canonicaljson::make_member("content", canonicaljson::Value{std::move(content)}));
        return serialize_canonical_string(canonicaljson::Value{std::move(event)});
    }

    // Spec (Client-Server API, "Events on Change of Profile Information"): "when homeservers emit
    // room membership events for their own users, they should include the display name and avatar
    // URL fields in these events so that clients already have these details to hand". A field the
    // user has not set is left out rather than sent empty.
    auto add_member_profile(canonicaljson::Object& content, std::optional<database::PersistentProfile> const& profile)
        -> void
    {
        if (!profile.has_value())
        {
            return;
        }
        if (!profile->displayname.empty())
        {
            replace_or_add_member(content, "displayname", canonicaljson::Value{profile->displayname});
        }
        if (!profile->avatar_url.empty())
        {
            replace_or_add_member(content, "avatar_url", canonicaljson::Value{profile->avatar_url});
        }
    }

    // The m.room.member join this server sends for its own user `user_id`, carrying their profile.
    // `authorising_user`, when not empty, is the join_authorised_via_users_server of a join into
    // a restricted room through one of its allow conditions (R04).
    [[nodiscard]] auto serialize_own_join_event_json(database::PersistentStore const& store, std::string_view user_id,
                                                     std::string_view authorising_user = {})
        -> std::optional<std::string>
    {
        auto content = canonicaljson::Object{};
        if (!authorising_user.empty())
        {
            content.push_back(canonicaljson::make_member("join_authorised_via_users_server",
                                                         canonicaljson::Value{std::string{authorising_user}}));
        }
        content.push_back(canonicaljson::make_member("membership", canonicaljson::Value{std::string{"join"}}));
        add_member_profile(content, database::find_profile(store, user_id));

        auto event = canonicaljson::Object{};
        event.push_back(canonicaljson::make_member("type", canonicaljson::Value{std::string{"m.room.member"}}));
        event.push_back(canonicaljson::make_member("state_key", canonicaljson::Value{std::string{user_id}}));
        event.push_back(canonicaljson::make_member("content", canonicaljson::Value{std::move(content)}));
        return serialize_canonical_string(canonicaljson::Value{std::move(event)});
    }

    // Builds the client-supplied `m.room.third_party_invite` event JSON. The
    // state_key is the opaque invite token, and the content carries the Ed25519
    // public key used later to validate `third_party_signed` joins.
    // Spec: Matrix v1.19 rooms/v11.md — Authorization rules for m.room.third_party_invite.
    [[nodiscard]] auto serialize_third_party_invite_event_json(
        std::string_view token, std::string_view public_key_base64, std::string_view key_validity_url,
        std::vector<merovingian::identity::StoreInvitePublicKey> const& public_keys, std::string_view display_name)
        -> std::optional<std::string>
    {
        // The IS returns a long-term key and an ephemeral key; both are emitted
        // in `public_keys` so joining servers can verify the join-side `signed`
        // blob against either via each entry's `key_validity_url`. The
        // top-level `public_key`/`key_validity_url` carry the ephemeral key the
        // IS used to sign the token. Spec: client-server-api.md
        // § m.room.third_party_invite.
        auto public_keys_array = canonicaljson::Array{};
        for (auto const& entry : public_keys)
        {
            auto pk_entry = canonicaljson::Object{};
            pk_entry.push_back(
                canonicaljson::make_member("public_key", canonicaljson::Value{std::string{entry.public_key}}));
            if (!entry.key_validity_url.empty())
            {
                pk_entry.push_back(canonicaljson::make_member(
                    "key_validity_url", canonicaljson::Value{std::string{entry.key_validity_url}}));
            }
            public_keys_array.push_back(canonicaljson::Value{std::move(pk_entry)});
        }

        auto content = canonicaljson::Object{};
        content.push_back(canonicaljson::make_member("display_name", canonicaljson::Value{std::string{display_name}}));
        content.push_back(
            canonicaljson::make_member("public_key", canonicaljson::Value{std::string{public_key_base64}}));
        if (!key_validity_url.empty())
        {
            content.push_back(
                canonicaljson::make_member("key_validity_url", canonicaljson::Value{std::string{key_validity_url}}));
        }
        content.push_back(
            canonicaljson::make_member("public_keys", canonicaljson::Value{std::move(public_keys_array)}));

        auto event = canonicaljson::Object{};
        event.push_back(
            canonicaljson::make_member("type", canonicaljson::Value{std::string{"m.room.third_party_invite"}}));
        event.push_back(canonicaljson::make_member("state_key", canonicaljson::Value{std::string{token}}));
        event.push_back(canonicaljson::make_member("content", canonicaljson::Value{std::move(content)}));
        return serialize_canonical_string(canonicaljson::Value{std::move(event)});
    }

    // Forward declaration: defined later in this anonymous namespace.
    [[nodiscard]] auto find_event_json(database::PersistentStore const& store, std::string_view event_id)
        -> canonicaljson::Value;

    // Builds the `m.room.member` event that accepts a third-party invite.
    // Its content carries `membership: invite` and the client-supplied signed
    // blob inside `third_party_invite.signed`, satisfying rooms/v11.md rule 4.3.1.
    // The caller must persist this event before attempting the user's actual join.
    [[nodiscard]] auto serialize_third_party_invite_member_event_json(std::string_view target_user_id,
                                                                      canonicaljson::Object const& signed_obj)
        -> std::optional<std::string>
    {
        auto signed_copy = canonicaljson::Object{};
        signed_copy.reserve(signed_obj.size());
        for (auto const& member : signed_obj)
        {
            signed_copy.push_back(canonicaljson::make_member(member.key, *member.value));
        }

        auto third_party_invite = canonicaljson::Object{};
        third_party_invite.push_back(
            canonicaljson::make_member("signed", canonicaljson::Value{std::move(signed_copy)}));

        auto content = canonicaljson::Object{};
        content.push_back(canonicaljson::make_member("membership", canonicaljson::Value{std::string{"invite"}}));
        content.push_back(
            canonicaljson::make_member("third_party_invite", canonicaljson::Value{std::move(third_party_invite)}));

        auto event = canonicaljson::Object{};
        event.push_back(canonicaljson::make_member("type", canonicaljson::Value{std::string{"m.room.member"}}));
        event.push_back(canonicaljson::make_member("state_key", canonicaljson::Value{std::string{target_user_id}}));
        event.push_back(canonicaljson::make_member("content", canonicaljson::Value{std::move(content)}));
        return serialize_canonical_string(canonicaljson::Value{std::move(event)});
    }

    // Collects every public key from an m.room.third_party_invite event content:
    // the legacy content.public_key plus each entry of content.public_keys[].public_key.
    // Spec: rooms/v11.md Authorization rules for m.room.member, rule 4.3.1.7.
    [[nodiscard]] auto collect_third_party_invite_public_keys(canonicaljson::Value const& third_party_invite_event)
        -> std::vector<std::string>
    {
        auto keys = std::vector<std::string>{};
        auto const* event_obj = std::get_if<canonicaljson::Object>(&third_party_invite_event.storage());
        if (event_obj == nullptr)
        {
            return keys;
        }
        auto const* content_value = object_member(*event_obj, "content");
        auto const* content_obj =
            content_value == nullptr ? nullptr : std::get_if<canonicaljson::Object>(&content_value->storage());
        if (content_obj == nullptr)
        {
            return keys;
        }
        if (auto const* legacy = string_member(*content_obj, "public_key"); legacy != nullptr)
        {
            keys.push_back(*legacy);
        }
        auto const* public_keys_value = object_member(*content_obj, "public_keys");
        auto const* public_keys =
            public_keys_value == nullptr ? nullptr : std::get_if<canonicaljson::Array>(&public_keys_value->storage());
        if (public_keys == nullptr)
        {
            return keys;
        }
        for (auto const& entry : *public_keys)
        {
            auto const* entry_obj = std::get_if<canonicaljson::Object>(&entry.storage());
            if (entry_obj == nullptr)
            {
                continue;
            }
            if (auto const* entry_key = string_member(*entry_obj, "public_key"); entry_key != nullptr)
            {
                keys.push_back(*entry_key);
            }
        }
        return keys;
    }

    // Verifies a client-supplied `third_party_signed` object against the matching
    // m.room.third_party_invite state event. Returns true if any signature in the
    // signed blob verifies against any public key carried by the invite event.
    // Spec: client-server-api.md Third-party Signed; server-server-api.md § Verifying the invite.
    [[nodiscard]] auto verify_third_party_signed(canonicaljson::Object const& signed_obj,
                                                 std::string_view expected_mxid, database::PersistentStore const& store,
                                                 std::string_view room_id) -> bool
    {
        auto const* mxid = string_member(signed_obj, "mxid");
        auto const* sender = string_member(signed_obj, "sender");
        auto const* token = string_member(signed_obj, "token");
        auto const* signatures_value = object_member(signed_obj, "signatures");
        if (mxid == nullptr || sender == nullptr || token == nullptr || signatures_value == nullptr)
        {
            return false;
        }
        // The identity server signed this object for one Matrix ID; it vouches for no other.
        if (*mxid != expected_mxid)
        {
            return false;
        }

        // The public keys come from the m.room.third_party_invite state event whose state key is
        // the signed token, never from the signed object itself.
        auto const tpi_event_id =
            database::find_current_state_event_id(store, room_id, "m.room.third_party_invite", *token);
        if (!tpi_event_id.has_value())
        {
            return false;
        }

        auto const tpi_event = find_event_json(store, *tpi_event_id);
        auto const* tpi_obj = std::get_if<canonicaljson::Object>(&tpi_event.storage());
        if (tpi_obj == nullptr)
        {
            return false;
        }
        // The signed object names who made the invite; it must be the invite event's sender.
        auto const* tpi_sender = string_member(*tpi_obj, "sender");
        if (tpi_sender == nullptr || *tpi_sender != *sender)
        {
            return false;
        }

        auto const public_keys = collect_third_party_invite_public_keys(tpi_event);
        if (public_keys.empty())
        {
            return false;
        }

        // The signature covers the canonical JSON of the object without `signatures` and
        // `unsigned` (appendices.md, Signing JSON).
        auto payload_obj = canonicaljson::Object{};
        payload_obj.reserve(signed_obj.size());
        for (auto const& member : signed_obj)
        {
            if (member.key != "signatures" && member.key != "unsigned")
            {
                payload_obj.push_back(canonicaljson::make_member(member.key, *member.value));
            }
        }
        auto const serialized = canonicaljson::serialize_canonical(canonicaljson::Value{std::move(payload_obj)});
        if (serialized.error != canonicaljson::CanonicalJsonError::none)
        {
            return false;
        }

        auto const* signatures = std::get_if<canonicaljson::Object>(&signatures_value->storage());
        if (signatures == nullptr)
        {
            return false;
        }
        // Any signature that verifies against any of the invite's keys proves the identity
        // server signed it; the server and key ID it is filed under are not trusted.
        for (auto const& server_signatures : *signatures)
        {
            auto const* key_sigs = std::get_if<canonicaljson::Object>(&server_signatures.value->storage());
            if (key_sigs == nullptr)
            {
                continue;
            }
            for (auto const& key_sig : *key_sigs)
            {
                auto const* sig_b64 = std::get_if<std::string>(&key_sig.value->storage());
                if (sig_b64 == nullptr)
                {
                    continue;
                }
                auto const signature_bytes = events::matrix_bytes_from_base64(*sig_b64);
                if (signature_bytes.empty())
                {
                    continue;
                }
                for (auto const& pk_b64 : public_keys)
                {
                    auto const public_key_bytes = events::matrix_bytes_from_base64(pk_b64);
                    if (public_key_bytes.size() != 32U) // Ed25519 public keys are 32 bytes
                    {
                        continue;
                    }
                    auto const verification =
                        crypto::ed25519_verify(crypto::Ed25519PublicKey{public_key_bytes}, serialized.output,
                                               crypto::Ed25519Signature{signature_bytes});
                    if (verification.valid)
                    {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    [[nodiscard]] auto room_version_number(std::string_view room_version) -> int
    {
        auto parsed = int{0};
        auto const [ptr, error] =
            std::from_chars(room_version.data(), room_version.data() + room_version.size(), parsed);
        return error == std::errc{} && ptr == room_version.data() + room_version.size() ? parsed : 0;
    }

    // createRoom answers 400 M_INVALID_ROOM_STATE when "The initial state implied by the
    // parameters to the request is invalid".
    [[nodiscard]] auto invalid_room_state_result(std::string reason) -> OperationResult
    {
        auto result = make_operation_result(false, {}, std::move(reason), 400U);
        result.errcode = "M_INVALID_ROOM_STATE";
        return result;
    }

    // The inputs of rooms::room_creation_encryption_policy (ADR-0445), which alone decides.
    // An unknown preset is private, as its join rules and guest access already are (ADR-0447).
    // A room can federate when this server federates and `m.federate` is not boolean false,
    // which is what the create-event auth rule reads.
    [[nodiscard]] auto creation_encryption_request(HomeserverRuntime const& runtime, CreateRoomOptions const& options)
        -> rooms::RoomCreationEncryptionRequest
    {
        auto const preset = options.preset == "public_chat"            ? rooms::RoomPreset::public_chat
                            : options.preset == "trusted_private_chat" ? rooms::RoomPreset::trusted_private_chat
                                                                       : rooms::RoomPreset::private_chat;
        auto const* federate = object_member(options.creation_content, "m.federate");
        auto const* federate_flag = federate == nullptr ? nullptr : std::get_if<bool>(&federate->storage());
        auto const can_federate =
            runtime.config.security().federation.enabled && (federate_flag == nullptr || *federate_flag);
        return {preset, options.is_direct, can_federate,
                rooms::encryption_request_from_initial_state(options.initial_state),
                runtime.config.security().encryption};
    }

    // Room version 12: the creation options must imply valid initial state. Each of the
    // create event's additional_creators "MUST be a valid user ID", and the room's creators
    // (the creator, the additional creators and, for trusted_private_chat, the invitees
    // appended to them) "cannot be specified in the users field" of m.room.power_levels.
    // Refusing here, before anything is created, keeps a client's mistake from surfacing as
    // a 500 from the create event's own auth check, and from being silently repaired.
    [[nodiscard]] auto v12_creation_refusal(CreateRoomOptions const& options, std::string_view creator)
        -> std::optional<std::string>
    {
        if (room_version_number(options.room_version) < 12)
        {
            return std::nullopt;
        }
        auto creators = std::vector<std::string>{std::string{creator}};
        if (auto const* additional = object_member(options.creation_content, "additional_creators");
            additional != nullptr)
        {
            auto const* entries = std::get_if<canonicaljson::Array>(&additional->storage());
            if (entries == nullptr)
            {
                return std::string{"additional_creators must be an array of user IDs"};
            }
            for (auto const& entry : *entries)
            {
                auto const* additional_id = std::get_if<std::string>(&entry.storage());
                if (additional_id == nullptr || !auth::user_id_is_valid_federated(*additional_id))
                {
                    return std::string{"additional_creators must contain only valid user IDs"};
                }
                creators.push_back(*additional_id);
            }
        }
        if (options.preset == "trusted_private_chat")
        {
            creators.insert(creators.end(), options.trusted_invitees.begin(), options.trusted_invitees.end());
        }
        // Without an `events` override the tombstone level is generated one above
        // state_default; at canonical JSON's largest integer, (2^53)-1, there is no
        // level above it to give, and the event could not be signed.
        constexpr auto max_canonical_integer = std::int64_t{9007199254740991};
        if (object_member(options.power_level_content_override, "events") == nullptr)
        {
            if (auto const* state_default = integer_member(options.power_level_content_override, "state_default");
                state_default != nullptr && *state_default >= max_canonical_integer)
            {
                return std::string{"power_level_content_override state_default leaves no tombstone level above it"};
            }
        }
        if (auto const* users_value = object_member(options.power_level_content_override, "users");
            users_value != nullptr)
        {
            if (auto const* users = std::get_if<canonicaljson::Object>(&users_value->storage()); users != nullptr)
            {
                for (auto const& member : *users)
                {
                    if (std::ranges::find(creators, member.key) != creators.end())
                    {
                        return std::string{"power_level_content_override must not name a room creator in users"};
                    }
                }
            }
        }
        return std::nullopt;
    }

    [[nodiscard]] auto full_room_alias(config::ServerConfig const& server, std::string_view room_alias_name)
        -> std::string
    {
        return "#" + std::string{room_alias_name} + ":" + server.server_name;
    }

    [[nodiscard]] auto copy_member_or_empty_object(canonicaljson::Object const& object, std::string_view key)
        -> canonicaljson::Value
    {
        auto const* value = object_member(object, key);
        auto const* member_object = value == nullptr ? nullptr : std::get_if<canonicaljson::Object>(&value->storage());
        return member_object == nullptr ? canonicaljson::Value{canonicaljson::Object{}}
                                        : canonicaljson::Value{*member_object};
    }

    [[nodiscard]] auto string_array(std::vector<std::string> const& values) -> canonicaljson::Value
    {
        auto array = canonicaljson::Array{};
        array.reserve(values.size());
        for (auto const& value : values)
        {
            array.push_back(canonicaljson::Value{value});
        }
        return canonicaljson::Value{std::move(array)};
    }

    [[nodiscard]] auto object_member_as_object(canonicaljson::Object const& object, std::string_view key) noexcept
        -> canonicaljson::Object const*
    {
        auto const* value = object_member(object, key);
        return value == nullptr ? nullptr : std::get_if<canonicaljson::Object>(&value->storage());
    }

    [[nodiscard]] auto validate_make_join_event(std::string_view requested_room_id, std::string_view requested_user_id,
                                                canonicaljson::Object const& response_object)
        -> ValidatedMakeJoinResponse
    {
        auto const* room_version_str = string_member(response_object, "room_version");
        auto const* event_value = object_member(response_object, "event");
        auto const* event_object =
            event_value == nullptr ? nullptr : std::get_if<canonicaljson::Object>(&event_value->storage());
        if (event_object == nullptr)
        {
            return {false, "make_join missing event field"};
        }
        auto const* room_id = string_member(*event_object, "room_id");
        if (room_id == nullptr || *room_id != requested_room_id)
        {
            return {false, "make_join event room_id does not match request"};
        }
        auto const* sender = string_member(*event_object, "sender");
        if (sender == nullptr || *sender != requested_user_id)
        {
            return {false, "make_join event sender does not match request"};
        }
        auto const* state_key = string_member(*event_object, "state_key");
        if (state_key == nullptr || *state_key != requested_user_id)
        {
            return {false, "make_join event state_key does not match request"};
        }
        auto const* event_type = string_member(*event_object, "type");
        if (event_type == nullptr || *event_type != "m.room.member")
        {
            return {false, "make_join event type must be m.room.member"};
        }
        // "Joining Rooms": the joining server "is expected to add or replace the
        // origin, origin_server_ts, and event_id", so the template need not carry
        // them (claim_membership_event_template sets ours). Only type, room_id,
        // sender, state_key and content.membership MUST be verified.
        auto const* content = object_member_as_object(*event_object, "content");
        if (content == nullptr)
        {
            return {false, "make_join event content must be an object"};
        }
        auto const* membership = string_member(*content, "membership");
        if (membership == nullptr || *membership != "join")
        {
            return {false, "make_join event content.membership must be join"};
        }

        return {true, {}, room_version_str == nullptr ? std::string{"1"} : *room_version_str, *event_object};
    }

    // Validates the make_leave response body. Mirrors validate_make_join_event
    // but checks content.membership == "leave".
    [[nodiscard]] auto validate_make_leave_event(std::string_view requested_room_id, std::string_view requested_user_id,
                                                 canonicaljson::Object const& response_object)
        -> ValidatedMakeLeaveResponse
    {
        auto const* room_version_str = string_member(response_object, "room_version");
        auto const* event_value = object_member(response_object, "event");
        auto const* event_object =
            event_value == nullptr ? nullptr : std::get_if<canonicaljson::Object>(&event_value->storage());
        if (event_object == nullptr)
        {
            return {false, "make_leave missing event field"};
        }
        auto const* room_id_field = string_member(*event_object, "room_id");
        if (room_id_field == nullptr || *room_id_field != requested_room_id)
        {
            return {false, "make_leave event room_id does not match request"};
        }
        auto const* sender = string_member(*event_object, "sender");
        if (sender == nullptr || *sender != requested_user_id)
        {
            return {false, "make_leave event sender does not match request"};
        }
        auto const* state_key = string_member(*event_object, "state_key");
        if (state_key == nullptr || *state_key != requested_user_id)
        {
            return {false, "make_leave event state_key does not match request"};
        }
        auto const* event_type = string_member(*event_object, "type");
        if (event_type == nullptr || *event_type != "m.room.member")
        {
            return {false, "make_leave event type must be m.room.member"};
        }
        auto const* content = object_member_as_object(*event_object, "content");
        if (content == nullptr)
        {
            return {false, "make_leave event content must be an object"};
        }
        auto const* membership = string_member(*content, "membership");
        if (membership == nullptr || *membership != "leave")
        {
            return {false, "make_leave event content.membership must be leave"};
        }
        return {true, {}, room_version_str == nullptr ? std::string{"10"} : *room_version_str, *event_object};
    }

    // Validates a make_knock response: the template must be the requesting user's
    // own m.room.member knock in the requested room, and `room_version`, which the
    // spec marks Required, must be present.
    [[nodiscard]] auto validate_make_knock_event(std::string_view requested_room_id, std::string_view requested_user_id,
                                                 canonicaljson::Object const& response_object)
        -> ValidatedMakeLeaveResponse
    {
        auto const* room_version_str = string_member(response_object, "room_version");
        if (room_version_str == nullptr || room_version_str->empty())
        {
            return {false, "make_knock missing room_version"};
        }
        auto const* event_object = object_member_as_object(response_object, "event");
        if (event_object == nullptr)
        {
            return {false, "make_knock missing event field"};
        }
        auto const* room_id_field = string_member(*event_object, "room_id");
        auto const* sender = string_member(*event_object, "sender");
        auto const* state_key = string_member(*event_object, "state_key");
        auto const* event_type = string_member(*event_object, "type");
        auto const* content = object_member_as_object(*event_object, "content");
        auto const* membership = content == nullptr ? nullptr : string_member(*content, "membership");
        if (room_id_field == nullptr || *room_id_field != requested_room_id || sender == nullptr ||
            *sender != requested_user_id || state_key == nullptr || *state_key != requested_user_id ||
            event_type == nullptr || *event_type != "m.room.member" || membership == nullptr || *membership != "knock")
        {
            return {false, "make_knock event is not this user's knock in this room"};
        }
        return {true, {}, *room_version_str, *event_object};
    }

    [[nodiscard]] auto event_json_for_id(database::PersistentStore const& store, std::string_view event_id)
        -> std::optional<std::string>
    {
        auto const event = store.events.find(event_id);
        return event == store.events.end() ? std::nullopt : std::optional<std::string>{event->json};
    }

    // `pending_invite_json` is the invitee's m.room.member event when it is about
    // to be stored with this metadata (DB-4): it stands in for the invitee's
    // current member entry, where that entry is, or comes last, where the
    // stored event will go.
    [[nodiscard]] auto invite_state_events_for_room(database::PersistentStore const& store, std::string_view room_id,
                                                    std::string_view invitee,
                                                    std::optional<std::string_view> pending_invite_json = std::nullopt)
        -> std::vector<std::string>
    {
        auto events = std::vector<std::string>{};
        auto const strip = [&](std::optional<std::string> const& event_json) {
            if (!event_json.has_value())
            {
                return;
            }
            auto const parsed = canonicaljson::parse_lossless(*event_json);
            if (parsed.error != canonicaljson::ParseError::none)
            {
                return;
            }
            auto const* event = std::get_if<canonicaljson::Object>(&parsed.value.storage());
            if (event == nullptr)
            {
                return;
            }
            auto const* type = string_member(*event, "type");
            auto const* state_key = string_member(*event, "state_key");
            auto const* sender = string_member(*event, "sender");
            auto const* content = object_member(*event, "content");
            if (type == nullptr || state_key == nullptr || sender == nullptr || content == nullptr ||
                !std::holds_alternative<canonicaljson::Object>(content->storage()))
            {
                return;
            }
            // Matrix v1.19 #stripped-state: persist a room summary, not the roster
            // or private state. The exact type allowlist is our disclosure policy.
            auto const is_summary =
                state_key->empty() && (*type == "m.room.create" || *type == "m.room.name" || *type == "m.room.avatar" ||
                                       *type == "m.room.topic" || *type == "m.room.join_rules" ||
                                       *type == "m.room.canonical_alias" || *type == "m.room.encryption");
            if (!is_summary && !(*type == "m.room.member" && *state_key == invitee))
            {
                return;
            }
            auto stripped = canonicaljson::Object{};
            stripped.push_back(canonicaljson::make_member("sender", canonicaljson::Value{*sender}));
            stripped.push_back(canonicaljson::make_member("type", canonicaljson::Value{*type}));
            stripped.push_back(canonicaljson::make_member("state_key", canonicaljson::Value{*state_key}));
            stripped.push_back(canonicaljson::make_member("content", *content));
            auto const serialized = serialize_canonical_string(canonicaljson::Value{std::move(stripped)});
            if (serialized.has_value())
            {
                events.push_back(*serialized);
            }
        };
        auto pending_used = false;
        database::for_each_room_state_row(store, room_id, [&](database::PersistentStateEvent const& state) {
            if (pending_invite_json.has_value() && state.event_type == "m.room.member" && state.state_key == invitee)
            {
                strip(std::string{*pending_invite_json});
                pending_used = true;
                return;
            }
            strip(event_json_for_id(store, state.event_id));
        });
        if (pending_invite_json.has_value() && !pending_used)
        {
            strip(std::string{*pending_invite_json});
        }
        return events;
    }

    // Whether a user of this server is joined to `room_id`. Only then is this server in
    // the room: it holds the room's current state and composes membership events
    // itself. Otherwise a join or knock goes through a resident server, even when this
    // server still knows the room from an earlier stay (ADR-0244).
    [[nodiscard]] auto this_server_is_in_room(HomeserverRuntime const& runtime, std::string_view room_id) -> bool
    {
        auto const our_server = runtime.config.server().server_name;
        return std::ranges::any_of(runtime.database.persistent_store.memberships,
                                   [&](database::PersistentMembership const& membership) {
                                       return membership.room_id == room_id && membership.membership == "join" &&
                                              auth::identifier_server_name(membership.user_id) == our_server;
                                   });
    }

    // The servers of users joined to `room_id` in the state this server last held,
    // other than this one: the residents a rejoin can go through when the client names
    // no server and the room ID has no other domain to try.
    [[nodiscard]] auto last_known_resident_servers(HomeserverRuntime const& runtime, std::string_view room_id)
        -> std::vector<std::string>
    {
        auto const our_server = runtime.config.server().server_name;
        auto servers = std::vector<std::string>{};
        for (auto const& membership : runtime.database.persistent_store.memberships)
        {
            if (membership.room_id != room_id || membership.membership != "join")
            {
                continue;
            }
            auto const server = std::string{auth::identifier_server_name(membership.user_id)};
            if (!server.empty() && server != our_server && std::ranges::find(servers, server) == servers.end())
            {
                servers.push_back(server);
            }
        }
        return servers;
    }

    // The server of the user who invited `user_id` to `room_id`, when that is another server and the
    // invite is still pending: the server that sent the invite is in the room, or was when it sent it.
    // Server-Server API, "Joining Rooms" and "Leaving Rooms (Rejecting Invites)": the resident server
    // "may be the server which sent the invite". Empty when there is no such invite.
    [[nodiscard]] auto invite_sender_server(HomeserverRuntime const& runtime, std::string_view room_id,
                                            std::string_view user_id) -> std::string
    {
        auto const membership = std::ranges::find_if(
            runtime.database.persistent_store.memberships, [&](database::PersistentMembership const& current) {
                return current.room_id == room_id && current.user_id == user_id;
            });
        if (membership == runtime.database.persistent_store.memberships.end() || membership->membership != "invite")
        {
            return {};
        }
        auto const invite = database::find_invite(runtime.database.persistent_store, room_id, user_id);
        if (!invite.has_value())
        {
            return {};
        }
        auto server = std::string{auth::user_id_server_name(invite->sender_user_id)};
        return server == runtime.config.server().server_name ? std::string{} : server;
    }

    // ADR-0252: a federated join, knock or leave changes the user's membership with
    // runtime.mutex released for its network exchange. A refused request is told to
    // retry after about one federation round trip.
    constexpr auto membership_exchange_retry_after_ms = std::uint32_t{1000U};

    // The claim marks the pair for
    // that whole time; any other /join, /knock or /leave for it is refused meanwhile,
    // or its result would be overwritten when the exchange commits. Constructed
    // with runtime.mutex held; the destructor takes it (it is recursive) to release.
    class MembershipExchangeClaim final
    {
    public:
        MembershipExchangeClaim(HomeserverRuntime& runtime, std::string_view room_id, std::string_view user_id)
            : runtime_{runtime}
            , key_{std::string{room_id}, std::string{user_id}}
        {
            runtime_.membership_exchanges.insert(key_);
        }
        ~MembershipExchangeClaim() noexcept
        {
            auto const lock = std::lock_guard{runtime_.mutex};
            runtime_.membership_exchanges.erase(key_);
        }
        MembershipExchangeClaim(MembershipExchangeClaim const&) = delete;
        auto operator=(MembershipExchangeClaim const&) -> MembershipExchangeClaim& = delete;
        MembershipExchangeClaim(MembershipExchangeClaim&&) = delete;
        auto operator=(MembershipExchangeClaim&&) -> MembershipExchangeClaim& = delete;

    private:
        HomeserverRuntime& runtime_;
        std::pair<std::string, std::string> key_;
    };

    // 429 while a membership exchange for this user and room is in flight; called
    // with runtime.mutex held, before anything is read or written.
    // ADR-0315: a remote server keeps a knock or an invite once it has them, so a change this server would
    // refuse to store is refused before it leaves.
    [[nodiscard]] auto sync_stream_refusal(HomeserverRuntime const& runtime) -> std::optional<OperationResult>
    {
        if (database::sync_stream_has_write_reserve(runtime.database.persistent_store))
        {
            return std::nullopt;
        }
        return make_operation_result(false, {}, "sync stream counter exhausted", 500U);
    }

    [[nodiscard]] auto membership_exchange_refusal(HomeserverRuntime const& runtime, std::string_view room_id,
                                                   std::string_view user_id) -> std::optional<OperationResult>
    {
        if (auto refused = sync_stream_refusal(runtime); refused.has_value())
        {
            return refused;
        }
        if (!runtime.membership_exchanges.contains(std::pair{std::string{room_id}, std::string{user_id}}))
        {
            return std::nullopt;
        }
        auto refused = make_operation_result(false, {}, "a membership change for this room is in progress", 429U);
        refused.retry_after_ms = membership_exchange_retry_after_ms;
        return refused;
    }

    // The answer when a federated join, knock or leave finds no client-outbound slot (ADR-0622): the same as the
    // other client-triggered outbound calls give (ADR-0079).
    [[nodiscard]] auto client_outbound_limit_result(HomeserverRuntime const& runtime) -> OperationResult
    {
        auto refused = make_operation_result(false, {}, "too many concurrent remote requests, retry shortly", 429U);
        refused.errcode = "M_LIMIT_EXCEEDED";
        refused.retry_after_ms = runtime.client_outbound_proxy_policy.retry_after_ms;
        return refused;
    }

    // Whether the room's stored m.room.create was sent by a user of this server.
    [[nodiscard]] auto room_created_here(HomeserverRuntime const& runtime, std::string_view room_id) -> bool
    {
        auto const& store = runtime.database.persistent_store;
        auto const create_event_id = database::find_current_state_event_id(store, room_id, "m.room.create", "");
        if (!create_event_id.has_value())
        {
            return false;
        }
        auto const event = store.events.find_in_room(room_id, *create_event_id);
        return event != store.events.end() &&
               auth::identifier_server_name(event->sender_user_id) == runtime.config.server().server_name;
    }

    [[nodiscard]] auto room_exists(HomeserverRuntime const& runtime, std::string_view room_id) -> bool
    {
        return find_room(runtime.database, room_id) != nullptr ||
               std::ranges::any_of(runtime.database.persistent_store.rooms,
                                   [room_id](database::PersistentRoom const& room) {
                                       return room.room_id == room_id;
                                   });
    }

    [[nodiscard]] auto membership_state_entry(database::PersistentStore const& store, std::string_view room_id,
                                              std::string_view user_id) -> std::optional<database::PersistentStateEvent>
    {
        auto const event_id = database::find_current_state_event_id(store, room_id, "m.room.member", user_id);
        return event_id.has_value() ? std::optional<database::PersistentStateEvent>{database::PersistentStateEvent{
                                          std::string{room_id}, "m.room.member", std::string{user_id}, *event_id}}
                                    : std::nullopt;
    }

    [[nodiscard]] auto store_or_update_membership(database::PersistentStore& store, std::string_view room_id,
                                                  std::string_view user_id, std::string_view membership,
                                                  std::uint64_t stream_ordering) -> bool
    {
        auto const result = database::store_membership(
            store, {std::string{room_id}, std::string{user_id}, std::string{membership}, stream_ordering});
        if (result == database::MembershipStoreResult::error)
        {
            return false;
        }
        return result != database::MembershipStoreResult::already_exists ||
               database::update_membership(store, room_id, user_id, membership, stream_ordering);
    }

    // Sends an event composed here to every other server in the room: those of its
    // joined members once the event applies, and `target_user_id`'s server (empty for
    // none). Server-Server API, "Room Events": a server sends the events it creates to
    // the room's other servers. Every path that composes and stores an event must call
    // it; a membership event that did not (a join, leave, kick, ban or local knock)
    // never reached another server.
    //
    // `excluded_server` (empty for none) is never sent the event: a resident that accepted
    // a send_join, send_leave or send_knock does not send it back to the server that made
    // the request, which already holds it.
    auto queue_event_to_room_servers(HomeserverRuntime& runtime, std::string_view room_id,
                                     std::vector<std::string> const& members, std::string_view event_id,
                                     std::string const& event_json, std::string_view target_user_id,
                                     std::string_view excluded_server) -> void
    {
        if (runtime.dispatch_worker != nullptr)
        {
            auto const& server_name = runtime.config.server().server_name;
            // Each remote server once, in the order the members name them. A set answers "seen" in one lookup;
            // searching the list per member made a large room cost members x servers.
            auto remote_servers = std::vector<std::string>{};
            auto seen_servers = std::unordered_set<std::string>{};
            auto const note_remote_server = [&](std::string_view candidate) {
                if (!candidate.empty() && candidate != server_name && candidate != excluded_server &&
                    seen_servers.emplace(candidate).second)
                {
                    remote_servers.emplace_back(candidate);
                }
            };
            for (auto const& member : members)
            {
                note_remote_server(auth::user_id_server_name(member));
            }
            // The target of a kick, ban or unban is told even though it is no longer (or
            // not yet) among the room's members once the event applies. An invite reaches
            // the invitee's server through /invite instead.
            note_remote_server(auth::user_id_server_name(target_user_id));
            // Built by the shared builder so the transaction carries the Required `origin` and
            // `origin_server_ts`; a hand-built body without them was refused by strict receivers.
            auto const tx_body_result = remote_servers.empty()
                                            ? std::optional<std::string>{}
                                            : federation::build_pdu_transaction_body(server_name, event_json);
            if (!remote_servers.empty() && !tx_body_result.has_value())
            {
                log_diagnostic("room.event.dispatch_refused",
                               {
                                   {"room_id",  std::string{room_id},                  false},
                                   {"event_id", std::string{event_id},                 false},
                                   {"reason",   "transaction body could not be built", false}
                },
                               observability::LogEventSeverity::error);
            }
            if (tx_body_result.has_value())
            {
                auto const& tx_body = *tx_body_result;
                // One transaction ID per destination: it is the durable queue row's key, so a shared ID
                // left one row for the whole fan-out and the first delivery deleted the others' row.
                // The destinations are queued as one batch: one committed transaction for the event, not one per
                // server (ADR-0441).
                auto refused = std::vector<std::string>{};
                auto batch = std::vector<federation::OutboundTransaction>{};
                auto batch_destinations = std::vector<std::string_view>{};
                batch.reserve(remote_servers.size());
                for (auto const& destination : remote_servers)
                {
                    // ADR-0391: not a refusal to report; the operator said this server gets nothing.
                    if (!federation::federation_server_policy(runtime.federation.config, destination).allowed)
                    {
                        continue;
                    }
                    auto const tx_id = federation::make_federation_transaction_id();
                    auto target = "/_matrix/federation/v1/send/" + tx_id;
                    auto transaction =
                        federation::make_outbound_transaction(destination, "PUT", target, server_name, tx_body);
                    transaction.transaction_id = tx_id;
                    batch.push_back(std::move(transaction));
                    batch_destinations.push_back(destination);
                }
                auto const accepted = runtime.dispatch_worker->enqueue_batch(std::move(batch));
                for (auto position = std::size_t{0U}; position < accepted.size(); ++position)
                {
                    if (!accepted[position])
                    {
                        refused.emplace_back(batch_destinations[position]);
                    }
                }
                if (!refused.empty())
                {
                    // The worker refused these (its queue, or the destination's share of it, is full).
                    // They are not retried; each peer recovers the event itself through prev_events
                    // once it is reachable (security audit run-1).
                    auto names = std::string{};
                    for (auto const& name : refused)
                    {
                        names += names.empty() ? name : "," + name;
                    }
                    log_diagnostic("room.event.dispatch_refused",
                                   {
                                       {"room_id",      std::string{room_id},           false},
                                       {"event_id",     std::string{event_id},          false},
                                       {"refused",      std::to_string(refused.size()), false},
                                       {"destinations", names,                          false}
                    },
                                   observability::LogEventSeverity::warning);
                }
                log_diagnostic("room.event.dispatched",
                               {
                                   {"room_id",      std::string{room_id},                                   false},
                                   {"event_id",     std::string{event_id},                                  false},
                                   {"destinations", std::to_string(remote_servers.size() - refused.size()), false}
                });
            }
        }
    }

    auto federate_local_event(HomeserverRuntime& runtime, std::string_view room_id, LocalRoom const& room,
                              ComposedEvent const& composed, std::string_view target_user_id = {}) -> void
    {
        wire_federation_callbacks(runtime);
        queue_event_to_room_servers(runtime, room_id, room.members, composed.event_id, composed.json, target_user_id,
                                    {});
    }

    // Forward declaration: defined further down this file, after
    // build_pending_push_deliveries / dispatch_push_deliveries /
    // PendingPushDelivery (near send_event, alongside the rest of the push
    // evaluation logic). This declaration's own signature deliberately never
    // names PendingPushDelivery, so persist_membership_transition, join_room
    // and invite_user_by_threepid (all defined earlier in the file than
    // that block) can call it via plain forward declaration without
    // requiring PendingPushDelivery to be a complete type at their call
    // sites -- constructing/moving a std::vector<PendingPushDelivery> would
    // need that, but it happens only inside this function's body, defined
    // later where the type is complete.
    auto dispatch_membership_push_notification(HomeserverRuntime& runtime, LocalRoom const& room,
                                               ComposedEvent const& composed, std::string_view sender,
                                               std::string_view extra_recipient) -> void;

    // A membership event composed and signed but not yet stored: the event, or why there is none.
    struct ComposedMembership final
    {
        std::optional<ComposedEvent> event{};
        OperationResult failure{};
    };

    [[nodiscard]] auto compose_membership_transition(HomeserverRuntime& runtime, std::string_view room_id,
                                                     std::string_view sender_user_id, std::string_view target_user_id,
                                                     std::string_view membership, std::string_view reason)
        -> ComposedMembership
    {
        auto const event_json = serialize_membership_event_json(target_user_id, membership, reason);
        if (!event_json.has_value())
        {
            return {std::nullopt, make_operation_result(false, {}, "membership event serialization failed", 500U)};
        }

        auto composition = compose_signed_event(runtime, room_id, sender_user_id, *event_json);
        if (composition.failure == ComposeFailure::too_large)
        {
            return {std::nullopt, event_too_large_result()};
        }
        if (!composition.event.has_value())
        {
            return {std::nullopt, make_operation_result(false, {}, "membership event rejected", 403U)};
        }
        return {std::move(composition.event), {}};
    }

    // Stores a composed membership event and tells the room's servers, the room's clients and the push
    // gateways about it. Split from the composing so that an invite to a user of another server can be
    // offered to that user's server in between (Server-Server API, "Inviting to a room").
    [[nodiscard]] auto store_composed_membership(HomeserverRuntime& runtime, std::string_view room_id,
                                                 std::string_view sender_user_id, std::string_view target_user_id,
                                                 std::string_view membership, ComposedEvent const& composed_event)
        -> OperationResult
    {
        if (persist_composed_event(runtime, room_id, sender_user_id, composed_event) == PersistOutcome::not_stored)
        {
            return make_operation_result(false, {}, "membership event persistence failed", 500U);
        }

        // persist_composed_event has already projected the membership (CSAZ-6).
        auto* room = find_room(runtime.database, room_id);
        if (room != nullptr)
        {
            // An invite reaches the invitee's server through /invite; every other
            // membership change also reaches its target's server.
            federate_local_event(runtime, room_id, *room, composed_event,
                                 membership == "invite" ? std::string_view{} : target_user_id);
        }

        auto const sync_stream_id = database::allocate_sync_stream_id(runtime.database.persistent_store);
        if (runtime.sync_notifier != nullptr)
        {
            // ADR-0437: the room's joined and invited members, the sender, and the user whose membership
            // changed, who may have just left it (kick, ban, leave).
            auto const audience =
                sync_audience_of_room(runtime.database.persistent_store, room_id, {sender_user_id, target_user_id});
            runtime.sync_notifier->publish(visible_stream_position(runtime.database), sync_stream_id, audience);
        }
        // Push delivery: covers invite/ban/kick/leave/knock, all funneled
        // through this one function. `target_user_id` is passed as an extra
        // recipient because for "invite" they are not (yet) a joined member
        // of `room` — see dispatch_membership_push_notification. For every
        // other membership value this is a harmless no-op: the default
        // ruleset's `.m.rule.member_event` override suppresses notification
        // for non-invite membership events, and a self-transition (leave,
        // knock) is filtered as the sender regardless.
        if (room != nullptr)
        {
            dispatch_membership_push_notification(runtime, *room, composed_event, sender_user_id, target_user_id);
        }
        return make_operation_result(true, std::string{room_id});
    }

    [[nodiscard]] auto persist_membership_transition(HomeserverRuntime& runtime, std::string_view room_id,
                                                     std::string_view sender_user_id, std::string_view target_user_id,
                                                     std::string_view membership, std::string_view reason = {})
        -> OperationResult
    {
        auto const composed =
            compose_membership_transition(runtime, room_id, sender_user_id, target_user_id, membership, reason);
        if (!composed.event.has_value())
        {
            return composed.failure;
        }
        return store_composed_membership(runtime, room_id, sender_user_id, target_user_id, membership, *composed.event);
    }

    // Per the Matrix spec v1.19 Sec. 4.4 auth_events, only specific event types
    // belong in auth_events depending on the event being composed:
    //   m.room.create:  none
    //   m.room.member:  {create, power_levels, sender_member, target_member}, plus
    //                   join_rules only when the membership is join, invite or
    //                   knock (auth rule 3.2 rejects any entry the selection does
    //                   not name, so a leave or ban carrying it is rejected)
    //   all others:      {create, power_levels, sender_member}
    // Room v12 (MSC4291) excludes create from auth_events (implied by room ID).
    // Synapse rejects events that include unrelated auth_events (e.g. join_rules
    // in a history_visibility event) with "unexpected auth_event".
    [[nodiscard]] auto auth_events_for_room(database::PersistentStore const& store, std::string_view room_id,
                                            std::string_view event_type, std::string_view membership,
                                            std::string_view target_state_key, std::string_view sender,
                                            bool exclude_create) -> std::vector<std::string>
    {
        auto const names_join_rules =
            event_type == "m.room.member" && (membership == "join" || membership == "invite" || membership == "knock");
        if (event_type == "m.room.create")
        {
            return {};
        }
        auto event_ids = std::vector<std::string>{};
        database::for_each_room_state_row(store, room_id, [&](database::PersistentStateEvent const& state) {
            if (state.event_type == "m.room.create" && state.state_key.empty())
            {
                if (!exclude_create)
                {
                    event_ids.push_back(state.event_id);
                }
                return;
            }
            if (state.event_type == "m.room.power_levels" && state.state_key.empty())
            {
                event_ids.push_back(state.event_id);
                return;
            }
            if (state.event_type == "m.room.join_rules" && state.state_key.empty())
            {
                if (names_join_rules)
                {
                    event_ids.push_back(state.event_id);
                }
                return;
            }
            if (state.event_type == "m.room.member")
            {
                if (event_type == "m.room.member" && state.state_key == target_state_key)
                {
                    event_ids.push_back(state.event_id);
                    return;
                }
                if (state.state_key == sender)
                {
                    // Avoid duplicate when sender == target (self-join).
                    if (event_type != "m.room.member" || target_state_key != sender)
                    {
                        event_ids.push_back(state.event_id);
                    }
                }
            }
            // All other state event types (history_visibility, guest_access,
            // encryption, canonical_alias, etc.) are NOT valid auth_events
            // for any event type per the Matrix spec.
        });
        return event_ids;
    }

    auto append_unique_member(std::vector<std::string>& members, std::string_view user_id) -> void
    {
        if (!std::ranges::any_of(members, [&](std::string const& member) {
                return member == user_id;
            }))
        {
            members.emplace_back(user_id);
        }
    }

    [[nodiscard]] auto is_local_user(LocalDatabase const& database, std::string_view user_id) noexcept -> bool
    {
        return std::ranges::any_of(database.users, [user_id](LocalUser const& user) {
            return user.user_id == user_id;
        });
    }

    // Spec (client-server-api.md, "Tracking the device list for a user"): a user who starts sharing a
    // room with a local user is added to that user's `device_lists.changed`. Called once the joiner is
    // on the room's roster. One batch, so one stream position and two commits (the watermark, then the
    // rows) however large the room is
    // (the roster of a federated room is chosen by a remote server).
    [[nodiscard]] auto record_room_share_started_device_changes(HomeserverRuntime& runtime, std::string_view room_id,
                                                                std::string_view joining_user_id) -> bool
    {
        auto const* room = find_room(runtime.database, room_id);
        if (room == nullptr)
        {
            return true;
        }
        auto const local_users = local_user_ids(runtime.database);
        auto const joiner_is_local = local_users.contains(joining_user_id);
        auto changes = std::vector<database::PersistentDeviceListChange>{};
        for (auto const& member : room->members)
        {
            if (member == joining_user_id)
            {
                continue;
            }
            // Only a local user has a client to tell; a remote user's server tracks its own.
            if (local_users.contains(member))
            {
                changes.push_back({0U, member, std::string{joining_user_id}, "changed"});
            }
            if (joiner_is_local)
            {
                changes.push_back({0U, std::string{joining_user_id}, member, "changed"});
            }
        }
        return database::record_device_list_changes(runtime.database.persistent_store, std::move(changes));
    }

    // Spec (same section): "Bob can also be notified when he stops sharing any room with Alice by
    // inspecting the `left` property". Called while the departing user is still on the roster. A
    // member who still shares another joined room with them is not told they left.
    [[nodiscard]] auto record_room_share_ended_device_changes(HomeserverRuntime& runtime, std::string_view room_id,
                                                              std::string_view departing_user_id) -> bool
    {
        auto const* room = find_room(runtime.database, room_id);
        if (room == nullptr)
        {
            return true;
        }
        auto still_sharing = std::unordered_set<std::string_view>{};
        for (auto const& other : runtime.database.rooms)
        {
            if (other.room_id == room_id || !room_has_member(other, departing_user_id))
            {
                continue;
            }
            still_sharing.insert(other.members.begin(), other.members.end());
        }
        auto const local_users = local_user_ids(runtime.database);
        auto const departing_is_local = local_users.contains(departing_user_id);
        // A remote user who now shares no room with a local user gets no updates sent here: forget their
        // cached device list (ADR-0560).
        if (!departing_is_local && std::ranges::none_of(still_sharing, [&local_users](std::string_view member) {
                return local_users.contains(member);
            }))
        {
            runtime.remote_device_lists.erase(departing_user_id);
        }
        auto changes = std::vector<database::PersistentDeviceListChange>{};
        for (auto const& member : room->members)
        {
            if (member == departing_user_id || still_sharing.contains(member))
            {
                continue;
            }
            if (local_users.contains(member))
            {
                changes.push_back({0U, member, std::string{departing_user_id}, "left"});
            }
            if (departing_is_local)
            {
                changes.push_back({0U, std::string{departing_user_id}, member, "left"});
            }
        }
        return database::record_device_list_changes(runtime.database.persistent_store, std::move(changes));
    }

    // A user who joins a room over federation is told to refresh their own account's device list too:
    // their server has just learned the whole roster, and their other devices have to be told the
    // account now shares a room with these users. The spec lets a server list a user in `changed`
    // when they start sharing a further room (client-server-api.md, DeviceLists note); Complement
    // TestDeviceListsUpdateOverFederation expects the joiner to be listed.
    [[nodiscard]] auto record_own_device_list_change(HomeserverRuntime& runtime, std::string_view user_id) -> bool
    {
        if (!is_local_user(runtime.database, user_id))
        {
            return true;
        }
        return database::record_device_list_change(runtime.database.persistent_store,
                                                   {0U, std::string{user_id}, std::string{user_id}, "changed"});
    }

    [[nodiscard]] auto find_event_json(database::PersistentStore const& store, std::string_view event_id)
        -> canonicaljson::Value
    {
        auto const event = store.events.find(event_id);
        if (event == store.events.end())
        {
            return {};
        }
        auto const parsed = canonicaljson::parse_lossless(event->json);
        return parsed.error == canonicaljson::ParseError::none ? parsed.value : canonicaljson::Value{};
    }

    // Extracts content.third_party_invite.signed.token from an in-progress
    // m.room.member event, if present. Used to look up the matching
    // m.room.third_party_invite state event for rule 4.3.1 (auth of 3PID invites).
    [[nodiscard]] auto third_party_invite_token(canonicaljson::Value const& event) -> std::string
    {
        auto const* obj = std::get_if<canonicaljson::Object>(&event.storage());
        auto const* content = obj == nullptr ? nullptr : object_member_as_object(*obj, "content");
        auto const* third_party_invite =
            content == nullptr ? nullptr : object_member_as_object(*content, "third_party_invite");
        auto const* signed_obj =
            third_party_invite == nullptr ? nullptr : object_member_as_object(*third_party_invite, "signed");
        auto const* token = signed_obj == nullptr ? nullptr : string_member(*signed_obj, "token");
        return token == nullptr ? std::string{} : *token;
    }

    // A join's content.join_authorised_via_users_server, or empty. server-server-api.md
    // "Auth events selection": "If type is m.room.member and membership is join, and
    // content.join_authorised_via_users_server is present ... the current m.room.member
    // event with state_key matching content.join_authorised_via_users_server".
    [[nodiscard]] auto join_authorising_user_of(canonicaljson::Value const& event) -> std::string
    {
        auto const* obj = std::get_if<canonicaljson::Object>(&event.storage());
        auto const* type = obj == nullptr ? nullptr : string_member(*obj, "type");
        if (type == nullptr || *type != "m.room.member" || events::extract_content_membership(event) != "join")
        {
            return {};
        }
        auto const* content = obj == nullptr ? nullptr : object_member_as_object(*obj, "content");
        auto const* authorising =
            content == nullptr ? nullptr : string_member(*content, "join_authorised_via_users_server");
        return authorising == nullptr ? std::string{} : *authorising;
    }

    // `user_id`'s membership in the room's current state, or empty.
    [[nodiscard]] auto current_membership_of(database::PersistentStore const& store, std::string_view room_id,
                                             std::string_view user_id) -> std::string
    {
        auto const event_id = database::find_current_state_event_id(store, room_id, "m.room.member", user_id);
        return event_id.has_value() ? std::string{events::extract_content_membership(find_event_json(store, *event_id))}
                                    : std::string{};
    }

    [[nodiscard]] auto build_auth_event_map(database::PersistentStore const& store, std::string_view room_id,
                                            std::string_view sender, std::string_view target_state_key,
                                            std::string_view event_type, canonicaljson::Value const& event)
        -> events::AuthEventMap
    {
        // One state index lookup per key the auth rules read (ADR-0344): the cost of authorising a composed event
        // is bounded by the keys it names, never by the state of every room on the server.
        auto result = events::AuthEventMap{};
        auto const current = [&](std::string_view type, std::string_view state_key) -> std::optional<std::string> {
            return database::find_current_state_event_id(store, room_id, type, state_key);
        };
        // Auth events selection: a join carrying join_authorised_via_users_server also names that user's
        // current m.room.member event (R04).
        if (auto const authorising_user = join_authorising_user_of(event); !authorising_user.empty())
        {
            if (auto const id = current("m.room.member", authorising_user); id.has_value())
            {
                result.authorising_user_member = find_event_json(store, *id);
            }
        }
        if (auto const id = current("m.room.create", ""); id.has_value())
        {
            result.create = find_event_json(store, *id);
            result.create_event_id = *id;
        }
        if (auto const id = current("m.room.power_levels", ""); id.has_value())
        {
            result.power_levels = find_event_json(store, *id);
        }
        if (auto const id = current("m.room.join_rules", ""); id.has_value())
        {
            result.join_rules = find_event_json(store, *id);
        }
        if (auto const id = current("m.room.member", sender); id.has_value())
        {
            result.sender_member = find_event_json(store, *id);
        }
        if (event_type == "m.room.member")
        {
            if (auto const id = current("m.room.member", target_state_key); id.has_value())
            {
                result.target_member = find_event_json(store, *id);
            }
        }
        if (auto const invite_token = third_party_invite_token(event); !invite_token.empty())
        {
            if (auto const id = current("m.room.third_party_invite", invite_token); id.has_value())
            {
                result.third_party_invite = find_event_json(store, *id);
            }
        }
        return result;
    }

    // Returns the room_version string from the room's m.room.create event, or "10"
    // as a safe fallback for rooms that pre-date initial-state generation.
    // The room's version, from its m.room.create through the one accessor
    // (stored_room_version). A room with no stored create falls back to "12",
    // the createRoom and capabilities default; a create without room_version is
    // room version 1, which has no policy, so nothing is composed in that room.
    [[nodiscard]] auto room_version_for_room(database::PersistentStore const& store, std::string_view room_id)
        -> std::string
    {
        return stored_room_version(store, room_id).value_or("12");
    }

    [[nodiscard]] auto compose_signed_event(HomeserverRuntime& runtime, std::string_view room_id,
                                            std::string_view sender, std::string_view client_event_json,
                                            std::optional<std::int64_t> origin_server_ts) -> ComposeResult
    {
        auto const parsed = canonicaljson::parse_lossless(client_event_json);
        auto const* input = std::get_if<canonicaljson::Object>(&parsed.value.storage());
        if (parsed.error != canonicaljson::ParseError::none || input == nullptr)
        {
            log_diagnostic("event.compose.body_rejected",
                           {
                               {"room_id",    std::string{room_id},                     false},
                               {"sender",     std::string{sender},                      false},
                               {"body_bytes", std::to_string(client_event_json.size()), false}
            });
            return ComposeResult{std::nullopt, ComposeFailure::rejected};
        }

        auto const* type = string_member(*input, "type");
        auto const event_type = type == nullptr ? std::string{"m.room.message"} : *type;
        auto const event_state_key = [input]() -> std::optional<std::string> {
            if (auto const* sk = string_member(*input, "state_key"); sk != nullptr)
            {
                return *sk;
            }
            return std::nullopt;
        }();
        if (event_state_key.has_value() && events::state_key_contains_nul(*event_state_key))
        {
            return ComposeResult{std::nullopt, ComposeFailure::invalid_state_key};
        }
        // CSAZ-9. Spec v1.19 "Size limits": "`state_key` MUST NOT exceed 255 bytes" and "`type`
        // MUST NOT exceed 255 bytes". Refused here, before anything is composed or stored.
        if (event_type.size() > events::max_event_type_length_bytes ||
            (event_state_key.has_value() && event_state_key->size() > events::max_state_key_length_bytes))
        {
            log_diagnostic(
                "event.compose.too_large",
                {
                    {"room_id",         std::string{room_id},                                           false},
                    {"sender",          std::string{sender},                                            false},
                    {"type_bytes",      std::to_string(event_type.size()),                              false},
                    {"state_key_bytes", std::to_string(event_state_key.value_or(std::string{}).size()), false}
            });
            return ComposeResult{std::nullopt, ComposeFailure::too_large};
        }
        // Derive the room version so the correct signing policy (event-id format, auth
        // rules, MSC4291/MSC4289 behaviour) is used for every event in the room. The
        // m.room.create event carries its own room_version in content — and while it is
        // being composed the store holds no create row yet — so read it from the event
        // itself; every other event reads the version from the room's persisted create.
        auto room_version = std::string{};
        if (event_type == "m.room.create")
        {
            room_version = declared_room_version(*input);
        }
        else
        {
            room_version = room_version_for_room(runtime.database.persistent_store, room_id);
        }
        auto const* policy = rooms::find_room_version_policy(room_version);
        if (policy == nullptr)
        {
            return ComposeResult{std::nullopt, ComposeFailure::rejected};
        }
        // MSC4291 (room v12): the create event omits room_id (the room ID is its reference
        // hash) and no event lists the create event in its auth_events.
        auto const create_defines_room_id = policy->create_event_is_room_id;
        auto const omit_room_id = event_type == "m.room.create" && create_defines_room_id;
        // ADR-0064 phase B1: prev_events for a new local event are the room's
        // recorded forward extremities, not "whatever was inserted into
        // store.events last". ADR-0225: chosen together with the state before
        // them, falling back to the newest extremity alone when the state
        // across all of them cannot be resolved.
        auto basis =
            basis_for_new_event(runtime.database.persistent_store, room_id, *policy,
                                state_resolution_limits(runtime.config.security().federation.state_resolution));
        auto const prev_events = basis.prev_event_ids;
        auto const membership = event_type == "m.room.member"
                                    ? events::extract_content_membership(canonicaljson::Value{*input})
                                    : std::string{};
        auto auth_events = auth_events_for_room(runtime.database.persistent_store, room_id, event_type, membership,
                                                event_state_key.value_or(""), sender, create_defines_room_id);
        // 3PID invite member events must list the matching m.room.third_party_invite
        // event in auth_events. auth_events_for_room does not inspect content, so
        // add it here when the client event carries a third_party_invite token.
        // client-server-api.md, m.room.member `join_authorised_via_users_server`: "When copying
        // the membership event's content (for profile updates and similar) it is therefore
        // encouraged to exclude this field in the copy, as otherwise the event might fail event
        // authorisation." A join by a user who is already joined needs no authorisation (rooms/v10.md
        // 4.3.5.1), so a copied field is dropped rather than honoured or refused.
        auto const drop_join_authoriser =
            event_type == "m.room.member" && membership == "join" && event_state_key == sender &&
            current_membership_of(runtime.database.persistent_store, room_id, sender) == "join";
        if (event_type == "m.room.member")
        {
            // A restricted join names its authorising user's m.room.member
            // event too (auth events selection, R04). This server signs every
            // event it composes, so a join naming one of its own users would
            // carry that user's server's signature whoever asked for it: the
            // field is honoured only when the allow conditions hold now, for
            // this joining user and that authorising user (client-server-api.md
            // "Restricted rooms": "the server MUST verify that the requesting
            // user meets at least one of the conditions"). A client cannot
            // name an authoriser through PUT /state to skip the check.
            if (auto const authorising_user =
                    drop_join_authoriser ? std::string{} : join_authorising_user_of(canonicaljson::Value{*input});
                !authorising_user.empty())
            {
                auto const& our_server = runtime.config.server().server_name;
                if (sender_domain_from_user_id(authorising_user) == our_server)
                {
                    auto const decision =
                        decide_restricted_join(runtime.database.persistent_store, room_id,
                                               event_state_key.value_or(std::string{}), our_server, authorising_user);
                    if (decision.verdict != RestrictedJoinVerdict::authorised)
                    {
                        log_diagnostic("event.compose.rejected", {
                                                                     {"room_id", std::string{room_id}, false},
                                                                     {"sender",  std::string{sender},  false},
                                                                     {"reason",  decision.reason,      false}
                        });
                        return ComposeResult{std::nullopt, ComposeFailure::rejected};
                    }
                }
                if (auto const authoriser_member = database::find_current_state_event_id(
                        runtime.database.persistent_store, room_id, "m.room.member", authorising_user);
                    authoriser_member.has_value() &&
                    std::ranges::find(auth_events, *authoriser_member) == auth_events.end())
                {
                    auth_events.push_back(*authoriser_member);
                }
            }
            auto const invite_token = third_party_invite_token(canonicaljson::Value{*input});
            if (!invite_token.empty())
            {
                if (auto const invite_event = database::find_current_state_event_id(
                        runtime.database.persistent_store, room_id, "m.room.third_party_invite", invite_token);
                    invite_event.has_value() && std::ranges::find(auth_events, *invite_event) == auth_events.end())
                {
                    auth_events.push_back(*invite_event);
                }
            }
        }
        auto const depth = depth_after_prev_events(runtime.database.persistent_store, prev_events);
        auto const now_ms = origin_server_ts.value_or(event_clock_now_ms(runtime));
        auto event = canonicaljson::Object{};
        event.push_back(canonicaljson::make_member("type", canonicaljson::Value{event_type}));
        if (!omit_room_id)
        {
            event.push_back(canonicaljson::make_member("room_id", canonicaljson::Value{std::string{room_id}}));
        }
        event.push_back(canonicaljson::make_member("sender", canonicaljson::Value{std::string{sender}}));
        event.push_back(canonicaljson::make_member("origin_server_ts", canonicaljson::Value{now_ms}));
        event.push_back(canonicaljson::make_member("depth", canonicaljson::Value{static_cast<std::int64_t>(depth)}));
        event.push_back(canonicaljson::make_member("prev_events", string_array(prev_events)));
        event.push_back(canonicaljson::make_member("auth_events", string_array(auth_events)));
        auto event_content = copy_member_or_empty_object(*input, "content");
        if (auto const* content_object = std::get_if<canonicaljson::Object>(&event_content.storage());
            drop_join_authoriser && content_object != nullptr)
        {
            auto kept = canonicaljson::Object{};
            for (auto const& member : *content_object)
            {
                if (member.key != "join_authorised_via_users_server")
                {
                    kept.push_back(member);
                }
            }
            event_content = canonicaljson::Value{std::move(kept)};
        }
        // Spec (Client-Server API, PUT /send): "In rooms with a version older than 11 they MUST move
        // the `redacts` property inside the `content` to the top level of the event." From room
        // version 11 it stays in `content` (rooms/v11.md).
        auto redacts_for_top_level = std::optional<std::string>{};
        if (event_type == "m.room.redaction" && policy->redaction_rules != rooms::RedactionRules::room_v11_plus)
        {
            if (auto const* content_object = std::get_if<canonicaljson::Object>(&event_content.storage());
                content_object != nullptr)
            {
                auto remaining = canonicaljson::Object{};
                for (auto const& member : *content_object)
                {
                    if (member.key != "redacts")
                    {
                        remaining.push_back(member);
                    }
                    else if (auto const* redacts = std::get_if<std::string>(&member.value->storage());
                             redacts != nullptr)
                    {
                        redacts_for_top_level = *redacts;
                    }
                }
                event_content = canonicaljson::Value{std::move(remaining)};
            }
        }
        event.push_back(canonicaljson::make_member("content", std::move(event_content)));
        if (redacts_for_top_level.has_value())
        {
            event.push_back(canonicaljson::make_member("redacts", canonicaljson::Value{*redacts_for_top_level}));
        }
        auto state_key = std::optional<std::string>{};
        if (event_state_key.has_value())
        {
            state_key = event_state_key;
            event.push_back(canonicaljson::make_member("state_key", canonicaljson::Value{*event_state_key}));
        }

        auto unsigned_event = canonicaljson::Value{event};
        auto const content_hash = events::make_content_hash(unsigned_event);
        if (!content_hash.error.empty())
        {
            log_diagnostic("event.compose.rejected", {
                                                         {"room_id",    std::string{room_id}, false},
                                                         {"sender",     std::string{sender},  false},
                                                         {"event_type", event_type,           false},
                                                         {"reason",     content_hash.error,   false}
            });
            return ComposeResult{std::nullopt, ComposeFailure::rejected};
        }
        auto hashes = canonicaljson::Object{};
        hashes.push_back(canonicaljson::make_member("sha256", canonicaljson::Value{content_hash.sha256}));
        event.push_back(canonicaljson::make_member("hashes", canonicaljson::Value{std::move(hashes)}));
        auto hash_event = canonicaljson::Value{event};
        auto const event_id = events::make_reference_hash_event_id(hash_event, *policy);
        if (!event_id.error.empty())
        {
            log_diagnostic("event.compose.rejected", {
                                                         {"room_id",    std::string{room_id}, false},
                                                         {"sender",     std::string{sender},  false},
                                                         {"event_type", event_type,           false},
                                                         {"reason",     event_id.error,       false}
            });
            return ComposeResult{std::nullopt, ComposeFailure::rejected};
        }

        auto key = find_active_server_signing_key(runtime);
        if (!key.has_value() || runtime.crypto_provider == nullptr)
        {
            log_diagnostic("event.compose.rejected", {
                                                         {"room_id",    std::string{room_id},             false},
                                                         {"sender",     std::string{sender},              false},
                                                         {"event_type", event_type,                       false},
                                                         {"reason",     "server signing key unavailable", false}
            });
            return ComposeResult{std::nullopt, ComposeFailure::rejected};
        }
        auto key_store = RuntimeSigningKeyStore{runtime.config.server().server_name, *key};
        auto const signed_event = events::sign_event_for_server(
            hash_event, *policy, key_store, *runtime.crypto_provider, runtime.config.server().server_name);
        if (!signed_event.error.empty())
        {
            log_diagnostic("event.compose.rejected", {
                                                         {"room_id",    std::string{room_id}, false},
                                                         {"sender",     std::string{sender},  false},
                                                         {"event_type", event_type,           false},
                                                         {"reason",     signed_event.error,   false}
            });
            return ComposeResult{std::nullopt, ComposeFailure::rejected};
        }
        // CSAZ-9. Spec v1.19 "Size limits": "The complete event MUST NOT be larger than 65536
        // bytes, when formatted with the federation event format, including any signatures, and
        // encoded as Canonical JSON." That is exactly signed_event.event_json, so a request body
        // under the limit is still refused when the envelope, hashes and signature push it over.
        if (signed_event.event_json.size() > events::max_event_size_bytes)
        {
            log_diagnostic("event.compose.too_large",
                           {
                               {"room_id",     std::string{room_id},                           false},
                               {"sender",      std::string{sender},                            false},
                               {"event_type",  event_type,                                     false},
                               {"event_bytes", std::to_string(signed_event.event_json.size()), false}
            });
            return ComposeResult{std::nullopt, ComposeFailure::too_large};
        }
        // Authorization is fail-closed: every path out of this block that is not an
        // explicit "allowed" returns nullopt. Before 0.12.4 the check sat inside
        // three nested guards with no else branch, so a parse failure, an
        // unrecognised room version, or a room whose m.room.create was missing from
        // local state all fell straight through to composing the event with no
        // authorization at all (#487). The denial for a missing create event
        // already existed inside authorize_event_against_auth_events as rule 2 —
        // it was simply never reached.
        //
        // A room's own m.room.create event legitimately has no prior create in the
        // auth map; that case is not special-cased here because rule 1 handles it,
        // and short-circuiting it again is how the fail-open arose in the first
        // place.
        auto const reject = [&](std::string_view reason, std::string_view rule_hook = {},
                                std::string_view rule_step = {}) -> ComposeResult {
            log_diagnostic("event.auth.rejected", {
                                                      {"room_id",    std::string{room_id},   false},
                                                      {"sender",     std::string{sender},    false},
                                                      {"event_type", event_type,             false},
                                                      {"rule_hook",  std::string{rule_hook}, false},
                                                      {"rule_step",  std::string{rule_step}, false},
                                                      {"reason",     std::string{reason},    false}
            });
            return ComposeResult{std::nullopt, ComposeFailure::rejected};
        };

        auto signed_event_value = canonicaljson::parse_lossless(signed_event.event_json);
        if (signed_event_value.error != canonicaljson::ParseError::none)
        {
            return reject("signed event could not be parsed for authorization");
        }

        auto const* auth_policy = rooms::find_room_version_policy(room_version);
        if (auth_policy == nullptr)
        {
            return reject("unrecognised room version; cannot authorize event");
        }

        auto auth_map = build_auth_event_map(runtime.database.persistent_store, room_id, sender, state_key.value_or(""),
                                             event_type, signed_event_value.value);
        auto const auth_decision =
            events::authorize_event_against_auth_events(signed_event_value.value, *auth_policy, auth_map);
        if (!auth_decision.allowed)
        {
            return reject(auth_decision.reason, auth_decision.rule_hook, auth_decision.rule_step);
        }

        return ComposeResult{
            ComposedEvent{
                          event_id.event_id,
                          signed_event.event_json,
                          depth, 0U,
                          prev_events, auth_events,
                          {{signed_event.server_name, signed_event.key_id, signed_event.signature}},
                          event_type, state_key,
                          room_version, std::move(basis),
                          }
        };
    }

    // CSAZ-6 / DB-4: the one place a locally created m.room.member event becomes
    // the user's membership. persist_composed_event builds this for every such
    // event, whichever endpoint sent it: the membership APIs, PUT
    // /state/m.room.member, createRoom and join alike. Before CSAZ-6 only the
    // membership APIs updated the projections, so a ban sent through the state API
    // changed room state but left the user in `memberships` and
    // `LocalRoom.members`, which the read gates and join_room trust. Before DB-4
    // the row was written in a transaction of its own after the event's, so a
    // fault between the two left a durable ban with a row still saying join.
    // The projection is now committed in the event's own transaction. Callers
    // must not repeat any of this.
    [[nodiscard]] auto local_membership_projection(HomeserverRuntime& runtime, std::string_view room_id,
                                                   std::string_view sender, ComposedEvent const& composed)
        -> std::optional<database::MembershipProjection>
    {
        auto const parsed = canonicaljson::parse_lossless(composed.json);
        auto const membership = events::extract_content_membership(parsed.value);
        if (parsed.error != canonicaljson::ParseError::none || membership.empty())
        {
            return std::nullopt;
        }
        auto const& target = *composed.state_key;
        auto projection = database::MembershipProjection{target, std::string{membership},
                                                         allocate_stream_ordering(runtime.database), std::nullopt};
        if (projection.membership == "invite")
        {
            projection.invite = database::PersistentInvite{
                std::string{room_id},
                target,
                std::string{sender},
                composed.event_id,
                composed.json,
                invite_state_events_for_room(runtime.database.persistent_store, room_id, target, composed.json),
                projection.stream_ordering};
        }
        return projection;
    }

    // The runtime half of a stored member event: the live roster and the device
    // list changes. The durable row was committed with the event. If state
    // resolution did not leave the event current (a fork with more forward
    // extremities than one event may cite), the event is not the user's
    // membership: the row is put back to whatever is current, and that is what
    // the roster follows.
    [[nodiscard]] auto finish_local_membership(HomeserverRuntime& runtime, std::string_view room_id,
                                               ComposedEvent const& composed, std::string membership) -> bool
    {
        auto& store = runtime.database.persistent_store;
        auto const& target = *composed.state_key;
        auto const current = membership_state_entry(store, room_id, target);
        if (current.has_value() && current->event_id != composed.event_id)
        {
            auto const current_json = event_json_for_id(store, current->event_id);
            if (!current_json.has_value())
            {
                return false;
            }
            auto const parsed = canonicaljson::parse_lossless(*current_json);
            membership = std::string{events::extract_content_membership(parsed.value)};
            if (parsed.error != canonicaljson::ParseError::none || membership.empty() ||
                !database::store_membership_projection(
                    store, room_id, {target, membership, allocate_stream_ordering(runtime.database), std::nullopt}))
            {
                return false;
            }
        }

        return apply_membership_to_roster(runtime, room_id, target, membership);
    }

    // Composes, signs, and persists a single room state event.  Used by create_room to
    // emit the initial chain (create → member → power_levels → join_rules) so the room's
    // current_state is populated before any federation peer calls send_join.
    // Each event must be stored before the next is generated: auth_events_for_room and
    // basis_for_new_event both read the persistent state to build the correct chain.
    // Persists an already-composed event (and its state row, if any) under room_id.
    // Split out from emit_initial_state_event so create_room can compose the room v12
    // m.room.create event first — deriving the room ID from its reference hash
    // (MSC4291) — and persist it once that room ID is known.
    [[nodiscard]] auto persist_composed_event(HomeserverRuntime& runtime, std::string_view room_id,
                                              std::string_view sender, ComposedEvent const& composed) -> PersistOutcome
    {
        // ADR-0064 phase B1: every locally created event goes through the
        // store_local_event choke point, never database::store_event_with_state
        // directly (see tests/unit/test_store_event_choke_point.cpp).
        auto const failed = [&room_id, &composed](std::string_view reason) {
            log_diagnostic("event.persist.failed",
                           {
                               {"room_id",  std::string{room_id}, false},
                               {"event_id", composed.event_id,    false},
                               {"reason",   std::string{reason},  false}
            },
                           observability::LogEventSeverity::warning);
            return PersistOutcome::not_stored;
        };
        auto const* policy = rooms::find_room_version_policy(composed.room_version);
        if (policy == nullptr)
        {
            return failed("room version policy missing");
        }
        auto const stream_ordering = allocate_stream_ordering(runtime.database);
        auto state = std::optional<database::PersistentStateEvent>{};
        if (composed.state_key.has_value())
        {
            state = database::PersistentStateEvent{std::string{room_id}, composed.event_type, *composed.state_key,
                                                   composed.event_id};
        }
        auto const is_member_event = composed.event_type == "m.room.member" && composed.state_key.has_value();
        auto membership = std::optional<database::MembershipProjection>{};
        if (is_member_event)
        {
            membership = local_membership_projection(runtime, room_id, sender, composed);
            if (!membership.has_value())
            {
                return failed("member event has no membership to project");
            }
        }
        auto committed_membership = membership.has_value() ? membership->membership : std::string{};
        auto event = database::PersistentEvent{};
        event.event_id = composed.event_id;
        event.room_id = std::string{room_id};
        event.sender_user_id = std::string{sender};
        event.json = composed.json;
        event.depth = composed.depth;
        event.stream_ordering = stream_ordering;
        event.prev_event_ids = composed.prev_event_ids;
        event.auth_event_ids = composed.auth_event_ids;
        event.signatures = composed.signatures;
        // store_local_event logs the step that failed.
        if (!store_local_event(
                runtime.database.persistent_store, *policy, std::move(event), std::move(state), composed.basis,
                state_resolution_limits(runtime.config.security().federation.state_resolution), std::move(membership)))
        {
            return PersistOutcome::not_stored;
        }
        // The event is durable from here. A bookkeeping failure is logged with the event ID (failed) but is not a
        // store failure: the caller still federates and announces the event (C13).
        if (is_member_event && !finish_local_membership(runtime, room_id, composed, std::move(committed_membership)))
        {
            std::ignore = failed("roster or device-list update after the member event failed");
            return PersistOutcome::stored_bookkeeping_failed;
        }
        return PersistOutcome::stored;
    }

    // CSAZ-9: true when createRoom content the client supplied cannot fit in an
    // event within the spec's size limits on its own. Checked before the room is
    // stored, so such a request creates nothing. Content that fits alone but not
    // once the envelope and signature are added is still caught by
    // compose_signed_event, after the room exists.
    [[nodiscard]] auto create_room_options_exceed_size_limits(CreateRoomOptions const& options) -> bool
    {
        auto const too_large = [](canonicaljson::Value const& value) {
            auto const serialized = serialize_canonical_string(value);
            return serialized.has_value() && serialized->size() > events::max_event_size_bytes;
        };
        if (options.name.size() > events::max_event_size_bytes || options.topic.size() > events::max_event_size_bytes ||
            too_large(canonicaljson::Value{options.creation_content}) ||
            too_large(canonicaljson::Value{options.power_level_content_override}))
        {
            return true;
        }
        return std::ranges::any_of(options.initial_state, [&too_large](canonicaljson::Value const& entry) {
            auto const* object = std::get_if<canonicaljson::Object>(&entry.storage());
            if (object == nullptr)
            {
                return false;
            }
            auto const* type = string_member(*object, "type");
            auto const* state_key = string_member(*object, "state_key");
            return too_large(entry) || (type != nullptr && type->size() > events::max_event_type_length_bytes) ||
                   (state_key != nullptr && state_key->size() > events::max_state_key_length_bytes);
        });
    }

    // The events one createRoom stored, queued for appservices when it ends, however it ends (the
    // create, membership, power level and join rule events a client sees in /sync are events like
    // any other and an interested appservice is owed them). They are queued at the end rather than
    // one by one because the room's alias, which an appservice's `aliases` namespace is matched
    // against, is recorded part way through; and on every exit because a createRoom that fails after
    // storing some events still leaves the room and those events behind.
    class CreatedEventQueue final
    {
    public:
        CreatedEventQueue(HomeserverRuntime& runtime, std::string_view room_id, std::string_view sender)
            : m_runtime{runtime}
            , m_room_id{room_id}
            , m_sender{sender}
        {
        }

        CreatedEventQueue(CreatedEventQueue const&) = delete;
        auto operator=(CreatedEventQueue const&) -> CreatedEventQueue& = delete;
        CreatedEventQueue(CreatedEventQueue&&) = delete;
        auto operator=(CreatedEventQueue&&) -> CreatedEventQueue& = delete;

        ~CreatedEventQueue()
        {
            try
            {
                // Recursive: createRoom holds runtime.mutex, and enqueue takes it itself.
                auto const* const room = find_room(m_runtime.database, m_room_id);
                if (room == nullptr)
                {
                    return;
                }
                for (auto const& event : m_events)
                {
                    enqueue_appservice_delivery(m_runtime, *room, event.event_id, event.stream_ordering, m_sender,
                                                event.member_event_target);
                }
            }
            catch (...)
            {
                LOG_WARNING("createRoom could not queue its events for appservices; room_id=" + m_room_id);
            }
        }

        auto add(ComposedEvent const& composed) -> void
        {
            m_events.push_back(
                {composed.event_id, composed.stream_ordering,
                 composed.event_type == "m.room.member" ? composed.state_key.value_or(std::string{}) : std::string{}});
        }

    private:
        struct Stored final
        {
            std::string event_id{};
            std::uint64_t stream_ordering{0U};
            std::string member_event_target{};
        };

        HomeserverRuntime& m_runtime;
        std::string m_room_id{};
        std::string m_sender{};
        std::vector<Stored> m_events{};
    };

    // Returns none once the event is stored. rejected also covers a persistence
    // failure; create_room only needs to tell too_large (400) from the rest (500).
    [[nodiscard]] auto emit_initial_state_event(HomeserverRuntime& runtime, std::string_view room_id,
                                                std::string_view sender, std::string const& event_json,
                                                CreatedEventQueue& created) -> ComposeFailure
    {
        auto const composition = compose_signed_event(runtime, room_id, sender, event_json);
        if (!composition.event.has_value())
        {
            // compose_signed_event already emitted a diagnostic.
            return composition.failure;
        }
        if (persist_composed_event(runtime, room_id, sender, *composition.event) == PersistOutcome::not_stored)
        {
            return ComposeFailure::rejected;
        }
        created.add(*composition.event);
        return ComposeFailure::none;
    }

    // Upserts m.direct global account data for `user_id` to record that
    // `room_id` is a direct message room with each invitee. Reads the existing
    // m.direct mapping (if any), appends room_id under each invitee key without
    // duplicating, and persists the result. Called when create_room is invoked
    // with is_direct:true so that a second device can classify the room via
    // sliding sync without relying on the first client to PUT m.direct itself.
    [[nodiscard]] auto upsert_m_direct(HomeserverRuntime& runtime, std::string_view user_id, std::string_view room_id,
                                       std::vector<std::string> const& invitees) -> bool
    {
        if (invitees.empty())
        {
            return true;
        }

        auto mapping = canonicaljson::Object{};
        auto const existing = database::find_account_data_content(runtime.database.persistent_store, user_id,
                                                                  std::string_view{}, "m.direct");
        if (existing.has_value())
        {
            // Client-owned account data may hold fractional numbers. The canonical parser
            // refused them, so the mapping started empty and the write below destroyed the
            // user's existing direct rooms.
            auto const parsed = canonicaljson::parse_json(*existing);
            if (parsed.error == canonicaljson::ParseError::none)
            {
                if (auto const* obj = std::get_if<canonicaljson::Object>(&parsed.value.storage()); obj != nullptr)
                {
                    mapping = *obj;
                }
            }
        }

        for (auto const& invitee : invitees)
        {
            auto const member_it = std::ranges::find_if(mapping, [&invitee](canonicaljson::ObjectMember const& m) {
                return m.key == invitee;
            });
            if (member_it == mapping.end())
            {
                auto arr = canonicaljson::Array{};
                arr.push_back(canonicaljson::Value{std::string{room_id}});
                mapping.push_back(canonicaljson::make_member(invitee, canonicaljson::Value{std::move(arr)}));
            }
            else
            {
                auto const* existing_arr = std::get_if<canonicaljson::Array>(&member_it->value->storage());
                if (existing_arr == nullptr)
                {
                    // Key exists but is not an array; replace it.
                    auto new_arr = canonicaljson::Array{};
                    new_arr.push_back(canonicaljson::Value{std::string{room_id}});
                    member_it->value = std::make_unique<canonicaljson::Value>(std::move(new_arr));
                }
                else
                {
                    auto const already = std::ranges::any_of(*existing_arr, [room_id](canonicaljson::Value const& v) {
                        auto const* s = std::get_if<std::string>(&v.storage());
                        return s != nullptr && *s == room_id;
                    });
                    if (!already)
                    {
                        auto new_arr = *existing_arr;
                        new_arr.push_back(canonicaljson::Value{std::string{room_id}});
                        member_it->value = std::make_unique<canonicaljson::Value>(std::move(new_arr));
                    }
                }
            }
        }

        auto const serialized = canonicaljson::serialize_canonical(canonicaljson::Value{std::move(mapping)});
        if (serialized.error != canonicaljson::CanonicalJsonError::none)
        {
            return false;
        }
        return database::store_account_data(runtime.database.persistent_store,
                                            {std::string{user_id}, {}, "m.direct", serialized.output, 0U});
    }

    // ADR-0362: holds a room ID a createRoom has chosen from the moment it chooses it until the request ends,
    // whatever the outcome. The policy-server hook between choosing and storing releases runtime.mutex, so
    // without this another creation could choose the same ID. The set it lives in is guarded by runtime.mutex.
    class RoomIdReservation final
    {
    public:
        explicit RoomIdReservation(HomeserverRuntime& runtime)
            : runtime_{runtime}
        {
        }

        // Reserves `room_id`, once; the caller holds runtime.mutex and has checked that it is free.
        auto hold(std::string room_id) -> void
        {
            runtime_.rooms_being_created.insert(room_id);
            room_id_ = std::move(room_id);
        }

        ~RoomIdReservation()
        {
            if (!room_id_.has_value())
            {
                return;
            }
            auto const guard = RuntimeLock{runtime_.mutex};
            runtime_.rooms_being_created.erase(*room_id_);
        }

        RoomIdReservation(RoomIdReservation const&) = delete;
        auto operator=(RoomIdReservation const&) -> RoomIdReservation& = delete;
        RoomIdReservation(RoomIdReservation&&) = delete;
        auto operator=(RoomIdReservation&&) -> RoomIdReservation& = delete;

    private:
        HomeserverRuntime& runtime_;
        std::optional<std::string> room_id_{};
    };

} // namespace

auto federate_accepted_membership_event(HomeserverRuntime& runtime, std::string_view room_id, std::string_view event_id,
                                        std::string const& event_json, std::string_view requesting_server) -> void
{
    // The room's joined members are those of the in-memory roster, which the caller has
    // already brought up to date for this event. A room with no roster entry has none.
    auto const room = find_room(runtime.database, room_id);
    if (room == nullptr)
    {
        return;
    }
    queue_event_to_room_servers(runtime, room_id, room->members, event_id, event_json, {}, requesting_server);
}

auto sync_audience_of_room(database::PersistentStore const& store, std::string_view room_id,
                           std::initializer_list<std::string_view> also) -> std::vector<std::string>
{
    auto audience = std::vector<std::string>{};
    auto seen = std::unordered_set<std::string>{};
    auto const add = [&](std::string_view user) {
        if (!user.empty() && seen.emplace(user).second)
        {
            audience.emplace_back(user);
        }
    };
    // The room's own rows (ADR-0437), not every room's.
    database::for_each_room_membership_row(store, room_id, [&add](database::PersistentMembership const& membership) {
        if (membership.membership == "join" || membership.membership == "invite")
        {
            add(membership.user_id);
        }
    });
    for (auto const user : also)
    {
        add(user);
    }
    return audience;
}

// The one place a membership change reaches the live roster and the device lists. The roster is always
// updated, since the member event is already stored; a device-list write that fails is reported through
// the result, not by leaving the roster behind the store.
auto apply_membership_to_roster(HomeserverRuntime& runtime, std::string_view room_id, std::string_view user_id,
                                std::string_view membership) -> bool
{
    auto const* room = find_room(runtime.database, room_id);
    auto const was_joined = room != nullptr && room_has_member(*room, user_id);
    // Device lists (spec v1.19 "Tracking the device list for a user"): leaving the room's joined set
    // is recorded while the user is still in it, joining once they are, matching what each helper
    // reads.
    auto recorded = true;
    if (was_joined && membership != "join")
    {
        recorded = record_room_share_ended_device_changes(runtime, room_id, user_id);
    }
    apply_runtime_membership(runtime.database, room_id, user_id, membership);
    if (!was_joined && membership == "join")
    {
        recorded = record_room_share_started_device_changes(runtime, room_id, user_id) && recorded;
    }
    return recorded;
}

// Perform a single synchronous outbound federation call. Returns the raw
// response body on success (HTTP 2xx), or an error description on failure.
// The request is signed in-process. An answer main checks by signature
// (OutboundAnswerTrust::signature_verified) may run in the federation worker's
// thread pool when a proxy is wired; every other answer runs on main's own
// OutboundClient (F-43, ADR-0349).
[[nodiscard]] auto perform_sync_outbound_call(HomeserverRuntime& runtime, OutboundAnswerTrust trust,
                                              std::string_view room_id,
                                              federation::OutboundTransaction const& transaction,
                                              std::string_view key_id, core::SecretBuffer secret_key,
                                              std::string_view diagnostic_event, std::uint32_t timeout_seconds,
                                              std::uint64_t max_response_bytes) -> std::pair<bool, std::string>
{
    auto result = perform_outbound_call(runtime, trust, room_id, transaction, key_id, std::move(secret_key),
                                        diagnostic_event, timeout_seconds, max_response_bytes, std::nullopt);
    return {result.ok, std::move(result.body)};
}

[[nodiscard]] auto perform_bounded_outbound_call_with_status(HomeserverRuntime& runtime, OutboundAnswerTrust trust,
                                                             std::string_view room_id,
                                                             federation::OutboundTransaction const& transaction,
                                                             std::string_view key_id, core::SecretBuffer secret_key,
                                                             std::string_view diagnostic_event,
                                                             std::uint32_t deadline_seconds) -> OutboundCallResult
{
    auto const bounded = std::optional<BoundedOutboundLimits>{
        BoundedOutboundLimits{OutboundDeadline{deadline_seconds},
                              std::chrono::seconds{runtime.client_outbound_proxy_policy.worker_margin_seconds}}
    };
    return perform_outbound_call(runtime, trust, room_id, transaction, key_id, std::move(secret_key), diagnostic_event,
                                 deadline_seconds, 0U, bounded);
}

[[nodiscard]] auto perform_bounded_outbound_call(HomeserverRuntime& runtime, OutboundAnswerTrust trust,
                                                 std::string_view room_id,
                                                 federation::OutboundTransaction const& transaction,
                                                 std::string_view key_id, core::SecretBuffer secret_key,
                                                 std::string_view diagnostic_event, std::uint32_t deadline_seconds)
    -> std::pair<bool, std::string>
{
    auto result = perform_bounded_outbound_call_with_status(runtime, trust, room_id, transaction, key_id,
                                                            std::move(secret_key), diagnostic_event, deadline_seconds);
    return {result.ok, std::move(result.body)};
}

namespace
{

    // "M_INVITE_BLOCKED" when a remote error body's `errcode` is exactly that, else empty (SS7). The body is a
    // remote server's, so nothing else of it is kept.
    [[nodiscard]] auto remote_invite_blocked_errcode(std::string_view body) -> std::string
    {
        auto const parsed = canonicaljson::parse_lossless(body);
        auto const* root = parsed.error == canonicaljson::ParseError::none
                               ? std::get_if<canonicaljson::Object>(&parsed.value.storage())
                               : nullptr;
        auto const* errcode = root == nullptr ? nullptr : string_member(*root, "errcode");
        return errcode != nullptr && *errcode == invite_blocked_errcode ? std::string{invite_blocked_errcode}
                                                                        : std::string{};
    }

    // A make_join, make_leave or make_knock answer is one event plus `room_version`, so four times the 64 KiB event
    // limit is ample headroom; the 16 MiB outbound default is not (F-13).
    inline constexpr auto membership_template_max_response_bytes = std::uint64_t{4U * events::max_event_size_bytes};
    // A send_knock answer holds a stripped state of at most `federation::max_invite_room_state_entries` PDUs, as the
    // invite that comes the other way does, and is bounded as that invite's body is (ADR-0620).
    inline constexpr auto knock_answer_max_response_bytes = std::uint64_t{http::RequestLimits{}.max_body_bytes};

    // What may be kept of a resident's `knock_room_state`, before any signature is checked (ADR-0620): only the
    // entries /sync could show the user (the summary types and their own membership), each within the event size
    // limit, and no list longer than an invite's may be. Spec (Server-Server API, PUT /send_knock): "Entries which are
    // improperly signed or formatted SHOULD be removed". A list over the count, or one of a room version whose list
    // must hold the create event without it, is dropped whole: the knock stands, as it does with no list at all.
    [[nodiscard]] auto bounded_knock_room_state(canonicaljson::Array const& entries, std::string_view user_id,
                                                rooms::RoomVersionPolicy const& policy) -> canonicaljson::Array
    {
        auto kept = canonicaljson::Array{};
        // The position in `kept` of each (type, state_key) already there: a later entry for the same state replaces
        // it, as the later state event would, so a record holds one entry per state however many were sent (C31).
        auto position_of = std::map<std::pair<std::string, std::string>, std::size_t>{};
        auto considered = std::size_t{0U};
        auto create_seen = false;
        for (auto const& entry : entries)
        {
            auto const* event = std::get_if<canonicaljson::Object>(&entry.storage());
            auto const* type = event == nullptr ? nullptr : string_member(*event, "type");
            auto const* state_key = event == nullptr ? nullptr : string_member(*event, "state_key");
            if (type == nullptr || state_key == nullptr)
            {
                continue;
            }
            auto const is_summary =
                state_key->empty() && (*type == "m.room.create" || *type == "m.room.name" || *type == "m.room.avatar" ||
                                       *type == "m.room.topic" || *type == "m.room.join_rules" ||
                                       *type == "m.room.canonical_alias" || *type == "m.room.encryption");
            if (!is_summary && !(*type == "m.room.member" && *state_key == user_id))
            {
                continue;
            }
            auto const serialized = canonicaljson::serialize_canonical(entry);
            if (serialized.error != canonicaljson::CanonicalJsonError::none ||
                serialized.output.size() > events::max_event_size_bytes)
            {
                continue;
            }
            create_seen = create_seen || *type == "m.room.create";
            ++considered;
            auto const [slot, inserted] = position_of.try_emplace({*type, *state_key}, kept.size());
            if (inserted)
            {
                kept.push_back(entry);
            }
            else
            {
                kept[slot->second] = entry;
            }
        }
        if (considered > federation::max_invite_room_state_entries || (policy.create_event_is_room_id && !create_seen))
        {
            log_diagnostic("room.knock.state_list_dropped",
                           {
                               {"entries", std::to_string(considered),                         false},
                               {"reason",  "over the entry limit or missing the create event", false}
            },
                           observability::LogEventSeverity::warning);
            return {};
        }
        return kept;
    }

    // Why a resident's template, completed as this server will hash, sign and store it, is outside the room version's
    // event format (size, `prev_events`, `auth_events`, `depth`); empty when it is within it.
    // `claim_membership_event_template` has already dropped `event_id` and `unsigned`, and `hashes` and `signatures`
    // are not yet there (F-13).
    [[nodiscard]] auto membership_template_format_refusal(canonicaljson::Object const& completed_event,
                                                          rooms::RoomVersionPolicy const& policy) -> std::string
    {
        return federation::pdu_format_violation(canonicaljson::Value{completed_event}, policy);
    }

} // namespace

[[nodiscard]] auto perform_outbound_call(HomeserverRuntime& runtime, OutboundAnswerTrust trust,
                                         std::string_view room_id, federation::OutboundTransaction const& transaction,
                                         std::string_view key_id, core::SecretBuffer secret_key,
                                         std::string_view diagnostic_event, std::uint32_t timeout_seconds,
                                         std::uint64_t max_response_bytes,
                                         std::optional<BoundedOutboundLimits> const& bounded) -> OutboundCallResult
{
    if (bounded.has_value() && bounded->deadline.expired())
    {
        log_diagnostic(diagnostic_event, {
                                             {"reason", "deadline exceeded", false}
        });
        return {false, "deadline exceeded"};
    }
    // ADR-0391: every signed call this process makes goes through here, so a server the operator excludes is
    // not called, by a join, a query or a proxied worker call. The caller answers as for any server that failed.
    if (auto policy = federation::federation_server_policy(runtime.federation.config, transaction.destination);
        !policy.allowed)
    {
        log_diagnostic(diagnostic_event,
                       {
                           {"destination", transaction.destination, false},
                           {"reason",      policy.reason,           false}
        });
        return {false, std::move(policy.reason)};
    }
    // Test-only: bypass discover_server() entirely when the destination has a
    // forced resolution wired (see TestOnlyForcedOutboundResolution in
    // HomeserverRuntime.hpp). Always empty in production, so this branch never executes
    // outside tests/integration/test_join_room_flow.cpp.
    auto const forced_it = runtime.test_forced_outbound_resolution.find(std::string{transaction.destination});
    auto const forced = forced_it != runtime.test_forced_outbound_resolution.end();
    auto resolved_host = std::string{};
    // M-02: the name the certificate must match, which differs from
    // resolved_host on SRV-discovered destinations.
    auto tls_server_name = std::string{};
    auto resolved_port = std::uint16_t{8448U};
    auto pinned_addresses = std::vector<std::string>{};
    auto trusted_ca_pem = std::string{};
    if (forced)
    {
        resolved_host = forced_it->second.resolved_host;
        resolved_port = forced_it->second.resolved_port;
        pinned_addresses = forced_it->second.pinned_addresses;
        trusted_ca_pem = forced_it->second.trusted_ca_pem;
    }
    else
    {
        auto* discovery_network = runtime.discovery_network.get();
        if (discovery_network == nullptr)
        {
            log_diagnostic(diagnostic_event, {
                                                 {"reason", "federation infrastructure not available", false}
            });
            return {false, "federation not available"};
        }
        // Discovery is a DNS/well-known cascade that can burn the full timeout
        // against an unreachable peer, so it must not run under runtime.mutex.
        //
        // A join makes two calls (make_join, send_join), each of which used to
        // run the whole cascade again. A fresh success is reused for the cache's
        // lifetime (server-server-api.md, "Resolving server names": responses
        // "should be cached"); a remembered failure is not served, so a retry
        // after the peer recovers is not refused. The cache is used only while it
        // wraps this runtime's current discovery network.
        auto* const cached = runtime.cached_discovery.get();
        auto const use_cache = cached != nullptr && &cached->upstream() == discovery_network;
        auto const resolution = [&]() {
            auto const unlocked = RuntimeLockRelease{};
            if (use_cache)
            {
                return cached->discover(transaction.destination, timeout_seconds,
                                        federation::DiscoveryCachePolicy::successes_only);
            }
            return federation::discover_server(transaction.destination, *discovery_network, timeout_seconds);
        }();
        if (!resolution.discovery_allowed)
        {
            log_diagnostic(diagnostic_event, {
                                                 {"destination", transaction.destination,   false},
                                                 {"reason",      "server discovery failed", false}
            });
            return {false, "server discovery failed"};
        }
        resolved_host = resolution.resolved_host;
        tls_server_name = resolution.tls_server_name;
        resolved_port = resolution.resolved_port;
        pinned_addresses = resolution.pinned_addresses;
    }
    auto constexpr expected_secret_bytes = crypto::ed25519_secret_key_bytes;
    if (secret_key.bytes().size() != expected_secret_bytes)
    {
        log_diagnostic(diagnostic_event, {
                                             {"reason", "server signing key not initialized", false}
        });
        return {false, "server signing key not initialized"};
    }
    auto call = federation::OutboundCall{};
    call.transaction = transaction;
    call.resolved_host = resolved_host;
    call.tls_server_name = tls_server_name;
    call.resolved_port = resolved_port;
    call.pinned_addresses = pinned_addresses;
    call.trusted_ca_pem = trusted_ca_pem;
    call.key_id = std::string{key_id};
    // The OutboundCall owns the key as an mlocked SecretBuffer so nothing the
    // caller holds (runtime.mutex, a borrowed span, etc.) has to outlive the
    // network round-trip or an orphan future.
    call.secret_key = std::move(secret_key);
    // 0 means "not configured — use FederationCall defaults (connect=10s, total=60s)".
    // Overwriting with 0 would make the IPC wait only 10 s (0+10 buffer in WorkerPool),
    // so only apply the caller's budget when it is actually set.
    if (bounded.has_value())
    {
        // Discovery and everything before this point drew from the same
        // deadline; what is left is all this request may take.
        auto const remaining = bounded->deadline.remaining_seconds();
        if (remaining == 0U)
        {
            log_diagnostic(diagnostic_event, {
                                                 {"reason", "deadline exceeded", false}
            });
            return {false, "deadline exceeded"};
        }
        auto const total = std::min(timeout_seconds, remaining);
        call.connect_timeout_seconds = std::min(total, 30U);
        call.total_timeout_seconds = total;
    }
    else if (timeout_seconds > 0U)
    {
        call.connect_timeout_seconds = std::min(timeout_seconds, 30U);
        call.total_timeout_seconds = timeout_seconds;
    }
    // 0 means "use the OutboundCall default (16 MiB)"; only override when the
    // caller supplied a larger, endpoint-specific budget (e.g. send_join).
    if (max_response_bytes > 0U)
    {
        call.max_response_body_bytes = static_cast<std::size_t>(max_response_bytes);
    }

    // Sign the request in-process — the Ed25519 secret never crosses the IPC boundary.
    auto const request = federation::build_outbound_request(call);

    // Route by what main can check the answer against (F-43, ADR-0349). Only an answer main
    // verifies by signature may be carried by the federation worker; every other answer comes over
    // main's own pinned, TLS-verified client, so a compromised worker cannot make main believe what
    // only the remote server could say. The request is fully built and signed above, so nothing
    // inside this block reads runtime state that the lock protects — which is what makes it safe
    // to run with runtime.mutex released. `call.secret_key` owns the key, so the span used for
    // signing stays valid even if runtime.mutex is released.
    auto outcome = http::OutboundResult{};
    auto const via_worker = trust == OutboundAnswerTrust::signature_verified;
    if (via_worker && runtime.test_worker_outbound_route)
    {
        auto const unlocked = RuntimeLockRelease{};
        outcome = runtime.test_worker_outbound_route(request);
    }
    else if (via_worker && runtime.federation_proxy)
    {
        auto const unlocked = RuntimeLockRelease{};
        outcome = runtime.federation_proxy->send_outbound_request(
            request, room_id, bounded.has_value() ? bounded->worker_margin : default_worker_ipc_margin);
    }
    else if (runtime.outbound_client)
    {
        auto const unlocked = RuntimeLockRelease{};
        outcome = runtime.outbound_client->perform(request);
    }
    else
    {
        log_diagnostic(diagnostic_event, {
                                             {"reason", "federation infrastructure not available", false}
        });
        return {false, "federation not available"};
    }

    if (!outcome.ok || outcome.response.status < 200U || outcome.response.status >= 300U)
    {
        log_diagnostic(diagnostic_event,
                       {
                           {"destination", transaction.destination,                                         false},
                           {"http_status", std::to_string(outcome.response.status),                         false},
                           {"reason",      outcome.error_detail.empty() ? "non-2xx" : outcome.error_detail, false}
        },
                       observability::LogEventSeverity::warning);
        return {false,
                outcome.error_detail.empty() ? "remote server returned " + std::to_string(outcome.response.status)
                                             : outcome.error_detail,
                outcome.ok ? outcome.response.status : std::uint16_t{0U},
                outcome.ok ? remote_invite_blocked_errcode(outcome.response.body) : std::string{}};
    }
    return {true, outcome.response.body, outcome.response.status};
}

// How long a published signing key advertises itself as valid. Federation peers
// cap any advertised window at seven days (spec: server-server-api.md, "Publishing
// Keys"), so a longer window buys nothing, and a far-future sentinel would let a
// compromised key live in peer caches forever. The window is rolled forward while
// the key is in use — it bounds how long peers may cache the key, not how long the
// server keeps its identity.
constexpr auto signing_key_validity_ms = std::uint64_t{7U * 24U * 60U * 60U * 1000U};

// How long a published key document may be served from the lock-free cache before
// it is re-published. Well inside signing_key_validity_ms so the advertised
// valid_until_ts of a served document is always comfortably in the future.
constexpr auto key_server_cache_refresh_interval_ms = std::uint64_t{60U * 60U * 1000U};

// Guarantees the runtime signing provider can actually sign with `key_id`.
//
// Callers sign locally composed events with the key id returned by
// ensure_runtime_server_signing_key, but the provider is a separate object built
// from the active secrets. If the two drift apart, every signature attempt fails
// with "signing key not held" and the server can no longer originate any event,
// even though the key material itself is intact. Rebuilding the provider is cheap
// and only happens when the key it was built from is no longer the preferred one.
auto ensure_crypto_provider_holds_key(HomeserverRuntime& runtime, std::string_view key_id) -> void
{
    // The federation worker never signs (ADR-0078) and holds no local secrets to rebuild from.
    if (runtime.crypto_provider_overridden)
    {
        return;
    }
    auto const held = runtime.crypto_provider != nullptr &&
                      std::ranges::any_of(runtime.database.signing_secret_keys,
                                          [key_id](std::pair<std::string, core::SecretBuffer> const& entry) {
                                              return entry.first == key_id;
                                          });
    if (held)
    {
        return;
    }
    // A null provider is the first build during startup, not a drift between the
    // stored key and the provider — only the latter is worth an info line.
    auto const was_built = runtime.crypto_provider != nullptr;
    reset_runtime_crypto_provider(runtime);
    if (was_built)
    {
        log_diagnostic("signing_key.provider_rebuilt",
                       {
                           {"key_id",    std::string{key_id},                                   false},
                           {"available", runtime.crypto_provider != nullptr ? "true" : "false", false}
        },
                       observability::LogEventSeverity::info);
    }
}

[[nodiscard]] auto derive_ed25519_key_id(std::span<unsigned char const> public_key) -> std::string
{
    static constexpr auto hex_digits = std::string_view{"0123456789abcdef"};
    auto key_version = std::string{};
    key_version.reserve(8U);
    for (auto i = 0U; i < 4U; ++i)
    {
        key_version += hex_digits[(public_key[i] >> 4U) & 0x0fU];
        key_version += hex_digits[public_key[i] & 0x0fU];
    }
    return "ed25519:" + key_version;
}

// Decrypt a stored signing secret.  Returns nullopt if the value is encrypted
// but cannot be decrypted (wrong master key / corrupted).  For legacy plaintext
// rows, returns the decoded bytes directly.
[[nodiscard]] auto decrypt_stored_signing_secret(HomeserverRuntime const& runtime, std::string_view stored)
    -> std::optional<core::SecretBuffer>
{
    if (auto const ciphertext = decode_encrypted_secret_from_storage(stored); ciphertext.has_value())
    {
        // Cached against the master key file's identity (finding 3).
        auto const key = crypto::signing_secret_box_key(runtime.config.security().secrets.master_key_file);
        if (!key.has_value())
        {
            log_diagnostic("signing_key.decryption_failed",
                           {
                               {"reason",
                                "encrypted signing secret requires a readable, lockable "
                                "security.secrets.master_key_file", false}
            });
            return std::nullopt;
        }
        auto plaintext = crypto::secret_box_decrypt(*ciphertext, *key);
        if (!plaintext.has_value())
        {
            log_diagnostic("signing_key.decryption_failed",
                           {
                               {"reason", "master key does not decrypt stored signing secret", false}
            });
            return std::nullopt;
        }
        return plaintext;
    }

    // Legacy plaintext base64 secret: decode into locked memory so the secret is
    // protected from here on. Rows like this can no longer be *written* (finding
    // 1), but pre-0.12.5 servers have them and must keep federating; the
    // diagnostic tells operators to rotate.
    auto const decoded = events::matrix_bytes_from_base64(stored);
    if (decoded.empty())
    {
        return core::SecretBuffer{};
    }
    log_diagnostic("signing_key.legacy_plaintext",
                   {
                       {"reason", "signing secret is stored plaintext; rotate to enable at-rest encryption", false}
    });
    return core::SecretBuffer{
        std::span<std::uint8_t const>{reinterpret_cast<std::uint8_t const*>(decoded.data()), decoded.size()}
    };
}

[[nodiscard]] auto ensure_runtime_server_signing_key(HomeserverRuntime& runtime)
    -> std::optional<database::PersistentServerSigningKey>
{
    auto const& server_name = runtime.config.server().server_name;
    auto const all_keys = database::snapshot_server_signing_keys_of(runtime.database.persistent_store, server_name);

    auto const now_ms = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
            .count());

    // Select the newest usable signing key for this server, whether or not its
    // published window has lapsed. `valid_until_ts` tells federation peers when to
    // re-fetch the key list (spec: server-server-api.md#publishing-keys); it is not a
    // lease after which the server may adopt a different identity. A lapsed window is
    // republished below, never replaced: a key minted behind the running signing
    // provider cannot sign anything (the provider does not hold it), and no peer has
    // ever seen it, so both local sends and outbound federation break at once.
    //
    // The legacy "ed25519:auto" sentinel is still excluded. Notary servers (e.g.
    // matrix.org) cached it with a far-future valid_until_ts and will never re-fetch,
    // so it can only be retired by generating a key with an id they have not cached.
    //
    // Selecting the greatest valid_until_ts also picks the correct key after a
    // rotation: the retired key was stamped with "now" while the new key carries a
    // full window, so the new key wins and the retired one is left for old_verify_keys.
    auto it = all_keys.end();
    for (auto candidate = all_keys.begin(); candidate != all_keys.end(); ++candidate)
    {
        if (candidate->server_name != server_name || candidate->key_id == "ed25519:auto" ||
            candidate->secret_key.empty())
        {
            continue;
        }
        if (it == all_keys.end() || candidate->valid_until_ts > it->valid_until_ts)
        {
            it = candidate;
        }
    }

    if (it != all_keys.end())
    {
        // Copy the record before any store write: persisting a key can append to the
        // backing vector and invalidate `it`.
        auto record = *it;

        // Decrypt (or decode legacy plaintext) the stored secret and validate its
        // size before trusting it.  Fail closed if the secret cannot hydrate into a
        // full Ed25519 secret key — attempting to sign with wrong-length material
        // produces corrupt signatures.
        auto constexpr expected_secret_bytes = crypto::ed25519_secret_key_bytes;
        auto const raw_secret = decrypt_stored_signing_secret(runtime, record.secret_key);
        auto const raw_secret_size = raw_secret.has_value() ? raw_secret->bytes().size() : std::size_t{0U};
        if (raw_secret_size != expected_secret_bytes)
        {
            log_diagnostic("signing_key.rejected", {
                                                       {"server_name", std::string{server_name},              false},
                                                       {"key_id",      record.key_id,                         false},
                                                       {"reason",      "secret_size_invalid",                 false},
                                                       {"secret_size", std::to_string(raw_secret_size),       false},
                                                       {"expected",    std::to_string(expected_secret_bytes), false}
            });
            return std::nullopt;
        }

        // Roll the published window forward once the key is past the halfway point of
        // its advertised validity. Without this the window simply lapses on any server
        // whose uptime exceeds it, and every peer that re-fetches /_matrix/key/v2/server
        // sees a valid_until_ts in the past and rejects the server's signatures.
        if (record.valid_until_ts <= now_ms + signing_key_validity_ms / 2U)
        {
            auto const refreshed_valid_until_ts = now_ms + signing_key_validity_ms;
            // An empty secret preserves the stored one; only the window changes.
            auto refreshed = database::PersistentServerSigningKey{record.server_name, record.key_id, record.public_key,
                                                                  refreshed_valid_until_ts, std::string{}};
            if (database::store_server_signing_key(runtime.database.persistent_store, std::move(refreshed)))
            {
                record.valid_until_ts = refreshed_valid_until_ts;
                log_diagnostic("signing_key.window_refreshed",
                               {
                                   {"server_name",    std::string{server_name},                 false},
                                   {"key_id",         record.key_id,                            false},
                                   {"valid_until_ts", std::to_string(refreshed_valid_until_ts), false}
                },
                               observability::LogEventSeverity::info);
            }
            else
            {
                // Degrade rather than fail closed: the key itself is intact and still
                // signs. Peers just re-fetch sooner because the advertised window is
                // the stale one.
                log_diagnostic("signing_key.window_refresh_failed",
                               {
                                   {"server_name", std::string{server_name}, false},
                                   {"key_id",      record.key_id,            false},
                                   {"reason",      "persist_failed",         false}
                },
                               observability::LogEventSeverity::warning);
            }
        }

        runtime.database.signing_secret_key = core::SecretBuffer{raw_secret->bytes()};
        // Debug, not info: this runs on every request path that needs the signing
        // identity, so at info it drowns the log. The state-changing events
        // (window refreshed, key generated, provider rebuilt) are the info-level ones.
        log_diagnostic("signing_key.loaded", {
                                                 {"server_name", std::string{server_name},                   false},
                                                 {"key_id",      record.key_id,                              false},
                                                 {"public_key",  record.public_key,                          false},
                                                 {"secret_size", std::to_string(raw_secret->bytes().size()), false}
        });
        ensure_crypto_provider_holds_key(runtime, record.key_id);
        return record;
    }

    // This server has no usable signing key at all — first boot, or a store holding
    // only the legacy sentinel / secret-less records. Log what was there (for ops
    // visibility) then generate a fresh Ed25519 keypair with a derived key_id. This
    // is the ONLY path that mints a key outside an explicit rotation.
    auto const has_legacy =
        std::ranges::any_of(all_keys, [&server_name](database::PersistentServerSigningKey const& k) {
            return k.server_name == server_name && k.key_id == "ed25519:auto";
        });
    auto const stored_for_server =
        std::ranges::count_if(all_keys, [&server_name](database::PersistentServerSigningKey const& k) {
            return k.server_name == server_name;
        });
    log_diagnostic("signing_key.generating", {
                                                 {"server_name",    std::string{server_name},          false},
                                                 {"has_legacy_key", has_legacy ? "true" : "false",     false},
                                                 {"stored_keys",    std::to_string(stored_for_server), false}
    });

    auto const keypair = crypto::generate_ed25519_keypair();
    if (!keypair.has_value())
    {
        return std::nullopt;
    }

    // Derive the key_id from the public key material so each new key gets a unique
    // id; stale notary-cache entries for old ids become irrelevant after rotation.
    auto const key_id = derive_ed25519_key_id(keypair->public_key);

    // Encrypt the secret at rest. There is no plaintext fallback (0.12.5 audit,
    // finding 1): a server with no master key configured used to write the
    // Ed25519 seed as base64 with encrypted='false', so anyone who exfiltrated
    // the database obtained forgery-capable federation signing material. That is
    // the whole threat this column exists to defend against, so a missing or
    // unusable master key is now a hard failure at generation time rather than a
    // diagnostic. Rows written by earlier versions still decrypt through the
    // legacy branch of decrypt_stored_signing_secret, so existing servers keep
    // federating and can rotate on their own schedule.
    auto const secret_span = keypair->secret_key.bytes();
    auto const stored_secret = encrypt_signing_secret(runtime, secret_span);
    auto const encrypted = std::string{"true"};
    if (!stored_secret.has_value())
    {
        log_diagnostic("signing_key.generation_failed",
                       {
                           {"server_name", std::string{server_name},  false},
                           {"reason",
                            runtime.config.security().secrets.master_key_file.empty()
                                ? "security.secrets.master_key_file is not configured; refusing to store a "
                                  "server signing secret in plaintext"
                                : "signing secret encryption failed",
                            false                                          }
        });
        return std::nullopt;
    }

    auto key = database::PersistentServerSigningKey{
        std::string{server_name},
        key_id,
        events::matrix_base64_from_bytes(
            std::string_view{reinterpret_cast<char const*>(keypair->public_key.data()), keypair->public_key.size()}),
        now_ms + signing_key_validity_ms,
        *stored_secret,
    };
    log_diagnostic("signing_key.generated",
                   {
                       {"server_name", std::string{server_name}, false},
                       {"key_id",      key_id,                   false},
                       {"public_key",  key.public_key,           false},
                       {"encrypted",   encrypted,                false}
    },
                   observability::LogEventSeverity::info);
    if (!database::store_server_signing_key(runtime.database.persistent_store, key))
    {
        return std::nullopt;
    }
    runtime.database.signing_secret_key = core::SecretBuffer{keypair->secret_key.bytes()};
    ensure_crypto_provider_holds_key(runtime, key.key_id);
    return key;
}

// Collect every signing-key record this server may currently sign or publish
// with. The preferred key — the newest non-legacy record holding a secret, i.e.
// exactly the record ensure_runtime_server_signing_key returns — is always
// included: it is the server's identity, so it stays signable even when its
// published window has lapsed and could not be refreshed. Every other key is
// active only while its valid_until_ts is in the future, which is what retires a
// key stamped with "now" by rotate_server_signing_key. The returned vector is
// sorted by valid_until_ts descending so the preferred key is always front().
[[nodiscard]] auto collect_active_server_signing_keys(HomeserverRuntime const& runtime)
    -> std::vector<database::PersistentServerSigningKey>
{
    auto const& server_name = runtime.config.server().server_name;
    auto const all_keys = database::snapshot_server_signing_keys_of(runtime.database.persistent_store, server_name);

    auto const now_ms = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
            .count());

    // The preferred key is the newest usable record — the same selection
    // ensure_runtime_server_signing_key makes — and is always active.
    auto preferred_key_id = std::string{};
    auto preferred_valid_until_ts = std::uint64_t{0U};
    for (auto const& candidate : all_keys)
    {
        if (candidate.server_name != server_name || candidate.key_id == "ed25519:auto" ||
            candidate.secret_key.empty() || candidate.public_key.empty())
        {
            continue;
        }
        if (preferred_key_id.empty() || candidate.valid_until_ts > preferred_valid_until_ts)
        {
            preferred_key_id = candidate.key_id;
            preferred_valid_until_ts = candidate.valid_until_ts;
        }
    }

    auto active = std::vector<database::PersistentServerSigningKey>{};
    for (auto const& candidate : all_keys)
    {
        if (candidate.server_name != server_name || candidate.key_id == "ed25519:auto" ||
            candidate.secret_key.empty() || candidate.public_key.empty())
        {
            continue;
        }
        if (candidate.key_id != preferred_key_id && candidate.valid_until_ts <= now_ms)
        {
            continue;
        }
        active.push_back(candidate);
    }
    std::ranges::sort(active,
                      [](database::PersistentServerSigningKey const& a, database::PersistentServerSigningKey const& b) {
                          return a.valid_until_ts > b.valid_until_ts;
                      });
    return active;
}

// Load and decrypt every currently-active signing secret. The vector follows the
// same order as collect_active_server_signing_keys (preferred key first) so the
// multi-key provider and legacy single-secret callers agree on which key is
// active. Secrets that fail decryption or have the wrong size are skipped.
[[nodiscard]] auto active_server_signing_key_secrets(HomeserverRuntime& runtime)
    -> std::vector<ActiveServerSigningKeySecret>
{
    auto const active_records = collect_active_server_signing_keys(runtime);
    if (active_records.empty())
    {
        return {};
    }

    auto constexpr expected_secret_bytes = crypto::ed25519_secret_key_bytes;
    auto result = std::vector<ActiveServerSigningKeySecret>{};
    result.reserve(active_records.size());
    for (auto const& record : active_records)
    {
        auto raw_secret = decrypt_stored_signing_secret(runtime, record.secret_key);
        if (!raw_secret.has_value() || raw_secret->bytes().size() != expected_secret_bytes)
        {
            continue;
        }
        // Already locked and zeroise-on-destruction: move it, do not copy it
        // through an intermediate buffer.
        result.push_back(ActiveServerSigningKeySecret{record.key_id, std::move(*raw_secret)});
    }
    return result;
}

[[nodiscard]] auto find_active_server_signing_key(HomeserverRuntime const& runtime)
    -> std::optional<database::PersistentServerSigningKey>
{
    auto const& server_name = runtime.config.server().server_name;
    auto const all_keys = database::snapshot_server_signing_keys_of(runtime.database.persistent_store, server_name);

    // Select the usable non-legacy key with the greatest valid_until_ts, mirroring
    // the choice made by ensure_runtime_server_signing_key but without touching the
    // encrypted secret, so callers that sign through runtime.crypto_provider can obtain
    // the key_id and public_key they need without loading the secret themselves.
    auto it = all_keys.end();
    for (auto candidate = all_keys.begin(); candidate != all_keys.end(); ++candidate)
    {
        if (candidate->server_name != server_name || candidate->key_id == "ed25519:auto" ||
            candidate->secret_key.empty())
        {
            continue;
        }
        if (it == all_keys.end() || candidate->valid_until_ts > it->valid_until_ts)
        {
            it = candidate;
        }
    }
    return it == all_keys.end() ? std::nullopt : std::optional<database::PersistentServerSigningKey>{*it};
}

[[nodiscard]] auto publish_server_signing_keys(HomeserverRuntime& runtime) -> OperationResult
{
    auto preferred = ensure_runtime_server_signing_key(runtime);
    if (!preferred.has_value())
    {
        return make_operation_result(false, {}, "server signing key unavailable", 500U);
    }
    if (runtime.crypto_provider == nullptr)
    {
        return make_operation_result(false, {}, "server signing provider unavailable", 500U);
    }

    auto const now_ms = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
            .count());
    // Advertise exactly the window the server has persisted for its preferred key
    // (ensure_runtime_server_signing_key rolled it forward above if it was over
    // halfway through). Advertising a longer window than the server itself records
    // is what let peers cache a key the server had already stopped honouring.
    auto const published_valid_until_ts = preferred->valid_until_ts;

    // Advertise every currently-active key in verify_keys. Multiple active keys are
    // supported during rotation windows or when the operator has pre-staged keys.
    auto active_keys = collect_active_server_signing_keys(runtime);
    if (active_keys.empty())
    {
        return make_operation_result(false, {}, "no active server signing keys", 500U);
    }

    auto verify_keys = canonicaljson::Object{};
    for (auto const& active : active_keys)
    {
        auto verify_key = canonicaljson::Object{};
        verify_key.push_back(canonicaljson::make_member("key", canonicaljson::Value{active.public_key}));
        verify_keys.push_back(canonicaljson::make_member(active.key_id, canonicaljson::Value{std::move(verify_key)}));
    }

    // Build old_verify_keys from every stored signing key for this server that is not
    // currently active. Per the Matrix spec each entry is:
    //   "<key_id>": { "expired_ts": <ms>, "key": "<base64 public key>" }
    // expired_ts is capped at now_ms so that superseded keys with a far-future
    // valid_until_ts (e.g. the legacy year-2999 sentinel) are never published with
    // a future expiry, which would cause peers to treat them as still valid.
    auto active_ids = std::set<std::string>{};
    for (auto const& active : active_keys)
    {
        active_ids.insert(active.key_id);
    }

    auto old_verify_keys_obj = canonicaljson::Object{};
    for (auto const& old_key :
         database::snapshot_server_signing_keys_of(runtime.database.persistent_store, preferred->server_name))
    {
        if (old_key.server_name != preferred->server_name || active_ids.contains(old_key.key_id) ||
            old_key.public_key.empty())
        {
            continue;
        }
        auto const expired_ts = std::min(old_key.valid_until_ts, now_ms);
        auto old_entry = canonicaljson::Object{};
        old_entry.push_back(
            canonicaljson::make_member("expired_ts", canonicaljson::Value{static_cast<std::int64_t>(expired_ts)}));
        old_entry.push_back(canonicaljson::make_member("key", canonicaljson::Value{old_key.public_key}));
        old_verify_keys_obj.push_back(
            canonicaljson::make_member(old_key.key_id, canonicaljson::Value{std::move(old_entry)}));
    }

    auto response = canonicaljson::Object{};
    response.push_back(
        canonicaljson::make_member("old_verify_keys", canonicaljson::Value{std::move(old_verify_keys_obj)}));
    response.push_back(canonicaljson::make_member("server_name", canonicaljson::Value{preferred->server_name}));
    response.push_back(canonicaljson::make_member(
        "valid_until_ts", canonicaljson::Value{static_cast<std::int64_t>(published_valid_until_ts)}));
    response.push_back(canonicaljson::make_member("verify_keys", canonicaljson::Value{std::move(verify_keys)}));

    auto payload = canonicaljson::serialize_canonical(canonicaljson::Value{response});
    if (payload.error != canonicaljson::CanonicalJsonError::none)
    {
        return make_operation_result(false, {}, canonicaljson::canonical_json_error_name(payload.error), 500U);
    }

    auto const sign_result =
        runtime.crypto_provider->sign(crypto::Ed25519SecretKeyHandle{preferred->key_id}, payload.output);
    if (!sign_result.error.empty())
    {
        return make_operation_result(false, {}, "server key response signing failed: " + sign_result.error, 500U);
    }

    auto server_signatures = canonicaljson::Object{};
    server_signatures.push_back(canonicaljson::make_member(
        preferred->key_id, canonicaljson::Value{events::matrix_base64_from_bytes(sign_result.signature.bytes)}));
    auto signatures = canonicaljson::Object{};
    signatures.push_back(
        canonicaljson::make_member(preferred->server_name, canonicaljson::Value{std::move(server_signatures)}));
    response.push_back(canonicaljson::make_member("signatures", canonicaljson::Value{std::move(signatures)}));

    auto signed_response = canonicaljson::serialize_canonical(canonicaljson::Value{std::move(response)});
    if (signed_response.error != canonicaljson::CanonicalJsonError::none)
    {
        return make_operation_result(false, {}, canonicaljson::canonical_json_error_name(signed_response.error), 500U);
    }

    // Atomically update the lock-free cache so dispatch_local_http_request can
    // serve subsequent key server requests without acquiring the runtime mutex.
    // The cached document carries a valid_until_ts, so it is only servable for part
    // of that window: past the refresh deadline the fast path falls through here
    // again and re-publishes, instead of serving a document whose advertised window
    // has quietly elapsed on a long-running server.
    if (runtime.database.key_server_cache)
    {
        runtime.database.key_server_cache->store(signed_response.output, now_ms + key_server_cache_refresh_interval_ms);
    }

    return make_operation_result(true, std::move(signed_response.output));
}

[[nodiscard]] auto rotate_server_signing_key(HomeserverRuntime& runtime) -> OperationResult
{
    auto guard = RuntimeLock{runtime.mutex};

    // Ensure a current active key exists to retire (this also loads its secret into
    // the runtime). Without a current key there is nothing to rotate from.
    auto const current = ensure_runtime_server_signing_key(runtime);
    if (!current.has_value())
    {
        return make_operation_result(false, {}, "server signing key unavailable", 500U);
    }

    auto const now_ms = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
            .count());

    // Retire the current key by setting its valid_until_ts to "now" so the next
    // publish moves it into old_verify_keys. Passing an empty secret preserves the
    // stored secret (store_server_signing_key keeps the existing value on empty),
    // which keeps the retired public key available for verifying historical events.
    auto retired = database::PersistentServerSigningKey{current->server_name, current->key_id, current->public_key,
                                                        now_ms, std::string{}};
    if (!database::store_server_signing_key(runtime.database.persistent_store, std::move(retired)))
    {
        return make_operation_result(false, {}, "failed to retire current signing key", 500U);
    }

    // Generate the new active key with a derived key_id and a rolling 7-day expiry,
    // matching ensure_runtime_server_signing_key's first-generation behaviour.
    auto const keypair = crypto::generate_ed25519_keypair();
    if (!keypair.has_value())
    {
        return make_operation_result(false, {}, "signing key generation failed", 500U);
    }
    auto const key_id = derive_ed25519_key_id(keypair->public_key);

    // Rotation carries the same rule as generation (0.12.5 audit, finding 1,
    // which cited only the generation path): a rotated signing secret is never
    // written in plaintext. Rotating into an unencrypted row would have handed
    // a database-exfiltration attacker a fresh forgery-capable key on exactly
    // the operation an operator performs to recover from a suspected leak.
    auto const stored_secret = encrypt_signing_secret(runtime, keypair->secret_key.bytes());
    auto const encrypted = std::string{"true"};
    if (!stored_secret.has_value())
    {
        return make_operation_result(false, {},
                                     runtime.config.security().secrets.master_key_file.empty()
                                         ? "security.secrets.master_key_file is not configured; refusing to store a "
                                           "rotated signing secret in plaintext"
                                         : "failed to encrypt rotated signing secret",
                                     500U);
    }

    auto new_key = database::PersistentServerSigningKey{
        current->server_name,
        key_id,
        events::matrix_base64_from_bytes(
            std::string_view{reinterpret_cast<char const*>(keypair->public_key.data()), keypair->public_key.size()}),
        now_ms + signing_key_validity_ms,
        *stored_secret,
    };
    if (!database::store_server_signing_key(runtime.database.persistent_store, new_key))
    {
        return make_operation_result(false, {}, "failed to store rotated signing key", 500U);
    }
    runtime.database.signing_secret_key = core::SecretBuffer{keypair->secret_key.bytes()};
    reset_runtime_crypto_provider(runtime);

    // The dispatch worker snapshots the signing identity when it is constructed, and
    // wire_federation_callbacks returns early once the callbacks exist — so nothing
    // else hands it the new key. Without this it keeps signing outbound transactions
    // with the key this rotation just retired, which peers reject.
    if (runtime.dispatch_worker != nullptr)
    {
        runtime.dispatch_worker->update_signing_identity(
            key_id, core::SecretBuffer{runtime.database.signing_secret_key.bytes()});
        log_diagnostic("dispatch.signing_identity_refreshed",
                       {
                           {"key_id", key_id, false}
        },
                       observability::LogEventSeverity::info);
    }

    log_diagnostic("signing_key.rotated",
                   {
                       {"server_name",    current->server_name, false},
                       {"retired_key_id", current->key_id,      false},
                       {"new_key_id",     key_id,               false},
                       {"encrypted",      encrypted,            false}
    },
                   observability::LogEventSeverity::info);

    // Refresh the cached key-server response so federation peers immediately observe
    // the rotation on their next GET /_matrix/key/v2/server.
    auto const published = publish_server_signing_keys(runtime);
    if (!published.ok)
    {
        return published;
    }
    return make_operation_result(true, key_id);
}

[[nodiscard]] auto create_room(HomeserverRuntime& runtime, std::string_view access_token) -> OperationResult
{
    return create_room(runtime, access_token, CreateRoomOptions{});
}

[[nodiscard]] auto create_room(HomeserverRuntime& runtime, std::string_view access_token,
                               CreateRoomOptions const& options) -> OperationResult
{
    auto guard = RuntimeLock{runtime.mutex};
    // create_room is called both standalone (this lock is the only one taken:
    // LocalSmokeFlow.cpp) and from within a request handler that already
    // holds runtime.mutex (ClientServerRuntime.cpp, LocalHttpRouter.cpp) — those
    // two callers release their own outer guard first (see the unlock/call/
    // relock at each call site) so this is never a *nested* acquisition of
    // the same recursive mutex. Publishing it here, exactly like the other
    // three request-lock-scope entry points, is what lets
    // resolve_policy_server_hook's RuntimeLockRelease actually find and release
    // *this* guard — the one genuinely protecting the rest of this function —
    // during the policy-server round trip. Before this, a caller-held outer
    // guard being double-locked here (a recursive mutex permits it, silently)
    // meant RuntimeLockRelease released only the outer level while this guard
    // kept the mutex held, so the network call still ran under an
    // effectively-locked mutex: see the room-creation regression scenario in
    // tests/integration/test_request_lock_contention_flow.cpp.
    auto const lock_scope = RequestLockScope{guard};
    log_diagnostic("room.create.started", {
                                              {"has_access_token", access_token.empty() ? "false" : "true", false}
    });
    auto const user_id = authenticated_user(runtime, access_token);
    if (!user_id.has_value())
    {
        log_diagnostic("room.create.rejected", {
                                                   {"status", "401",             false},
                                                   {"reason", "unauthenticated", false}
        });
        return make_operation_result(false, {}, "unauthenticated", 401U);
    }
    // Preflight the complete initial-state list before creating the room or
    // persisting any earlier bootstrap/initial-state event (DB-6).
    if (std::ranges::any_of(options.initial_state, [](canonicaljson::Value const& entry) {
            auto const* object = std::get_if<canonicaljson::Object>(&entry.storage());
            auto const* state_key = object == nullptr ? nullptr : string_member(*object, "state_key");
            return state_key != nullptr && events::state_key_contains_nul(*state_key);
        }))
    {
        return invalid_state_key_result();
    }
    // F-19: the canonical alias check PUT /state makes applies to `initial_state` too. The room does not
    // exist yet, so a local alias must be the one this request creates (room_alias_name), and nothing is stored when
    // an entry is refused.
    {
        auto const pending_alias = options.room_alias_name.empty()
                                       ? std::string{}
                                       : full_room_alias(runtime.config.server(), options.room_alias_name);
        for (auto const& entry : options.initial_state)
        {
            auto const* object = std::get_if<canonicaljson::Object>(&entry.storage());
            auto const* type = object == nullptr ? nullptr : string_member(*object, "type");
            auto const* content = object == nullptr ? nullptr : object_member_as_object(*object, "content");
            // m.room.encryption is not judged here: ADR-0445 decides it. An entry that is not m.megolm.v1.aes-sha2 is
            // the documented way to ask for an unencrypted room, refused by default (M_INVALID_ROOM_STATE) and
            // allowed where the operator's encryption settings say so.
            if (type == nullptr || content == nullptr || *type != "m.room.canonical_alias")
            {
                continue;
            }
            auto const* named_state_key = string_member(*object, "state_key");
            auto const refusal = state_content_refusal(
                runtime.database.persistent_store, {}, runtime.config.server().server_name, *type,
                named_state_key == nullptr ? std::string_view{} : std::string_view{*named_state_key}, *content,
                pending_alias);
            if (refusal.has_value())
            {
                log_diagnostic("room.create.rejected", {
                                                           {"actor",      *user_id,         false},
                                                           {"status",     "400",            false},
                                                           {"event_type", *type,            false},
                                                           {"reason",     refusal->message, false}
                });
                // Spec (createRoom, 400): "The initial state implied by the parameters to the request is invalid"
                // is M_INVALID_ROOM_STATE, the code ADR-0445 already gives an invalid m.room.encryption entry.
                return invalid_room_state_result(refusal->message);
            }
        }
    }
    if (create_room_options_exceed_size_limits(options))
    {
        log_diagnostic("room.create.rejected", {
                                                   {"actor",  *user_id,                                       false},
                                                   {"status", "400",                                          false},
                                                   {"reason", "content exceeds the Matrix event size limits", false}
        });
        return event_too_large_result();
    }
    // power_level_content_override replaces whole top-level keys (ADR-0240), so a key
    // of the wrong shape ("users": null, "ban": "x") would reach the auth rules only
    // once the room and its first events were stored, as a 500 over a half-made
    // room. Spec (createRoom, 400 M_INVALID_ROOM_STATE): "The initial state implied
    // by the parameters to the createRoom request is invalid".
    if (auto const* override_policy = rooms::find_room_version_policy(options.room_version); override_policy != nullptr)
    {
        if (auto problem = events::power_levels_content_problem(options.power_level_content_override, *override_policy);
            !problem.empty())
        {
            log_diagnostic("room.create.rejected",
                           {
                               {"actor",  *user_id, false},
                               {"status", "400",    false},
                               {"reason", problem,  false}
            });
            return invalid_room_state_result("power_level_content_override: " + problem);
        }
    }
    // Spec (createRoom, 400 M_INVALID_ROOM_STATE): "The initial state implied by the parameters
    // to the createRoom request is invalid". Judged before anything is stored (ADR-0445).
    auto const encryption_request = creation_encryption_request(runtime, options);
    auto const encryption_decision = rooms::room_creation_encryption_policy(encryption_request);
    if (!encryption_decision.allowed)
    {
        log_diagnostic(
            "room.create.rejected",
            {
                {"actor",  *user_id,                   false},
                {"status", "400",                      false},
                {"reason", encryption_decision.reason, false}
        });
        return invalid_room_state_result(encryption_decision.reason);
    }
    if (auto refusal = v12_creation_refusal(options, *user_id); refusal.has_value())
    {
        log_diagnostic("room.create.rejected",
                       {
                           {"actor",  *user_id, false},
                           {"status", "400",    false},
                           {"reason", *refusal, false}
        });
        return invalid_room_state_result(std::move(*refusal));
    }

    // Build the m.room.create content first. In room version 12 the room ID is the
    // reference hash of the create event (MSC4291), so the create event must be
    // composed before a room ID exists; earlier versions use a server-scoped ID.
    auto create_content = options.creation_content;
    auto const* version_policy = rooms::find_room_version_policy(options.room_version);
    auto const create_sender_replaces_legacy_creator =
        version_policy != nullptr && version_policy->redaction_rules == rooms::RedactionRules::room_v11_plus;
    if (create_sender_replaces_legacy_creator)
    {
        // Room v11 removed content.creator. Strip client-supplied values too;
        // they must not survive into the signed create event as misleading data.
        std::erase_if(create_content, [](canonicaljson::ObjectMember const& member) {
            return member.key == "creator";
        });
    }
    else
    {
        upsert_object_member(create_content, canonicaljson::make_member("creator", canonicaljson::Value{*user_id}));
    }
    upsert_object_member(create_content,
                         canonicaljson::make_member("room_version", canonicaljson::Value{options.room_version}));

    auto const create_defines_room_id = version_policy != nullptr && version_policy->create_event_is_room_id;
    auto const supports_additional_creators = version_policy != nullptr && version_policy->privilege_room_creators;

    // MSC4289 / Matrix v1.16: only room versions that privilege creators (v12+) support
    // additional_creators. For the trusted_private_chat preset the server SHOULD append the
    // invited users to additional_creators, combined with any additional_creators the client
    // supplied in creation_content and deduplicated between the two. The sender is already a
    // creator, so it is never repeated. Pre-v12 rooms have no additional_creators concept —
    // there the preset instead grants invitees power level 100 in m.room.power_levels.
    if (supports_additional_creators && options.preset == "trusted_private_chat")
    {
        auto combined_creators = std::vector<std::string>{};
        auto const append_unique = [&combined_creators, &user_id](std::string_view candidate) {
            if (candidate.empty() || candidate == *user_id)
            {
                return;
            }
            if (std::ranges::find(combined_creators, candidate) == combined_creators.end())
            {
                combined_creators.emplace_back(candidate);
            }
        };
        if (auto const* existing = object_member(create_content, "additional_creators"); existing != nullptr)
        {
            if (auto const* existing_array = std::get_if<canonicaljson::Array>(&existing->storage());
                existing_array != nullptr)
            {
                for (auto const& entry : *existing_array)
                {
                    if (auto const* additional_id = std::get_if<std::string>(&entry.storage());
                        additional_id != nullptr)
                    {
                        append_unique(*additional_id);
                    }
                }
            }
        }
        for (auto const& invitee : options.trusted_invitees)
        {
            append_unique(invitee);
        }
        if (!combined_creators.empty())
        {
            upsert_object_member(create_content,
                                 canonicaljson::make_member("additional_creators", string_array(combined_creators)));
        }
    }
    auto room_id = std::string{};
    // Every server-side failure below answers 500 through this, so the reason
    // reaches an operator's log at error level; refusals the client caused stay
    // debug-level room.create.rejected diagnostics.
    auto const server_failure = [&user_id, &room_id](std::string reason) {
        log_diagnostic("room.create.failed",
                       {
                           {"actor",   *user_id, false},
                           {"room_id", room_id,  false},
                           {"status",  "500",    false},
                           {"reason",  reason,   false}
        },
                       observability::LogEventSeverity::error);
        return make_operation_result(false, {}, std::move(reason), 500U);
    };
    auto precomposed_create = std::optional<ComposedEvent>{};
    auto reservation = RoomIdReservation{runtime};
    if (create_defines_room_id)
    {
        // MSC4291: compose the create event (which carries no room_id) so the room ID can
        // be derived as "!" + the event's reference hash (i.e. the create event ID with a
        // "!" sigil instead of "$"). There is no ":server" suffix in room v12 IDs.
        auto create_event_object = canonicaljson::Object{};
        create_event_object.push_back(
            canonicaljson::make_member("type", canonicaljson::Value{std::string{"m.room.create"}}));
        create_event_object.push_back(canonicaljson::make_member("state_key", canonicaljson::Value{std::string{}}));
        create_event_object.push_back(canonicaljson::make_member("content", canonicaljson::Value{create_content}));
        auto const create_event_json = serialize_canonical_string(canonicaljson::Value{std::move(create_event_object)});
        if (!create_event_json.has_value())
        {
            return server_failure("initial room state event generation failed");
        }
        // A v12 create event has no room_id and no prev_events, so its sender,
        // content and origin_server_ts alone decide the room ID, and Ed25519
        // signing is deterministic. Two requests from one user with the same
        // creation content in one millisecond would derive the same room ID, and
        // the second would fail on the duplicate room row. Stamp each create event
        // strictly after the last one this runtime composed, and step past a
        // timestamp whose room ID is already taken: after a restart the runtime has
        // no memory of earlier timestamps and the clock may have stepped back.
        // Each existing room blocks at most one timestamp, so rooms.size() + 1
        // attempts always find a free room ID (ADR-0156).
        auto const room_id_taken = [&runtime](std::string_view candidate) {
            return find_room(runtime.database, candidate) != nullptr ||
                   std::ranges::any_of(runtime.database.persistent_store.rooms,
                                       [candidate](database::PersistentRoom const& existing) {
                                           return existing.room_id == candidate;
                                       });
        };
        auto create_ts = std::max(event_clock_now_ms(runtime), runtime.last_create_event_ts_ms + 1);
        auto const max_attempts = runtime.database.persistent_store.rooms.size() + runtime.database.rooms.size() + 1U;
        for (auto attempt = std::size_t{0U}; attempt < max_attempts; ++attempt, ++create_ts)
        {
            auto create_composition =
                compose_signed_event(runtime, std::string_view{}, *user_id, *create_event_json, create_ts);
            if (create_composition.failure == ComposeFailure::too_large)
            {
                return event_too_large_result();
            }
            if (!create_composition.event.has_value())
            {
                return server_failure("initial room state event generation failed");
            }
            auto candidate = "!" + create_composition.event->event_id.substr(1U);
            if (!room_id_taken(candidate))
            {
                runtime.last_create_event_ts_ms = create_ts;
                precomposed_create = std::move(create_composition.event);
                room_id = std::move(candidate);
                break;
            }
            log_diagnostic("room.create.room_id_taken", {
                                                            {"actor",            *user_id,                  false},
                                                            {"room_id",          candidate,                 false},
                                                            {"origin_server_ts", std::to_string(create_ts), false}
            });
        }
        if (!precomposed_create.has_value())
        {
            return server_failure("no free room ID for the create event timestamps");
        }
    }
    else
    {
        // The first "!room<N>" that no room holds and no creation in flight has chosen (ADR-0362). The count of
        // rooms alone is not enough: a join can drop a room from the in-memory list while its row stays
        // (F-82), and the policy-server hook below releases runtime.mutex, so a second creation can overlap.
        auto const slots = runtime.database.rooms.size() + runtime.database.persistent_store.rooms.size() +
                           runtime.rooms_being_created.size() + 1U;
        auto number = runtime.database.rooms.size() + 1U;
        for (auto attempt = std::size_t{0U}; attempt < slots; ++attempt, ++number)
        {
            auto candidate = "!room" + std::to_string(number) + ":" + runtime.config.server().server_name;
            if (find_room(runtime.database, candidate) != nullptr ||
                std::ranges::any_of(runtime.database.persistent_store.rooms,
                                    [&candidate](database::PersistentRoom const& existing) {
                                        return existing.room_id == candidate;
                                    }) ||
                runtime.rooms_being_created.contains(candidate))
            {
                continue;
            }
            room_id = std::move(candidate);
            break;
        }
        if (room_id.empty())
        {
            return server_failure("no free room ID");
        }
        reservation.hold(room_id);
    }
    auto const local_rule = find_policy_rule(runtime, "room", room_id);
    auto const held_for_review = local_rule.has_value() && local_rule->action == "quarantine";
    auto const blocked_by_local_policy =
        local_rule.has_value() && local_rule->action != "allow" && local_rule->action != "quarantine";
    auto const room_decision = trust_safety::evaluate_room_policy(
        {room_id, held_for_review, blocked_by_local_policy,
         resolve_policy_server_hook(runtime, trust_safety::PolicySurface::room, room_id)});
    if (!room_decision.allowed)
    {
        log_diagnostic(
            "room.create.rejected",
            {
                {"actor",   *user_id,                  false},
                {"room_id", room_id,                   false},
                {"reason",  room_decision.reason.code, false}
        });
        return make_operation_result(false, {}, room_decision.reason.code, 403U);
    }

    auto const alias = options.room_alias_name.empty()
                           ? std::string{}
                           : full_room_alias(runtime.config.server(), options.room_alias_name);
    // F-18, defence in depth: the createRoom handler refuses this too, but no caller of the service may store
    // an alias that cannot be resolved or deleted. Nothing has been stored yet.
    if (!alias.empty() && !auth::room_alias_is_valid(alias))
    {
        auto result = make_operation_result(false, {}, "room_alias_name does not make a valid room alias", 400U);
        result.errcode = "M_INVALID_PARAM";
        return result;
    }
    if (!alias.empty() && database::find_room_alias(runtime.database.persistent_store, alias).has_value())
    {
        log_diagnostic("room.create.rejected", {
                                                   {"actor",      *user_id,          false},
                                                   {"room_alias", alias,             false},
                                                   {"status",     "400",             false},
                                                   {"reason",     "room alias busy", false}
        });
        return make_operation_result(false, {}, "room alias in use", 400U);
    }

    if (!database::store_room_with_membership(runtime.database.persistent_store,
                                              {room_id, *user_id, options.directory_public}, {room_id, *user_id}))
    {
        return server_failure("room persistence failed");
    }
    runtime.database.rooms.push_back({room_id, *user_id, {*user_id}, options.directory_public});
    // Declared before any event is emitted so that its destructor, which runs on every way out of
    // this function, queues what was stored for interested appservices.
    auto created_events = CreatedEventQueue{runtime, room_id, *user_id};

    // Set when an initial state event is refused for the spec's size limits, so
    // the request answers 413 M_TOO_LARGE rather than a 500 (CSAZ-9).
    auto initial_state_too_large = false;
    auto emit_state = [&](std::string_view event_type, canonicaljson::Object content,
                          std::string_view state_key = std::string_view{}) -> bool {
        auto event = canonicaljson::Object{};
        event.push_back(canonicaljson::make_member("type", canonicaljson::Value{std::string{event_type}}));
        event.push_back(canonicaljson::make_member("state_key", canonicaljson::Value{std::string{state_key}}));
        event.push_back(canonicaljson::make_member("content", canonicaljson::Value{std::move(content)}));
        auto const serialized = serialize_canonical_string(canonicaljson::Value{std::move(event)});
        if (!serialized.has_value())
        {
            return false;
        }
        auto const failure = emit_initial_state_event(runtime, room_id, *user_id, *serialized, created_events);
        initial_state_too_large = initial_state_too_large || failure == ComposeFailure::too_large;
        return failure == ComposeFailure::none;
    };
    auto const initial_state_failure = [&initial_state_too_large, &server_failure] {
        return initial_state_too_large ? event_too_large_result()
                                       : server_failure("initial room state event generation failed");
    };

    // m.room.power_levels `events`: "when the server sends the initial power levels event during
    // room creation in room versions 12 and higher, the m.room.tombstone event MUST be explicitly
    // defined and given a power level higher than state_default. ... Clients may override this
    // using the described power_level_content_override field." So it is part of the generated
    // content, which the override is then applied on top of.
    auto generated_events = canonicaljson::Object{};
    if (room_version_number(options.room_version) >= 12)
    {
        generated_events.push_back(
            canonicaljson::make_member("m.room.tombstone", canonicaljson::Value{std::int64_t{150}}));
    }
    auto power_levels = canonicaljson::Object{};
    power_levels.push_back(canonicaljson::make_member("ban", canonicaljson::Value{std::int64_t{50}}));
    power_levels.push_back(canonicaljson::make_member("events", canonicaljson::Value{std::move(generated_events)}));
    power_levels.push_back(canonicaljson::make_member("events_default", canonicaljson::Value{std::int64_t{0}}));
    power_levels.push_back(canonicaljson::make_member("invite", canonicaljson::Value{std::int64_t{50}}));
    power_levels.push_back(canonicaljson::make_member("kick", canonicaljson::Value{std::int64_t{50}}));
    power_levels.push_back(canonicaljson::make_member("redact", canonicaljson::Value{std::int64_t{50}}));
    power_levels.push_back(canonicaljson::make_member("state_default", canonicaljson::Value{std::int64_t{50}}));
    // MSC4291: in room version 12+ the creator and any additional_creators hold an implicit,
    // infinite power level and MUST NOT appear in m.room.power_levels content.users. Synapse and
    // the room v12 auth rules reject a power_levels event that names a creator ("Creator user ...
    // must not appear in content.users"), which previously blocked remote users from joining.
    auto const creator_has_implicit_power_level = room_version_number(options.room_version) >= 12;
    auto creator_ids = std::vector<std::string>{*user_id};
    if (auto const* additional_value = object_member(create_content, "additional_creators");
        additional_value != nullptr)
    {
        if (auto const* additional_array = std::get_if<canonicaljson::Array>(&additional_value->storage());
            additional_array != nullptr)
        {
            for (auto const& entry : *additional_array)
            {
                if (auto const* additional_id = std::get_if<std::string>(&entry.storage()); additional_id != nullptr)
                {
                    creator_ids.push_back(*additional_id);
                }
            }
        }
    }

    auto power_users = canonicaljson::Object{};
    if (!creator_has_implicit_power_level)
    {
        power_users.push_back(canonicaljson::make_member(*user_id, canonicaljson::Value{std::int64_t{100}}));
        if (options.preset == "trusted_private_chat")
        {
            for (auto const& invitee : options.trusted_invitees)
            {
                upsert_object_member(power_users,
                                     canonicaljson::make_member(invitee, canonicaljson::Value{std::int64_t{100}}));
            }
        }
    }
    power_levels.push_back(canonicaljson::make_member("users", canonicaljson::Value{std::move(power_users)}));
    power_levels.push_back(canonicaljson::make_member("users_default", canonicaljson::Value{std::int64_t{0}}));
    // power_level_content_override "is applied on top of the generated m.room.power_levels event
    // content": each of its keys replaces that key of the generated content, nested maps
    // (`users`, `events`) included (ADR-0240).
    for (auto const& member : options.power_level_content_override)
    {
        upsert_object_member(power_levels, canonicaljson::make_member(member.key, *member.value));
    }
    if (creator_has_implicit_power_level)
    {
        // v12_creation_refusal has already refused a client override naming a creator; this
        // keeps the emitted event valid for v12 whatever reaches it.
        if (auto const* users_value = object_member(power_levels, "users"); users_value != nullptr)
        {
            if (auto const* users_object = std::get_if<canonicaljson::Object>(&users_value->storage());
                users_object != nullptr)
            {
                auto filtered_users = canonicaljson::Object{};
                for (auto const& member : *users_object)
                {
                    if (std::ranges::find(creator_ids, member.key) == creator_ids.end())
                    {
                        filtered_users.push_back(canonicaljson::make_member(member.key, *member.value));
                    }
                }
                upsert_object_member(
                    power_levels, canonicaljson::make_member("users", canonicaljson::Value{std::move(filtered_users)}));
            }
        }
    }
    // An override that supplies `events` owns the whole map, tombstone included. Otherwise the
    // generated tombstone level stays above state_default, which the override may have raised.
    auto const override_sets_events = object_member(options.power_level_content_override, "events") != nullptr;
    if (room_version_number(options.room_version) >= 12 && !override_sets_events)
    {
        auto state_default = std::int64_t{50};
        if (auto const* configured_state_default = integer_member(power_levels, "state_default");
            configured_state_default != nullptr)
        {
            state_default = *configured_state_default;
        }
        auto events_object = object_copy(*object_member(power_levels, "events"));
        auto const tombstone_level = state_default >= 150 ? state_default + 1 : std::int64_t{150};
        upsert_object_member(events_object,
                             canonicaljson::make_member("m.room.tombstone", canonicaljson::Value{tombstone_level}));
        upsert_object_member(power_levels,
                             canonicaljson::make_member("events", canonicaljson::Value{std::move(events_object)}));
    }

    auto join_rules = canonicaljson::Object{};
    join_rules.push_back(canonicaljson::make_member(
        "join_rule", canonicaljson::Value{std::string{options.preset == "public_chat" ? "public" : "invite"}}));
    auto history_visibility = canonicaljson::Object{};
    history_visibility.push_back(
        canonicaljson::make_member("history_visibility", canonicaljson::Value{std::string{"shared"}}));
    auto guest_access = canonicaljson::Object{};
    guest_access.push_back(canonicaljson::make_member(
        "guest_access", canonicaljson::Value{std::string{options.preset == "public_chat" ? "forbidden" : "can_join"}}));

    auto creator_member = canonicaljson::Object{};
    creator_member.push_back(canonicaljson::make_member("membership", canonicaljson::Value{std::string{"join"}}));
    add_member_profile(creator_member, database::find_profile(runtime.database.persistent_store, *user_id));

    // In room v12 the create event was composed up-front to derive the room ID, so
    // persist that exact event; earlier versions compose and persist it here.
    auto const create_persisted = [&]() -> bool {
        if (!create_defines_room_id)
        {
            return emit_state("m.room.create", std::move(create_content));
        }
        if (persist_composed_event(runtime, room_id, *user_id, *precomposed_create) == PersistOutcome::not_stored)
        {
            return false;
        }
        created_events.add(*precomposed_create);
        return true;
    }();
    if (!create_persisted || !emit_state("m.room.member", std::move(creator_member), *user_id) ||
        !emit_state("m.room.power_levels", std::move(power_levels)))
    {
        log_diagnostic("room.create.rejected", {
                                                   {"actor",   *user_id,                                     false},
                                                   {"room_id", room_id,                                      false},
                                                   {"status",  "500",                                        false},
                                                   {"reason",  "initial room state event generation failed", false}
        });
        return initial_state_failure();
    }

    if (!alias.empty())
    {
        auto canonical_alias = canonicaljson::Object{};
        canonical_alias.push_back(canonicaljson::make_member("alias", canonicaljson::Value{alias}));
        if (!emit_state("m.room.canonical_alias", std::move(canonical_alias)) ||
            !database::store_room_alias(runtime.database.persistent_store, {alias, room_id, *user_id}))
        {
            log_diagnostic("room.create.rejected", {
                                                       {"actor",      *user_id,                        false},
                                                       {"room_id",    room_id,                         false},
                                                       {"room_alias", alias,                           false},
                                                       {"status",     "500",                           false},
                                                       {"reason",     "room alias persistence failed", false}
            });
            return server_failure("room alias persistence failed");
        }
    }

    // Scan initial_state once for all client-provided event types that overlap
    // with preset-derived state, so presets are not emitted as duplicates.
    auto client_provided_join_rules = false;
    auto client_provided_history_visibility = false;
    auto client_provided_guest_access = false;
    for (auto const& item : options.initial_state)
    {
        auto const* state_obj = std::get_if<canonicaljson::Object>(&item.storage());
        if (state_obj == nullptr)
        {
            continue;
        }
        auto const* type_str = string_member(*state_obj, "type");
        if (type_str == nullptr)
        {
            continue;
        }
        if (*type_str == "m.room.join_rules")
        {
            client_provided_join_rules = true;
        }
        else if (*type_str == "m.room.history_visibility")
        {
            client_provided_history_visibility = true;
        }
        else if (*type_str == "m.room.guest_access")
        {
            client_provided_guest_access = true;
        }
    }

    if (!client_provided_join_rules && !emit_state("m.room.join_rules", std::move(join_rules)))
    {
        log_diagnostic("room.create.rejected", {
                                                   {"actor",   *user_id,                                    false},
                                                   {"room_id", room_id,                                     false},
                                                   {"status",  "500",                                       false},
                                                   {"reason",  "preset room state event generation failed", false}
        });
        return server_failure("preset room state event generation failed");
    }
    if (!client_provided_history_visibility && !emit_state("m.room.history_visibility", std::move(history_visibility)))
    {
        log_diagnostic("room.create.rejected", {
                                                   {"actor",   *user_id,                                    false},
                                                   {"room_id", room_id,                                     false},
                                                   {"status",  "500",                                       false},
                                                   {"reason",  "preset room state event generation failed", false}
        });
        return server_failure("preset room state event generation failed");
    }
    if (!client_provided_guest_access && !emit_state("m.room.guest_access", std::move(guest_access)))
    {
        log_diagnostic("room.create.rejected", {
                                                   {"actor",   *user_id,                                    false},
                                                   {"room_id", room_id,                                     false},
                                                   {"status",  "500",                                       false},
                                                   {"reason",  "preset room state event generation failed", false}
        });
        return server_failure("preset room state event generation failed");
    }

    // Emit the default m.room.encryption when the policy says the room is encrypted and the
    // client gave no effective entry. With an effective entry (the last one under the empty
    // state key) the initial_state loop below stores exactly the entry the policy judged, and an
    // entry under another state key never replaces the default (ADR-0445).
    if (encryption_decision.encryption_enabled &&
        encryption_request.encryption == rooms::RoomEncryptionRequest::unspecified)
    {
        auto encryption_content = canonicaljson::Object{};
        encryption_content.push_back(
            canonicaljson::make_member("algorithm", canonicaljson::Value{std::string{"m.megolm.v1.aes-sha2"}}));
        if (!emit_state("m.room.encryption", std::move(encryption_content)))
        {
            log_diagnostic("room.create.rejected",
                           {
                               {"actor",   *user_id,                                        false},
                               {"room_id", room_id,                                         false},
                               {"status",  "500",                                           false},
                               {"reason",  "encryption room state event generation failed", false}
            });
            return server_failure("encryption room state event generation failed");
        }
    }

    for (auto const& item : options.initial_state)
    {
        auto const* initial_state = std::get_if<canonicaljson::Object>(&item.storage());
        if (initial_state == nullptr)
        {
            continue;
        }
        auto const* event_type = string_member(*initial_state, "type");
        auto const* content = object_member(*initial_state, "content");
        if (event_type == nullptr || content == nullptr)
        {
            continue;
        }
        auto state_key = std::string{};
        if (auto const* initial_state_key = string_member(*initial_state, "state_key"); initial_state_key != nullptr)
        {
            state_key = *initial_state_key;
        }
        if (!emit_state(*event_type, object_copy(*content), state_key))
        {
            return initial_state_failure();
        }
    }

    if (!options.name.empty())
    {
        auto name_content = canonicaljson::Object{};
        name_content.push_back(canonicaljson::make_member("name", canonicaljson::Value{options.name}));
        if (!emit_state("m.room.name", std::move(name_content)))
        {
            return initial_state_failure();
        }
    }
    if (!options.topic.empty())
    {
        auto topic_content = canonicaljson::Object{};
        // Spec (m.room.topic, v1.15): `topic` is the plain text topic and "SHOULD duplicate the
        // content of the `text/plain` representation in `m.topic`"; createRoom's `topic` is sent
        // "with a `text/plain` mimetype". So write both: {"m.text":[{"body":..,"mimetype":"text/plain"}]}.
        topic_content.push_back(canonicaljson::make_member("topic", canonicaljson::Value{options.topic}));
        auto plain_text = canonicaljson::Object{};
        plain_text.push_back(canonicaljson::make_member("body", canonicaljson::Value{options.topic}));
        plain_text.push_back(canonicaljson::make_member("mimetype", canonicaljson::Value{std::string{"text/plain"}}));
        auto representations = canonicaljson::Array{};
        representations.emplace_back(canonicaljson::Value{std::move(plain_text)});
        auto topic_block = canonicaljson::Object{};
        topic_block.push_back(canonicaljson::make_member("m.text", canonicaljson::Value{std::move(representations)}));
        topic_content.push_back(canonicaljson::make_member("m.topic", canonicaljson::Value{std::move(topic_block)}));
        if (!emit_state("m.room.topic", std::move(topic_content)))
        {
            return initial_state_failure();
        }
    }

    auto invited_anyone = false;
    for (auto const& invitee : options.invitees)
    {
        auto invite_content = canonicaljson::Object{};
        invite_content.push_back(canonicaljson::make_member("membership", canonicaljson::Value{std::string{"invite"}}));
        if (options.is_direct)
        {
            invite_content.push_back(canonicaljson::make_member("is_direct", canonicaljson::Value{true}));
        }
        // emit_state's persist_composed_event projects the invite, its metadata
        // included (CSAZ-6).
        if (!emit_state("m.room.member", std::move(invite_content), invitee))
        {
            return initial_state_failure();
        }
        invited_anyone = true;
    }

    if (options.is_direct && !options.invitees.empty())
    {
        if (!upsert_m_direct(runtime, *user_id, room_id, options.invitees))
        {
            return server_failure("m.direct account data update failed");
        }
    }

    append_local_audit(runtime.database, observability::AuditCategory::admin, "room.created", *user_id, room_id,
                       "created");
    log_diagnostic("room.create.accepted",
                   {
                       {"actor",   *user_id, false},
                       {"room_id", room_id,  false}
    },
                   observability::LogEventSeverity::info);
    // Room creation changes membership which is visible in /sync;
    // advance the sync stream counter so the publish wakes clients.
    auto sync_stream_id = database::allocate_sync_stream_id(runtime.database.persistent_store);
    if (invited_anyone)
    {
        sync_stream_id = database::allocate_sync_stream_id(runtime.database.persistent_store);
    }
    if (runtime.sync_notifier != nullptr)
    {
        runtime.sync_notifier->publish(visible_stream_position(runtime.database), sync_stream_id);
    }
    notify_room_changed(runtime, room_id);
    return make_operation_result(true, room_id);
}

auto stripped_state_pdus(database::PersistentStore const& store, std::string_view room_id) -> std::vector<std::string>
{
    // The create event goes first: it is the one entry the spec requires, and a receiver that
    // reads only a prefix of the list still finds it.
    constexpr auto types =
        std::array<std::string_view, 7U>{"m.room.create", "m.room.join_rules",      "m.room.name",      "m.room.avatar",
                                         "m.room.topic",  "m.room.canonical_alias", "m.room.encryption"};
    auto entries = std::vector<std::string>{};
    for (auto const type : types)
    {
        auto const state_event_id = database::find_current_state_event_id(store, room_id, type, "");
        if (!state_event_id.has_value())
        {
            continue;
        }
        auto const event = store.events.find_in_room(room_id, *state_event_id);
        if (event == store.events.end())
        {
            continue;
        }
        auto const parsed = canonicaljson::parse_lossless(event->json);
        auto const* object = parsed.error == canonicaljson::ParseError::none
                                 ? std::get_if<canonicaljson::Object>(&parsed.value.storage())
                                 : nullptr;
        if (object == nullptr)
        {
            continue;
        }
        auto pdu = canonicaljson::Object{};
        for (auto const& member : *object)
        {
            if (member.key != "unsigned")
            {
                pdu.push_back(member);
            }
        }
        if (auto serialized = serialize_canonical_string(canonicaljson::Value{std::move(pdu)}); serialized.has_value())
        {
            entries.push_back(std::move(*serialized));
        }
    }
    return entries;
}

auto parse_join_via_servers(std::string_view query) -> std::optional<std::vector<std::string>>
{
    auto servers = std::vector<std::string>{};
    while (!query.empty())
    {
        auto const amp = query.find('&');
        auto const pair = query.substr(0U, amp);
        query = amp == std::string_view::npos ? std::string_view{} : query.substr(amp + 1U);
        auto const eq = pair.find('=');
        if (eq == std::string_view::npos)
        {
            continue;
        }
        // `server_name` is the legacy spelling; `via` (MSC4156) is the current one.
        if (auto const key = pair.substr(0U, eq); key != "server_name" && key != "via")
        {
            continue;
        }
        auto const encoded = pair.substr(eq + 1U);
        if (core::path_component_contains_nul(encoded))
        {
            return std::nullopt;
        }
        auto decoded = core::percent_decode_path_component(encoded);
        if (!decoded.empty() && std::ranges::find(servers, decoded) == servers.end())
        {
            servers.push_back(std::move(decoded));
        }
    }
    return servers;
}

auto join_candidate_servers(std::vector<std::string> const& via_servers, std::string_view room_id,
                            std::string_view our_server) -> std::vector<std::string>
{
    auto candidates = std::vector<std::string>{};
    auto const add = [&](std::string_view server) {
        if (!server.empty() && server != our_server && std::ranges::find(candidates, server) == candidates.end())
        {
            candidates.emplace_back(server);
        }
    };
    for (auto const& server : via_servers)
    {
        add(server);
    }
    // ADR-0242: room IDs "are not routable on their own" (appendices, Room IDs), so
    // the room ID's domain is only a last resort when the client named no other
    // server: added to the via list, it let a join the client routed through one
    // server succeed through another. A room version 12 ID has no domain at all
    // (MSC4291), and server_name_from_room_id returns empty.
    if (candidates.empty())
    {
        add(server_name_from_room_id(room_id));
    }
    return candidates;
}

auto cap_join_candidates(std::vector<std::string> candidates, std::uint32_t max_candidates) -> std::vector<std::string>
{
    auto const cap = static_cast<std::size_t>(std::max(std::uint32_t{1U}, max_candidates));
    if (candidates.size() > cap)
    {
        candidates.resize(cap);
    }
    return candidates;
}

namespace
{

    // FED-1 (ADR-0083): the room a send_join `state` or `auth_chain` entry
    // belongs to, or "" when it has none we can accept. Under a room version
    // whose m.room.create event defines the room ID (v12, rooms/v12.md), the
    // create event has no room_id — "The room ID is the event ID of the event
    // with sigil ! instead of $" — and one that carries a room_id is rejected
    // by auth rule 1.2, so it belongs to no room here.
    [[nodiscard]] auto send_join_event_room_id(canonicaljson::Value const& entry,
                                               rooms::RoomVersionPolicy const& policy) -> std::string
    {
        auto const* entry_obj = std::get_if<canonicaljson::Object>(&entry.storage());
        if (entry_obj == nullptr)
        {
            return {};
        }
        auto const* type_field = json_string_member(*entry_obj, "type");
        if (policy.create_event_is_room_id && type_field != nullptr && *type_field == "m.room.create")
        {
            if (json_object_member(*entry_obj, "room_id") != nullptr)
            {
                return {};
            }
            auto const create_id = events::make_reference_hash_event_id(entry, policy);
            if (!create_id.error.empty() || create_id.event_id.size() < 2U)
            {
                return {};
            }
            return "!" + create_id.event_id.substr(1U);
        }
        auto const* room_field = json_string_member(*entry_obj, "room_id");
        return room_field != nullptr ? *room_field : std::string{};
    }

} // namespace

[[nodiscard]] auto filter_send_join_events_for_room(canonicaljson::Array const& events, std::string_view room_id,
                                                    rooms::RoomVersionPolicy const& policy) -> canonicaljson::Array
{
    auto kept = canonicaljson::Array{};
    if (room_id.empty())
    {
        return kept;
    }
    kept.reserve(events.size());
    for (auto const& entry : events)
    {
        if (send_join_event_room_id(entry, policy) == room_id)
        {
            kept.push_back(entry);
        }
    }
    if (kept.size() != events.size())
    {
        log_diagnostic("room.join.state_event_rejected",
                       {
                           {"room_id", std::string{room_id},                             false},
                           {"dropped", std::to_string(events.size() - kept.size()),      false},
                           {"reason",  "event does not belong to the room being joined", false}
        },
                       observability::LogEventSeverity::warning);
    }
    return kept;
}

namespace
{
    // ADR-0630: whether a resident's snapshot may replay this server's own event about one of its users. It may when
    // this server holds no row for the user in the room (nothing to contradict), or when the event is the one held as
    // current.
    // Otherwise this server's own record stands; `held_event_id` is the event it holds as current for the user.
    struct LocalMemberClaim final
    {
        bool taken{false};
        std::optional<std::string> held_event_id{};
    };

    [[nodiscard]] auto judge_local_member_claim(database::PersistentStore const& store, std::string_view room_id,
                                                std::string_view user_id, std::string_view claimed_event_id)
        -> LocalMemberClaim
    {
        auto held = database::find_current_state_event_id(store, room_id, "m.room.member", user_id);
        auto const agrees = held.has_value() && *held == claimed_event_id;
        auto const holds_a_row = held.has_value() || !current_membership_of(store, room_id, user_id).empty();
        return {agrees || !holds_a_row, std::move(held)};
    }
} // namespace

// Persists the `state` array from a send_join response. Each event is stored to
// the persistent event graph. Events that carry a "state_key" field in their raw
// JSON (even when that value is "") are also written to the state table. That is
// the correct discriminant per the Matrix spec: any event with a "state_key"
// field is a state event, regardless of whether the value is empty.
//
// Returns the user IDs with membership="join" found within the ingested events.
//
// IMPORTANT: this function is also called directly from integration tests to verify
// that state events with empty state_key (m.room.encryption, m.room.create, etc.)
// are correctly persisted. Do NOT change the state-key check without updating the
// corresponding test in tests/integration/test_federation_invite_join_flow.cpp.
[[nodiscard]] auto ingest_send_join_state(HomeserverRuntime& runtime, std::string_view room_id,
                                          canonicaljson::Array const& state_arr, rooms::RoomVersionPolicy const& policy)
    -> SendJoinStateIngestResult
{
    auto result = SendJoinStateIngestResult{};
    auto& joined_members = result.joined_members;
    // The whole snapshot commits in one transaction, under runtime.mutex: one
    // write per event, a room's full member list since ADR-0241, held every other
    // request back for the length of the join. Each entry is prepared in array
    // order; an event already stored, or repeated in the array, is recorded but
    // not written again.
    //
    // Every write is prepared against the store as it was before the batch, so
    // two events for one (event_type, state_key) would each prepare an INSERT
    // into current_state, whose primary key is that pair, and fail the whole
    // transaction on a backend that runs the SQL. Only the final event for a key,
    // the last entry naming it, writes current_state, from its first stored copy;
    // the others are stored as the outliers they are.
    struct SnapshotCandidate final
    {
        database::PersistentEvent event{};
        std::optional<database::PersistentStateEvent> state{};
        // A refused claim about a local user: the event this server holds as current for the key, which the
        // snapshot's state group carries in its place (ADR-0630).
        std::optional<database::PersistentStateGroupStateEntry> held_entry{};
        std::string joined_member{};
        bool refused_claim{false};
        bool repeated{false};
    };
    struct SnapshotEntry final
    {
        std::optional<database::PreparedStateUpdate> prepared{};
        std::optional<database::PersistentStateEvent> state{};
        std::optional<database::PersistentStateGroupStateEntry> held_entry{};
        std::string joined_member{};
        bool refused_claim{false};
    };
    auto candidates = std::vector<SnapshotCandidate>{};
    auto batch_event_ids = std::set<std::string, std::less<>>{};
    auto next_ordering = allocate_stream_orderings(runtime.database, state_arr.size());
    for (auto const& state_entry : state_arr)
    {
        // FED-1 (ADR-0083): an entry for any other room is never stored and
        // never written to current_state. join_room filters the arrays before
        // verification too; this is the check at the writer.
        if (room_id.empty() || send_join_event_room_id(state_entry, policy) != room_id)
        {
            continue;
        }
        // The resident's `unsigned` on an entry is covered by no signature (ADR-0402).
        auto const serialized = canonicaljson::serialize_canonical(events::without_unsigned(state_entry));
        if (serialized.error == canonicaljson::CanonicalJsonError::none)
        {
            auto const parsed = events::parse_event_envelope(state_entry);
            if (parsed.error.empty())
            {
                auto const* entry_obj = std::get_if<canonicaljson::Object>(&state_entry.storage());
                auto event_id = std::string{};
                if (entry_obj != nullptr)
                {
                    if (policy.event_id_format == rooms::EventIdFormat::reference_hash)
                    {
                        auto const eid = events::make_reference_hash_event_id(state_entry, policy);
                        event_id = eid.event_id;
                    }
                    else
                    {
                        auto const* id_field = json_string_member(*entry_obj, "event_id");
                        if (id_field != nullptr)
                        {
                            event_id = *id_field;
                        }
                    }
                }
                auto depth = std::uint64_t{0U};
                if (entry_obj != nullptr)
                {
                    if (auto const* d = json_integer_member(*entry_obj, "depth"); d != nullptr && *d >= 0)
                    {
                        depth = static_cast<std::uint64_t>(*d);
                    }
                }
                auto prev_ids = std::vector<std::string>{};
                auto auth_ids = std::vector<std::string>{};
                if (entry_obj != nullptr)
                {
                    if (auto const* pv = json_object_member(*entry_obj, "prev_events"); pv != nullptr)
                    {
                        prev_ids = json_string_array(*pv);
                    }
                    if (auto const* av = json_object_member(*entry_obj, "auth_events"); av != nullptr)
                    {
                        auth_ids = json_string_array(*av);
                    }
                }
                auto const stream_ordering = next_ordering++;
                // A state event is identified by the PRESENCE of the "state_key" field
                // in the raw JSON, even when its value is "". EventEnvelope::state_key
                // defaults to "" both for state events with state_key="" AND for
                // non-state events (where the field is absent), so .empty() cannot
                // distinguish the two. Check the raw JSON field instead.
                // The entry belongs to `room_id` (checked above). For a v12
                // m.room.create, which carries no room_id field, that is the room
                // ID derived from its reference hash, so the PersistentStateEvent
                // is stored with the correct room_id and can be found later by
                // build_pdu_auth_event_map.
                auto const effective_room_id = std::string{room_id};
                auto state = std::optional<database::PersistentStateEvent>{};
                if (entry_obj != nullptr)
                {
                    if (auto const* raw_sk = json_string_member(*entry_obj, "state_key"); raw_sk != nullptr)
                    {
                        state = database::PersistentStateEvent{effective_room_id, parsed.event.event_type, *raw_sk,
                                                               event_id};
                    }
                }
                auto pe = database::PersistentEvent{};
                pe.event_id = event_id;
                pe.room_id = effective_room_id;
                pe.sender_user_id = parsed.event.sender;
                pe.json = serialized.output;
                pe.depth = depth;
                pe.stream_ordering = stream_ordering;
                pe.prev_event_ids = std::move(prev_ids);
                pe.auth_event_ids = std::move(auth_ids);
                pe.signatures = parsed.event.signatures;
                // ADR-0064 phase B1: this event reaches us as part of the
                // send_join response's state snapshot, not our own timeline
                // — it is not (yet) reachable by walking prev_events from
                // anything we hold, so it is stored as an outlier: kept for
                // auth-chain lookups, but never given a state group of its
                // own and never a forward extremity. join_room builds ONE
                // snapshot state group from the full state array below,
                // used as the join event's state-before.
                pe.status = "outlier";
                auto candidate = SnapshotCandidate{};
                candidate.state = std::move(state);
                // ADR-0630: an event this server authored about one of its users is judged against this server's own
                // record. A refused one is kept as an outlier like any event, writes no current_state row and no
                // membership, and the state group takes this server's event for the key. A remote sender's event (a
                // ban issued while this server was out of the room) can only be learned from the snapshot.
                if (candidate.state.has_value() && parsed.event.event_type == "m.room.member" &&
                    auth::user_id_server_name(candidate.state->state_key) == runtime.config.server().server_name &&
                    auth::user_id_server_name(parsed.event.sender) == runtime.config.server().server_name)
                {
                    auto verdict = judge_local_member_claim(runtime.database.persistent_store, room_id,
                                                            candidate.state->state_key, event_id);
                    if (!verdict.taken)
                    {
                        log_diagnostic("room.join.local_member_claim_refused",
                                       {
                                           {"room_id",  std::string{room_id},                            false},
                                           {"event_id", event_id,                                        false},
                                           {"user_id",  candidate.state->state_key,                      false},
                                           {"reason",   "this server holds its own record for the user", false}
                        },
                                       observability::LogEventSeverity::warning);
                        if (verdict.held_event_id.has_value())
                        {
                            candidate.held_entry = database::PersistentStateGroupStateEntry{
                                {}, "m.room.member", candidate.state->state_key, std::move(*verdict.held_event_id)};
                        }
                        candidate.state.reset();
                        candidate.refused_claim = true;
                    }
                }
                // Track joined members for the in-memory LocalRoom population step.
                // state_key is non-empty for membership events (it holds the user ID).
                if (parsed.event.event_type == "m.room.member" && !parsed.event.state_key.empty() &&
                    events::extract_content_membership(state_entry) == "join")
                {
                    candidate.joined_member = parsed.event.state_key;
                }
                // The same event earlier in this batch: this copy is recorded
                // again, not written twice.
                candidate.repeated = !batch_event_ids.insert(event_id).second;
                candidate.event = std::move(pe);
                candidates.push_back(std::move(candidate));
            }
        }
    }

    // The last first copy of an event for each key, by position in `candidates`.
    // The final event for each key: the last entry naming it, a repeated copy
    // included, so A, B, A ends at A. Its first stored copy writes current_state.
    auto final_for_key = std::map<std::pair<std::string, std::string>, std::string>{};
    for (auto const& candidate : candidates)
    {
        if (candidate.state.has_value())
        {
            final_for_key.insert_or_assign(std::pair{candidate.state->event_type, candidate.state->state_key},
                                           candidate.event.event_id);
        }
    }
    auto entries = std::vector<SnapshotEntry>{};
    auto kept_event_ids = std::set<std::string, std::less<>>{};
    for (auto index = std::size_t{0U}; index < candidates.size(); ++index)
    {
        auto& candidate = candidates[index];
        auto const event_id = candidate.event.event_id;
        auto entry = SnapshotEntry{};
        entry.state = candidate.state;
        entry.held_entry = candidate.held_entry;
        entry.refused_claim = candidate.refused_claim;
        entry.joined_member = candidate.state.has_value() ? std::move(candidate.joined_member) : std::string{};
        if (candidate.repeated)
        {
            // Recorded again only when its first copy was kept.
            if (kept_event_ids.contains(event_id))
            {
                entries.push_back(std::move(entry));
            }
            continue;
        }
        auto const writes_current_state =
            candidate.state.has_value() &&
            final_for_key.at(std::pair{candidate.state->event_type, candidate.state->state_key}) == event_id;
        entry.prepared = database::prepare_store_event_with_state(
            runtime.database.persistent_store, std::move(candidate.event),
            writes_current_state ? candidate.state : std::optional<database::PersistentStateEvent>{});
        // A duplicate verified snapshot event is already committed; include
        // it in the join snapshot rather than mistaking the store's
        // duplicate-insert refusal for a failed initial state.
        if (!entry.prepared.has_value() && runtime.database.persistent_store.events.find_in_room(room_id, event_id) ==
                                               runtime.database.persistent_store.events.end())
        {
            log_diagnostic("room.join.state_entry_dropped",
                           {
                               {"room_id",  std::string{room_id},                                 false},
                               {"event_id", event_id,                                             false},
                               {"reason",   "not preparable and not already stored in this room", false}
            },
                           observability::LogEventSeverity::warning);
            continue;
        }
        kept_event_ids.insert(event_id);
        entries.push_back(std::move(entry));
    }

    auto statements = std::vector<database::PreparedStatement>{};
    for (auto const& entry : entries)
    {
        if (entry.prepared.has_value())
        {
            statements.insert(statements.end(), entry.prepared->statements.begin(), entry.prepared->statements.end());
        }
    }
    if (!statements.empty() && !database::commit_persistent_transaction(runtime.database.persistent_store, statements))
    {
        // Nothing of the snapshot is stored; join_room refuses the join on the
        // missing state entries.
        return SendJoinStateIngestResult{};
    }
    auto recorded_keys = std::map<std::pair<std::string, std::string>, std::size_t>{};
    // The joined member each recorded entry names (empty when it names none),
    // parallel to result.state_entries: a later entry for the same key, a leave
    // after a join, replaces it, so the roster matches the state group.
    auto recorded_members = std::vector<std::string>{};
    for (auto const& entry : entries)
    {
        if (entry.prepared.has_value())
        {
            database::apply_store_event_with_state(runtime.database.persistent_store, *entry.prepared);
        }
        if (entry.held_entry.has_value())
        {
            // A refused claim counts as recorded: the snapshot was read in full, and the group carries this server's
            // event for the key.
            ++result.recorded_state_events;
            if (auto const [position, inserted] = recorded_keys.try_emplace(
                    std::pair{entry.held_entry->event_type, entry.held_entry->state_key}, result.state_entries.size());
                inserted)
            {
                result.state_entries.push_back(*entry.held_entry);
                recorded_members.emplace_back();
            }
            else
            {
                result.state_entries[position->second] = *entry.held_entry;
                recorded_members[position->second].clear();
            }
        }
        else if (entry.refused_claim)
        {
            ++result.recorded_state_events;
        }
        else if (entry.state.has_value())
        {
            ++result.recorded_state_events;
            // One entry per key: the state group rejects a key twice. A later
            // entry for the same key replaces the earlier, as current_state does.
            // Indexed, not searched: a large room's snapshot is all member events.
            auto recorded = database::PersistentStateGroupStateEntry{
                {}, entry.state->event_type, entry.state->state_key, entry.state->event_id};
            if (auto const [position, inserted] = recorded_keys.try_emplace(
                    std::pair{entry.state->event_type, entry.state->state_key}, result.state_entries.size());
                inserted)
            {
                result.state_entries.push_back(std::move(recorded));
                recorded_members.push_back(entry.joined_member);
            }
            else
            {
                result.state_entries[position->second] = std::move(recorded);
                recorded_members[position->second] = entry.joined_member;
            }
        }
    }
    for (auto const& member : recorded_members)
    {
        if (!member.empty())
        {
            append_unique_member(joined_members, member);
        }
    }
    return result;
}

auto filter_verified_send_join_events(HomeserverRuntime& runtime, canonicaljson::Array const& events,
                                      rooms::RoomVersionPolicy const& policy, std::string_view our_server)
    -> canonicaljson::Array
{
    if (events.empty())
    {
        return {};
    }
    // ADR-0390: the operator's policy for each server that wrote part of the answer. Asked once per server, since
    // a large room's answer has thousands of events and the admin's rules are read under runtime.mutex.
    auto policy_refused_servers = std::map<std::string, bool, std::less<>>{};
    // Spec: "Checks performed on receipt of a PDU", step 1. A resident's answer is held to the room version's event
    // format like any other received event, so what breaks it is dropped before a key is fetched for it (ADR-0399).
    auto in_format = std::vector<std::reference_wrapper<canonicaljson::Value const>>{};
    in_format.reserve(events.size());
    for (auto const& entry : events)
    {
        if (auto const violation = federation::pdu_format_violation(entry, policy); !violation.empty())
        {
            log_diagnostic("room.join.state_event_rejected",
                           {
                               {"reason", violation, false}
            },
                           observability::LogEventSeverity::warning);
            continue;
        }
        in_format.emplace_back(entry);
    }
    auto const refused_by_policy = [&runtime, &policy_refused_servers](std::string_view server) {
        auto const known = policy_refused_servers.find(server);
        if (known != policy_refused_servers.end())
        {
            return known->second;
        }
        auto const refused = !federation::operator_policy_refusal(runtime.federation, server).empty();
        policy_refused_servers.emplace(std::string{server}, refused);
        return refused;
    };
    // Pre-resolve distinct (sender_domain, key_id) pairs in parallel so a state
    // array carrying one m.room.member per room member (thousands for a large
    // room) does not pay N serial key discovery+fetch round trips. Mirrors the
    // fan-out pattern in src/federation/InboundRequest.cpp's parallel inbound
    // PDU sender-key resolution. Fan-out is capped by join_state_key_parallelism
    // (default 100); a configured value of 0 is clamped to 1 defensively
    // (config validation already rejects 0).
    auto sender_key_map =
        std::map<std::pair<std::string, std::string>, std::optional<federation::FederationKeyRecord>>{};
    if (runtime.federation.remote_key_resolver)
    {
        auto distinct_pairs = std::vector<std::pair<std::string, std::string>>{};
        auto seen = std::set<std::pair<std::string, std::string>>{};
        for (canonicaljson::Value const& entry : in_format)
        {
            auto const parsed = events::parse_event_envelope(entry);
            if (!parsed.error.empty())
            {
                continue;
            }
            // A restricted join's authorising server is verified below too
            // (ADR-0171); fetch every key the verifier may try (at most
            // max_authorising_signature_keys) in the same parallel pass. A room version
            // without restricted joins has no such rule to check (ADR-0356).
            if (auto const authorising =
                    policy.restricted_join_rule ? federation::join_authorising_signature_key(entry) : std::nullopt;
                authorising.has_value() && authorising->server_name != our_server &&
                !refused_by_policy(authorising->server_name))
            {
                for (auto const& authorising_key_id : authorising->key_ids)
                {
                    auto key = std::make_pair(authorising->server_name, authorising_key_id);
                    if (seen.insert(key).second)
                    {
                        distinct_pairs.push_back(std::move(key));
                    }
                }
            }
            auto const dom = sender_domain_from_user_id(parsed.event.sender);
            if (dom.empty() || dom == our_server || refused_by_policy(dom))
            {
                continue;
            }
            // R05 (ADR-0183): every key the sender check may try, at most
            // max_signature_keys_per_server per event, in the same pass.
            for (auto& key_id : federation::signature_key_ids_for_server(parsed.event.signatures, dom))
            {
                auto key = std::make_pair(std::string{dom}, std::move(key_id));
                if (seen.insert(key).second)
                {
                    distinct_pairs.push_back(std::move(key));
                }
            }
        }
        if (!distinct_pairs.empty())
        {
            static constexpr auto k_max_join_state_key_parallelism = std::ptrdiff_t{1024};
            auto const& federation_config = runtime.federation.config;
            auto const configured = federation_config.join_state_key_parallelism;
            // FED-10, ADR-0155: each fetch takes one of the process-wide
            // key-resolution slots, so more tasks than slots would only wait.
            auto const parallelism = std::min(
                {static_cast<std::ptrdiff_t>(std::max(std::uint32_t{1U}, configured)), k_max_join_state_key_parallelism,
                 static_cast<std::ptrdiff_t>(
                     std::max(std::uint32_t{1U}, federation_config.key_resolution_max_in_flight))});
            // A slot is waited for, never refused, but not for longer than a
            // join may take.
            auto constexpr fallback_join_timeout = std::chrono::seconds{180};
            auto const deadline =
                std::chrono::steady_clock::now() + (federation_config.join_timeout_seconds > 0U
                                                        ? std::chrono::seconds{federation_config.join_timeout_seconds}
                                                        : fallback_join_timeout);
            auto resolved = std::vector<std::optional<federation::FederationKeyRecord>>(distinct_pairs.size());
            auto& federation_state = runtime.federation;
            // Every task writes only its own slot of `resolved`, and the call
            // returns only once all of them have finished. A lookup that throws
            // gives its slot back (the slot used to be released by hand, so
            // `parallelism` throws left the next acquire waiting forever).
            core::run_bounded_parallel(
                distinct_pairs.size(), static_cast<std::size_t>(parallelism), [&](std::size_t const i) {
                    auto const& pair = distinct_pairs[i];
                    resolved[i] =
                        federation::resolve_join_state_key(federation_state, pair.first, pair.second, deadline);
                });
            for (auto i = std::size_t{0U}; i < distinct_pairs.size(); ++i)
            {
                sender_key_map[distinct_pairs[i]] = std::move(resolved[i]);
            }
        }
    }
    // FED-1 (ADR-0083): an event naming our own domain is verified like any
    // other, against this server's OWN signing keys — never fetched over the
    // network. federation::find_own_server_signing_key reads only the rows
    // for our server name that hold a secret (the keys we generated: the
    // current one and every retired one); a row without a secret is a copy
    // fetched from somewhere and is not trusted as ours. It takes the store's
    // signing-key lock, so this is safe with runtime.mutex released.
    auto const own_signing_key = [&](std::string_view key_id) -> std::optional<federation::FederationKeyRecord> {
        return federation::find_own_server_signing_key(runtime.database.persistent_store, our_server, key_id);
    };
    // Verify each event's signature against its sender-domain key, dropping
    // events that fail. Fail-closed (src/federation/AGENTS.md rule 2): an event
    // whose sender-domain key was not found, or whose signature does not
    // verify, is silently dropped — never persisted.
    auto verified = canonicaljson::Array{};
    verified.reserve(in_format.size());
    for (canonicaljson::Value const& entry : in_format)
    {
        auto const parsed = events::parse_event_envelope(entry);
        if (!parsed.error.empty())
        {
            continue;
        }
        auto const dom = sender_domain_from_user_id(parsed.event.sender);
        if (dom.empty())
        {
            continue;
        }
        if (refused_by_policy(dom))
        {
            log_diagnostic("room.join.state_event_rejected",
                           {
                               {"sender_domain", std::string{dom},                      false},
                               {"reason",        "server is denied by operator policy", false}
            },
                           observability::LogEventSeverity::warning);
            continue;
        }
        if (federation::signature_key_ids_for_server(parsed.event.signatures, dom).empty())
        {
            log_diagnostic("room.join.state_event_rejected",
                           {
                               {"sender_domain", std::string{dom},                          false},
                               {"reason",        "no signature from event sender's domain", false}
            },
                           observability::LogEventSeverity::warning);
            continue;
        }
        if (runtime.crypto_provider == nullptr)
        {
            continue;
        }
        // R05 (ADR-0183): every listed key that is known and unexpired must
        // verify, and at least one must. Each is one of ours (never fetched) or
        // was resolved in the pass above. ADR-0075: from room v5 a key counts
        // only if it was still valid at the event's origin_server_ts, the same
        // rule every received event is held to.
        auto const verification = federation::verify_server_signatures_on_event(
            entry, policy, dom, parsed.event.signatures,
            [&](std::string_view server_name, std::string_view key_id) {
                if (server_name == our_server)
                {
                    return federation::VerificationKeyResolution{own_signing_key(key_id)};
                }
                auto const map_it = sender_key_map.find(
                    std::pair<std::string, std::string>{std::string{server_name}, std::string{key_id}});
                return federation::VerificationKeyResolution{map_it != sender_key_map.end() ? map_it->second
                                                                                            : std::nullopt};
            },
            *runtime.crypto_provider);
        if (!verification.accepted)
        {
            log_diagnostic("room.join.state_event_rejected",
                           {
                               {"sender_domain", std::string{dom},    false},
                               {"reason",        verification.reason, false}
            },
                           observability::LogEventSeverity::warning);
            continue;
        }
        // EVT-1, ADR-0171: a restricted join in the resident's state must also be
        // validly signed by its authorising server, like on every other ingestion
        // path. Its key was resolved in the pass above (or is one of ours).
        auto const authorising = federation::verify_join_authorising_server_signature(
            entry, policy,
            [&](std::string_view server_name, std::string_view authorising_key_id) {
                if (server_name == our_server)
                {
                    return federation::VerificationKeyResolution{own_signing_key(authorising_key_id)};
                }
                auto const map_it = sender_key_map.find(
                    std::pair<std::string, std::string>{std::string{server_name}, std::string{authorising_key_id}});
                return federation::VerificationKeyResolution{map_it != sender_key_map.end() ? map_it->second
                                                                                            : std::nullopt};
            },
            *runtime.crypto_provider);
        if (!authorising.accepted)
        {
            log_diagnostic("room.join.state_event_rejected",
                           {
                               {"sender_domain", std::string{dom},   false},
                               {"reason",        authorising.reason, false}
            },
                           observability::LogEventSeverity::warning);
            continue;
        }
        // Spec, "Checks performed on receipt of a PDU", step 3: a hash mismatch redacts the event before it is
        // processed further. The signature and the event ID cover only the redacted form, so a resident can change
        // what redaction removes and keep both (F-45, ADR-0369). The redacted form is what goes on.
        if (events::verify_pdu_content_hash(entry))
        {
            verified.push_back(entry);
            continue;
        }
        auto redacted = events::redact_event(entry, policy);
        if (!redacted.error.empty())
        {
            log_diagnostic("room.join.state_event_rejected",
                           {
                               {"sender_domain", std::string{dom},                             false},
                               {"reason",        "content hash mismatch and redaction failed", false}
            },
                           observability::LogEventSeverity::warning);
            continue;
        }
        verified.push_back(std::move(redacted.event));
    }
    return verified;
}

namespace
{

    // What a federated join needs to hand back to `join_room` once the network
    // work is done and `runtime.mutex` has been re-acquired.
    //
    // `perform_federated_join` runs with the mutex RELEASED, so it can hold no
    // reference into runtime state — every value here is owned. An engaged
    // `failure` means the join did not get far enough to produce the rest, and
    // `join_room` returns it verbatim.
    struct FederatedJoinOutcome final
    {
        std::optional<OperationResult> failure{};
        // Held by value. The lookup returns a pointer into a static table, but
        // storing that pointer here would make the caller's dereference depend on
        // `failure` being disengaged, and the project forbids raw pointers.
        // RoomVersionPolicy is a string_view and a handful of enums and bools.
        rooms::RoomVersionPolicy policy{};
        std::string remote_server{};
        events::SignedEventResult signed_event{};
        canonicaljson::Value signed_event_value{};
        events::EventIdResult event_id_result{};
        // Every event of the send_join `state` array whose signature checked out,
        // other members' m.room.member events included (ADR-0241).
        canonicaljson::Array verified_state{};
        canonicaljson::Array verified_auth_chain{};
        // Only for a join through another resident of a room this server is already in
        // (ADR-0287): the resident's `event`, the join with its co-signature, once checked.
        std::string resident_signed_event_json{};
    };

    // How `perform_federated_join` uses the send_join answer.
    enum class FederatedJoinPurpose : std::uint8_t
    {
        // This server holds nothing of the room: the answer's `state` and `auth_chain`
        // become the room's state.
        enter_room,
        // This server is resident and holds the room's state (ADR-0287): only the
        // resident's co-signed copy of the join is wanted, and state is never taken from
        // the answer.
        join_through_resident,
    };

    // `base`, a signed event, with the signature that `source` carries for `server_name` under each of
    // `key_ids` added to its `signatures`. Nothing else of `base` changes: the result keeps `base`'s
    // content, hashes and every signature it already had (Server-Server API, PUT /v2/invite: "All other
    // fields of the events should remain untouched"). nullopt when a named key has no signature in
    // `source` or the result cannot be built.
    [[nodiscard]] auto with_server_signatures(canonicaljson::Value const& base,
                                              std::vector<events::EventSignature> const& source,
                                              std::string_view server_name, std::vector<std::string> const& key_ids)
        -> std::optional<canonicaljson::Value>
    {
        auto merged = base;
        for (auto const& key_id : key_ids)
        {
            auto const found = std::ranges::find_if(source, [&](events::EventSignature const& candidate) {
                return candidate.server_name == server_name && candidate.key_id == key_id;
            });
            if (found == source.end())
            {
                return std::nullopt;
            }
            auto const attached = events::attach_event_signature(
                merged, events::SigningKeyId{std::string{server_name}, key_id}, found->signature);
            if (attached.error != canonicaljson::CanonicalJsonError::none)
            {
                return std::nullopt;
            }
            auto parsed = canonicaljson::parse_lossless(attached.output);
            if (parsed.error != canonicaljson::ParseError::none)
            {
                return std::nullopt;
            }
            merged = std::move(parsed.value);
        }
        return merged;
    }

    // ADR-0287: checks the `event` of a send_join answer for a restricted join through
    // another resident, and returns this server's own join with the resident's co-signature
    // merged in, serialized, or the reason it was refused. The answer's event must be the join
    // this server signed (same reference-hash event ID) and name an authorising user who is
    // not a user of this server. Only its authorising-server signatures are taken, and they are
    // added to `own_signed_event`: the reference hash and the signatures are over the redacted
    // form, so a resident can change a field redaction drops (a display name) and keep both,
    // and the event stored is never the resident's copy. The combined event must verify: this
    // server's own signature and the authorising server's (rooms/v10.md 4.2.1, ADR-0171). A join
    // authorised by a server whose signature was not checked is never accepted.
    struct ResidentSignedJoin final
    {
        std::string json{};
        std::string refusal{};
        // The verified combined event `json` serializes.
        canonicaljson::Value value{};
    };

    [[nodiscard]] auto verify_resident_signed_join(HomeserverRuntime& runtime, canonicaljson::Object const& answer,
                                                   rooms::RoomVersionPolicy const& policy, std::string_view our_server,
                                                   std::string_view expected_event_id,
                                                   canonicaljson::Value const& own_signed_event) -> ResidentSignedJoin
    {
        auto const* event_value = object_member(answer, "event");
        if (event_value == nullptr || !std::holds_alternative<canonicaljson::Object>(event_value->storage()))
        {
            return {{}, "send_join answer carries no signed join event"};
        }
        auto const& event = std::get<canonicaljson::Object>(event_value->storage());
        auto const id = events::make_reference_hash_event_id(*event_value, policy);
        if (!id.error.empty() || id.event_id != expected_event_id)
        {
            return {{}, "the resident changed the join event"};
        }
        // The reference hash covers the authorising user, so the resident's copy and this server's own
        // name the same one; read it from the copy that is kept.
        auto const* own_event = std::get_if<canonicaljson::Object>(&own_signed_event.storage());
        auto const* content = own_event == nullptr ? object_member_as_object(event, "content")
                                                   : object_member_as_object(*own_event, "content");
        auto const* authoriser =
            content == nullptr ? nullptr : string_member(*content, "join_authorised_via_users_server");
        if (authoriser == nullptr || sender_domain_from_user_id(*authoriser) == our_server ||
            sender_domain_from_user_id(*authoriser).empty())
        {
            return {{}, "the join names no authorising user of another server"};
        }
        auto const authorising_server = std::string{sender_domain_from_user_id(*authoriser)};
        auto const resident_copy = events::parse_event_envelope(*event_value);
        if (!resident_copy.error.empty())
        {
            return {{}, "the resident's join event could not be read"};
        }
        auto const authorising_key_ids =
            federation::signature_key_ids_for_server(resident_copy.event.signatures, authorising_server);
        if (authorising_key_ids.empty())
        {
            return {{}, "the join carries no signature of its authorising server"};
        }
        auto const combined = with_server_signatures(own_signed_event, resident_copy.event.signatures,
                                                     authorising_server, authorising_key_ids);
        if (!combined.has_value())
        {
            return {{}, "the authorising server's signatures could not be added to the join"};
        }
        auto const verified =
            filter_verified_send_join_events(runtime, canonicaljson::Array{*combined}, policy, our_server);
        if (verified.size() != 1U)
        {
            return {{}, "the join's signatures did not verify"};
        }
        auto serialized = canonicaljson::serialize_canonical(verified.front());
        if (serialized.error != canonicaljson::CanonicalJsonError::none)
        {
            return {{}, "the signed join event could not be serialized"};
        }
        return {std::move(serialized.output), {}, verified.front()};
    }

    [[nodiscard]] auto federated_join_failure(std::string reason, std::uint16_t status) -> FederatedJoinOutcome
    {
        auto outcome = FederatedJoinOutcome{};
        outcome.failure = make_operation_result(false, {}, std::move(reason), status);
        return outcome;
    }

    // Runs the whole federated join — make_join race, sign, send_join, signature
    // verification of the returned state — with `runtime.mutex` RELEASED.
    //
    // This is a function rather than a block inside `join_room` for one reason:
    // the scope boundary IS the lock boundary. Nine of the values produced here
    // are consumed after the re-lock, and leaving them as declarations inside a
    // released region meant either hoisting them above the release (stripping
    // `const` from nine initialisations in a 1000-line function) or trusting a
    // hand-written `unlock()`/`lock()` pair to bracket them. Returning them makes
    // the released region something the compiler enforces the shape of.
    //
    // Everything this needs from runtime state is passed in, read under the lock
    // by the caller. `runtime` itself is still touched — `runtime.federation.config`
    // for timeouts, `runtime.orphan_futures_` under its own mutex, and the
    // outbound client — none of which is guarded by `runtime.mutex`.
    // One lease per canonical requested room. Refusing overlaps avoids a
    // failed join clearing another join's queue. The caller holds mutex when
    // constructing/taking the queue; cleanup also locks on exceptional exits.
    class PendingJoinLease final
    {
    public:
        PendingJoinLease(HomeserverRuntime& runtime, std::string_view room_id)
            : runtime_{runtime}
            , room_id_{room_id}
        {
            if (runtime_.pending_federated_joins.size() < runtime_.federation.config.pending_join_max_rooms)
            {
                active_ = runtime_.pending_federated_joins.try_emplace(room_id_).second;
            }
        }
        ~PendingJoinLease() noexcept
        {
            if (active_)
            {
                auto const lock = std::lock_guard{runtime_.mutex};
                runtime_.pending_federated_joins.erase(room_id_);
            }
        }
        PendingJoinLease(PendingJoinLease const&) = delete;
        auto operator=(PendingJoinLease const&) -> PendingJoinLease& = delete;
        [[nodiscard]] auto acquired() const noexcept -> bool
        {
            return active_;
        }
        [[nodiscard]] auto take_committed() -> std::vector<federation::InboundPduEnvelope>
        {
            auto pdus = std::move(runtime_.pending_federated_joins.at(room_id_).pdus);
            runtime_.pending_federated_joins.erase(room_id_);
            active_ = false;
            return pdus;
        }

    private:
        HomeserverRuntime& runtime_;
        std::string room_id_;
        bool active_{false};
    };

    // Tells the race state, on every way out of a worker, that the worker has ended: the last one releases the
    // request's client-outbound slot (C33).
    class MakeJoinWorkerExit final
    {
    public:
        explicit MakeJoinWorkerExit(MakeJoinRaceState& state) noexcept
            : state_{state}
        {
        }
        MakeJoinWorkerExit(MakeJoinWorkerExit const&) = delete;
        auto operator=(MakeJoinWorkerExit const&) -> MakeJoinWorkerExit& = delete;
        ~MakeJoinWorkerExit()
        {
            state_.worker_finished();
        }

    private:
        MakeJoinRaceState& state_;
    };

    [[nodiscard]] auto perform_federated_join(
        HomeserverRuntime& runtime, std::string_view room_id, std::string const& user_id, std::string const& our_server,
        std::vector<std::string> candidates, std::vector<std::string> const& supported_versions,
        std::optional<database::PersistentServerSigningKey> const& signing_key, std::string_view key_id,
        core::SecretBuffer secret_key, std::optional<database::PersistentProfile> const& profile,
        FederatedJoinPurpose purpose = FederatedJoinPurpose::enter_room,
        std::optional<http::InFlightBudget::Slot>* outbound_slot = nullptr) -> FederatedJoinOutcome
    {
        // Parallel make_join race: fire up to join_parallelism concurrent make_join
        // calls and return on the first successful response. Still-running losers are
        // moved into runtime.orphan_futures_ to complete in the background; they are
        // drained in HomeserverRuntime::~HomeserverRuntime() before any member is
        // destroyed. Completed orphans from a previous race are pruned first.
        {
            auto const orphan_lk = std::lock_guard{runtime.orphan_futures_mutex_};
            reap_completed_futures(runtime.orphan_futures_);
        }
        // join_timeout_seconds is the per-call budget for each make_join attempt.
        // Fall back to remote_timeout_seconds only when the join timeout is
        // unconfigured (zero), so the default 180s join budget is always preferred
        // over the 30s general federation timeout for large-room joins.
        static constexpr auto k_max_join_parallelism = std::ptrdiff_t{512};
        auto const parallelism = std::min(
            static_cast<std::ptrdiff_t>(std::max(std::uint32_t{1U}, runtime.federation.config.join_parallelism)),
            k_max_join_parallelism);
        auto const per_call_timeout = runtime.federation.config.join_timeout_seconds > 0U
                                          ? runtime.federation.config.join_timeout_seconds
                                          : runtime.federation.config.remote_timeout_seconds;
        // C33: at most `parallelism` worker threads for this join, each taking the next candidate when it has finished
        // the last, never one thread per candidate. The request's client-outbound slot moves into the race state below,
        // so the last worker to end releases it, not this request's return.
        auto const worker_total =
            MakeJoinRaceState::worker_count(static_cast<std::size_t>(parallelism), candidates.size());
        auto race_state = std::make_shared<MakeJoinRaceState>(candidates, worker_total);
        // C33: the whole race, and so every call a candidate makes, ends at the race deadline (when one is set).
        auto const race_bounds = std::optional<BoundedOutboundLimits>{
            runtime.federation.config.join_race_deadline_seconds > 0U
                ? std::optional<BoundedOutboundLimits>{BoundedOutboundLimits{
                      OutboundDeadline{runtime.federation.config.join_race_deadline_seconds},
                      std::chrono::seconds{runtime.client_outbound_proxy_policy.worker_margin_seconds}}}
                : std::nullopt};
        // Owned copies so tasks moved into orphan_futures_ are self-contained
        // and do not dangle on stack variables in join_room.
        auto room_id_copy = std::string{room_id};
        auto user_id_copy = std::string{user_id};
        auto our_server_copy = std::string{our_server};
        auto key_id_copy = std::string{key_id};
        auto sv_copy = supported_versions;
        auto race_futures = std::vector<std::future<void>>{};
        race_futures.reserve(worker_total);
        for (auto worker = std::size_t{0U}; worker < worker_total; ++worker)
        {
            // Each worker needs its own owned copy of the signing key so orphan
            // futures do not dangle on the parameter span.
            auto secret_key_copy = core::SecretBuffer{secret_key.bytes()};
            race_futures.push_back(
                std::async(std::launch::async, [&runtime, race_state, room_id_copy, user_id_copy, our_server_copy,
                                                key_id_copy, secret_key = std::move(secret_key_copy), sv_copy,
                                                per_call_timeout, race_bounds]() {
                    // Whatever ends this worker, the last one releases the request's slot.
                    auto const exit = MakeJoinWorkerExit{*race_state};
                    while (auto cand = race_state->next_candidate())
                    {
                        log_diagnostic("room.join.remote.make_join", {
                                                                         {"actor",         user_id_copy, false},
                                                                         {"room_id",       room_id_copy, false},
                                                                         {"remote_server", *cand,        false}
                        });
                        auto tx = federation::make_outbound_make_membership(federation::FederationEndpoint::make_join,
                                                                            *cand, our_server_copy, room_id_copy,
                                                                            user_id_copy, sv_copy);
                        auto call = perform_outbound_call(runtime, OutboundAnswerTrust::unverified, room_id_copy, tx,
                                                          key_id_copy, core::SecretBuffer{secret_key.bytes()},
                                                          "room.join.remote.make_join_failed", per_call_timeout,
                                                          membership_template_max_response_bytes, race_bounds);
                        race_state->record_answer(*cand, call.ok, std::move(call.body), call.remote_status == 403U);
                    }
                }));
        }
        if (outbound_slot != nullptr)
        {
            race_state->adopt_slot(std::move(*outbound_slot));
            outbound_slot->reset();
        }
        // Block until first winner, all candidates exhausted, or the overall race
        // deadline elapses — whichever comes first. The deadline bounds the WHOLE
        // race (unlike per_call_timeout, which bounds one candidate), so a large via
        // list cannot grind past what a calling client's own HTTP timeout allows.
        // A deadline of 0 (unconfigured) preserves the old unbounded wait.
        auto race_deadline_exceeded = false;
        {
            auto lk = std::unique_lock{race_state->mtx};
            auto const predicate = [&race_state] {
                return race_state->winner.has_value() || race_state->remaining <= 0;
            };
            if (runtime.federation.config.join_race_deadline_seconds > 0U)
            {
                auto const deadline = std::chrono::steady_clock::now() +
                                      std::chrono::seconds(runtime.federation.config.join_race_deadline_seconds);
                race_deadline_exceeded = !race_state->cv.wait_until(lk, deadline, predicate);
            }
            else
            {
                race_state->cv.wait(lk, predicate);
            }
        }
        // C33: from here no candidate that has not made its call makes one.
        race_state->cancel();
        // Park still-running losers in orphan_futures_; discard completed ones.
        {
            auto orphan_lk = std::lock_guard{runtime.orphan_futures_mutex_};
            for (auto& f : race_futures)
            {
                if (!f.valid())
                {
                    continue;
                }
                if (f.wait_for(std::chrono::seconds{0}) == std::future_status::ready)
                {
                    // Completed loser — let the future destructor clean up silently.
                }
                else
                {
                    runtime.orphan_futures_.push_back(std::move(f));
                }
            }
        }
        if (!race_state->winner.has_value())
        {
            // Copied under the race mutex: a losing candidate can still be running
            // and write either field.
            auto const [last_error, refused] = [&race_state] {
                auto const lk = std::lock_guard{race_state->mtx};
                return std::pair{race_state->last_error, race_state->refused};
            }();
            // Spec (CS API, POST /join, 403): "You do not have permission to join the
            // room". A resident's refusal is that answer; anything else is upstream.
            auto const status = refused ? std::uint16_t{403U} : std::uint16_t{502U};
            auto const reason =
                race_deadline_exceeded ? "make_join race deadline exceeded" : "make_join failed via all candidates";
            log_diagnostic("room.join.rejected",
                           {
                               {"actor",   user_id_copy,           false},
                               {"room_id", room_id_copy,           false},
                               {"status",  std::to_string(status), false},
                               {"reason",  reason,                 false}
            },
                           observability::LogEventSeverity::warning);
            auto const message = race_deadline_exceeded && !refused
                                     ? "make_join failed: race deadline exceeded before any candidate succeeded"
                                     : "make_join failed: " + last_error;
            return federated_join_failure(message, status);
        }
        auto [remote_server, make_body] = std::move(*race_state->winner);
        // Parse the make_join response and validate the template before we sign it.
        auto const make_response = canonicaljson::parse_lossless(make_body);
        auto const* make_obj = std::get_if<canonicaljson::Object>(&make_response.value.storage());
        if (make_obj == nullptr)
        {
            log_diagnostic("room.join.rejected", {
                                                     {"actor",   user_id,                    false},
                                                     {"room_id", std::string{room_id},       false},
                                                     {"status",  "502",                      false},
                                                     {"reason",  "malformed make_join body", false}
            });
            return federated_join_failure("malformed make_join response", 502U);
        }
        auto const validated = validate_make_join_event(room_id, user_id, *make_obj);
        if (!validated.ok)
        {
            log_diagnostic("room.join.rejected", {
                                                     {"actor",   user_id,              false},
                                                     {"room_id", std::string{room_id}, false},
                                                     {"status",  "502",                false},
                                                     {"reason",  validated.reason,     false}
            });
            return federated_join_failure(validated.reason, 502U);
        }
        auto const room_version = validated.room_version;
        auto const* policy = rooms::find_room_version_policy(room_version);
        if (policy == nullptr)
        {
            log_diagnostic("room.join.rejected", {
                                                     {"actor",   user_id,                       false},
                                                     {"room_id", std::string{room_id},          false},
                                                     {"status",  "500",                         false},
                                                     {"reason",  "room version policy missing", false}
            });
            return federated_join_failure("room version policy missing", 500U);
        }
        auto event_object = validated.event;
        claim_membership_event_template(event_object, our_server, event_clock_now_ms(runtime));
        // The resident server's template carries the membership; the joining user's display name
        // and avatar URL are this server's to add, before the content hash and signature. Any the
        // template supplies are dropped first: add_member_profile leaves an unset local field out,
        // so a resident value would otherwise be signed as this user's profile.
        // C18: and so is anything else it put in the content, so the content is rebuilt from an allow-list.
        if (auto const refusal = restrict_membership_template_content(event_object, our_server, true); !refusal.empty())
        {
            return federated_join_failure("make_join template refused: " + refusal, 502U);
        }
        if (auto const* template_content = object_member_as_object(event_object, "content");
            template_content != nullptr)
        {
            auto content = *template_content;
            add_member_profile(content, profile);
            replace_or_add_member(event_object, "content", canonicaljson::Value{std::move(content)});
        }
        // The event as this server would sign and store it is held to the room version's event format before it is
        // hashed (F-13): the resident chose the template, and the signature would make it the user's own event.
        if (auto const violation = membership_template_format_refusal(event_object, *policy); !violation.empty())
        {
            log_diagnostic("room.join.rejected", {
                                                     {"actor",   user_id,              false},
                                                     {"room_id", std::string{room_id}, false},
                                                     {"status",  "502",                false},
                                                     {"reason",  violation,            false}
            });
            return federated_join_failure("make_join template refused: " + violation, 502U);
        }
        // Compute and attach the content hash (hashes.sha256) before signing.
        // The Matrix spec requires every PDU to carry this field (room versions >= 2).
        // Without it, Synapse rejects send_join with:
        //   SynapseError: 400 - Malformed 'hashes': <class 'NoneType'>
        auto const content_hash = events::make_content_hash(canonicaljson::Value{event_object});
        if (!content_hash.error.empty())
        {
            log_diagnostic("room.join.rejected", {
                                                     {"actor",   user_id,              false},
                                                     {"room_id", std::string{room_id}, false},
                                                     {"status",  "500",                false},
                                                     {"reason",  content_hash.error,   false}
            });
            return federated_join_failure("join event content hash failed", 500U);
        }
        auto hashes_obj = canonicaljson::Object{};
        hashes_obj.push_back(canonicaljson::make_member("sha256", canonicaljson::Value{content_hash.sha256}));
        replace_or_add_member(event_object, "hashes", canonicaljson::Value{std::move(hashes_obj)});

        auto event_to_sign = canonicaljson::Value{event_object};
        // Sign the event with our server's signing key.
        // signing_key is guaranteed non-empty here: perform_sync_outbound_call
        // validates secret_key size before executing make_join, so a failed key
        // means make_ok was false and we returned 502 above.
        if (runtime.crypto_provider == nullptr)
        {
            log_diagnostic("room.join.rejected", {
                                                     {"actor",   user_id,                                 false},
                                                     {"room_id", std::string{room_id},                    false},
                                                     {"status",  "500",                                   false},
                                                     {"reason",  "server signing provider not available", false}
            });
            return federated_join_failure("server signing provider not available", 500U);
        }
        auto key_store = RuntimeSigningKeyStore{our_server, signing_key.value()};
        auto signed_event =
            events::sign_event_for_server(event_to_sign, *policy, key_store, *runtime.crypto_provider, our_server);
        if (!signed_event.error.empty())
        {
            log_diagnostic("room.join.rejected", {
                                                     {"actor",   user_id,              false},
                                                     {"room_id", std::string{room_id}, false},
                                                     {"status",  "500",                false},
                                                     {"reason",  signed_event.error,   false}
            });
            return federated_join_failure("event signing failed", 500U);
        }
        // Compute the event_id from the signed event (room v10+ uses
        // reference hash-based event IDs).
        auto const signed_value = canonicaljson::parse_lossless(signed_event.event_json);
        auto const event_id_result = events::make_reference_hash_event_id(signed_value.value, *policy);
        if (event_id_result.error.empty() && event_id_result.event_id.empty())
        {
            log_diagnostic("room.join.rejected", {
                                                     {"actor",   user_id,                       false},
                                                     {"room_id", std::string{room_id},          false},
                                                     {"status",  "500",                         false},
                                                     {"reason",  "event_id computation failed", false}
            });
            return federated_join_failure("event_id computation failed", 500U);
        }
        // Send the signed join event via send_join.
        auto send_join_tx = federation::make_outbound_send_membership(
            federation::FederationEndpoint::send_join, remote_server, our_server, room_id, event_id_result.event_id,
            signed_event.event_json);
        log_diagnostic("room.join.remote.send_join", {
                                                         {"actor",         user_id,                    false},
                                                         {"room_id",       std::string{room_id},       false},
                                                         {"remote_server", std::string{remote_server}, false},
                                                         {"event_id",      event_id_result.event_id,   false}
        });
        // send_join can return megabytes of room state for large rooms, so give it
        // the full join budget rather than the shorter remote_timeout used for key
        // and discovery calls.  Mirror the same fallback chain as make_join.
        auto const send_join_timeout = runtime.federation.config.join_timeout_seconds > 0U
                                           ? runtime.federation.config.join_timeout_seconds
                                           : runtime.federation.config.remote_timeout_seconds;
        auto send_join_call =
            perform_outbound_call(runtime, OutboundAnswerTrust::unverified, room_id, send_join_tx, key_id,
                                  std::move(secret_key), "room.join.remote.send_join_failed", send_join_timeout,
                                  runtime.federation.config.join_response_max_bytes, std::nullopt);
        auto const& send_body = send_join_call.body;
        if (!send_join_call.ok)
        {
            // As for make_join: the resident refusing the join event is a 403 to the client.
            auto const status = send_join_call.remote_status == 403U ? std::uint16_t{403U} : std::uint16_t{502U};
            log_diagnostic("room.join.rejected",
                           {
                               {"actor",   user_id,                false},
                               {"room_id", std::string{room_id},   false},
                               {"status",  std::to_string(status), false},
                               {"reason",  "send_join failed",     false}
            },
                           observability::LogEventSeverity::warning);
            return federated_join_failure("send_join failed: " + send_body, status);
        }
        // Parse the send_join response. The v2 send_join response is
        // ["200", { ... }] per MSC328; extract the inner object.
        auto send_response = canonicaljson::parse_lossless(send_body);
        auto const* send_obj = std::get_if<canonicaljson::Object>(&send_response.value.storage());
        // If wrapped in ["200", {...}], unwrap the array element.
        auto const* send_arr = std::get_if<canonicaljson::Array>(&send_response.value.storage());
        if (send_arr != nullptr && send_arr->size() >= 2U)
        {
            auto const* inner = std::get_if<canonicaljson::Object>(&(*send_arr)[1].storage());
            if (inner != nullptr)
            {
                send_obj = inner;
            }
        }
        if (send_obj == nullptr)
        {
            log_diagnostic("room.join.rejected", {
                                                     {"actor",   user_id,                        false},
                                                     {"room_id", std::string{room_id},           false},
                                                     {"status",  "502",                          false},
                                                     {"reason",  "malformed send_join response", false}
            });
            return federated_join_failure("malformed send_join response", 502U);
        }
        // The resident's co-signed copy of this server's join, verified; a refusal is logged here and answered 502 by
        // the caller. Shared by a join through another resident and a first restricted join (ADR-0745).
        auto const verify_resident_join = [&]() {
            auto resident_join = verify_resident_signed_join(runtime, *send_obj, *policy, our_server,
                                                             event_id_result.event_id, signed_value.value);
            if (!resident_join.refusal.empty())
            {
                log_diagnostic("room.join.rejected",
                               {
                                   {"actor",         user_id,               false},
                                   {"room_id",       std::string{room_id},  false},
                                   {"status",        "502",                 false},
                                   {"remote_server", remote_server,         false},
                                   {"reason",        resident_join.refusal, false}
                },
                               observability::LogEventSeverity::warning);
            }
            return resident_join;
        };
        if (purpose == FederatedJoinPurpose::join_through_resident)
        {
            auto resident_join = verify_resident_join();
            if (!resident_join.refusal.empty())
            {
                return federated_join_failure(resident_join.refusal, 502U);
            }
            auto outcome = FederatedJoinOutcome{};
            outcome.policy = *policy;
            outcome.remote_server = std::move(remote_server);
            outcome.signed_event = std::move(signed_event);
            outcome.signed_event_value = signed_value.value;
            outcome.event_id_result = event_id_result;
            outcome.resident_signed_event_json = std::move(resident_join.json);
            return outcome;
        }
        // ADR-0745: a join into a restricted room this server holds nothing of names an authorising user of the
        // resident's server, and the auth rules require that server's signature on the join (rooms/v10.md 4.2.1).
        // The resident adds it to the copy it returns as the answer's `event` (send_join v2, "event": "Required if
        // the room is restricted and the joining user is authorised by one of the conditions"). The co-signature is
        // taken exactly as for a join through another resident: only the authorising server's verified signatures
        // are merged into this server's own signed join, and the combined event must verify. That combined event is
        // the one the answer is authorised against and the one stored. A missing, altered or unverifiable copy is
        // refused: a join no checked signature authorises is never stored.
        auto join_signed_event = std::move(signed_event);
        auto join_value = signed_value.value;
        if (!join_authorising_user_of(signed_value.value).empty())
        {
            auto resident_join = verify_resident_join();
            if (!resident_join.refusal.empty())
            {
                return federated_join_failure(resident_join.refusal, 502U);
            }
            join_signed_event.event_json = std::move(resident_join.json);
            join_value = std::move(resident_join.value);
        }
        // ADR-0241: the whole state array — other members' m.room.member events
        // included — is verified here and persisted by join_room before the join
        // returns. The join event's after-state group is built from it, and the
        // auth rules judge every later event from an existing member against
        // that state, so no member may be left out of it. Signature verification
        // (network-bound key resolution) runs here, inside the released region,
        // so it never holds runtime.mutex.
        auto const state_arr_member = std::ranges::find_if(*send_obj, [](canonicaljson::ObjectMember const& m) {
            return m.key == "state";
        });
        auto const* state_arr = state_arr_member != send_obj->end()
                                    ? std::get_if<canonicaljson::Array>(&state_arr_member->value->storage())
                                    : nullptr;
        // FED-1 (ADR-0083): only the joined room's events go any further — an
        // entry naming any other room is dropped before key resolution. The
        // response's own `event` field is never read: the join event we store
        // is the one signed above from the validated make_join template.
        // Verify each event's signature before it enters the event graph
        // (src/federation/AGENTS.md rule 2) — resolves distinct sender-domain
        // signing keys with bounded parallelism rather than trusting the
        // resident server's response wholesale. Unverifiable events are
        // silently dropped, not persisted.
        auto verified_state =
            state_arr != nullptr
                ? filter_verified_send_join_events(
                      runtime, filter_send_join_events_for_room(*state_arr, room_id, *policy), *policy, our_server)
                : canonicaljson::Array{};
        // A room's version is the one its m.room.create declares; one without room_version is
        // room version 1 (ADR-0076). The make_join answer only names it. Joining under a version
        // the create event does not declare would let each component judge the room by a
        // different rule set, so refuse before anything is stored (security audit run-1).
        for (auto const& entry : verified_state)
        {
            auto const* event = std::get_if<canonicaljson::Object>(&entry.storage());
            auto const* type = event == nullptr ? nullptr : string_member(*event, "type");
            auto const* state_key = event == nullptr ? nullptr : string_member(*event, "state_key");
            if (type == nullptr || *type != "m.room.create" || state_key == nullptr || !state_key->empty())
            {
                continue;
            }
            if (auto const declared = declared_room_version(*event); declared != room_version)
            {
                log_diagnostic("room.join.rejected",
                               {
                                   {"actor",           user_id,                                      false},
                                   {"room_id",         std::string{room_id},                         false},
                                   {"status",          "502",                                        false},
                                   {"make_join",       room_version,                                 false},
                                   {"create_declares", declared,                                     false},
                                   {"reason",          "create event and make_join versions differ", false}
                },
                               observability::LogEventSeverity::warning);
                return federated_join_failure("the room's create event does not declare the make_join room version",
                                              502U);
            }
        }
        auto const auth_arr_member = std::ranges::find_if(*send_obj, [](canonicaljson::ObjectMember const& m) {
            return m.key == "auth_chain";
        });
        auto const* auth_arr = auth_arr_member != send_obj->end()
                                   ? std::get_if<canonicaljson::Array>(&auth_arr_member->value->storage())
                                   : nullptr;
        auto verified_auth_chain =
            auth_arr != nullptr
                ? filter_verified_send_join_events(
                      runtime, filter_send_join_events_for_room(*auth_arr, room_id, *policy), *policy, our_server)
                : canonicaljson::Array{};
        // Step 4 of the receipt checks, with runtime.mutex still released (F-45, ADR-0369).
        auto authorized_answer =
            authorize_send_join_answer(verified_state, verified_auth_chain, join_value, *policy, room_id);
        if (authorized_answer.dropped > 0U || !authorized_answer.refusal.empty())
        {
            log_diagnostic("room.join.answer_checked",
                           {
                               {"actor",         user_id,                                   false},
                               {"room_id",       std::string{room_id},                      false},
                               {"remote_server", remote_server,                             false},
                               {"dropped",       std::to_string(authorized_answer.dropped), false},
                               {"refusal",       authorized_answer.refusal,                 false}
            },
                           observability::LogEventSeverity::warning);
        }
        if (!authorized_answer.refusal.empty())
        {
            return federated_join_failure(authorized_answer.refusal, 502U);
        }
        verified_state = std::move(authorized_answer.state);
        verified_auth_chain = std::move(authorized_answer.auth_chain);

        auto outcome = FederatedJoinOutcome{};
        outcome.policy = *policy;
        outcome.remote_server = std::move(remote_server);
        outcome.signed_event = std::move(join_signed_event);
        outcome.signed_event_value = std::move(join_value);
        outcome.event_id_result = event_id_result;
        outcome.verified_state = std::move(verified_state);
        outcome.verified_auth_chain = std::move(verified_auth_chain);
        return outcome;
    }

    // A PDU parked during a join, rebuilt under the room's real version: its event ID is the one that version
    // derives, and every signature that version covers has been checked. Empty when it fails or no longer parses.
    // Called with runtime.mutex released: a signature check may fetch a key.
    [[nodiscard]] auto pending_pdu_under_room_version(HomeserverRuntime& runtime,
                                                      federation::InboundPduEnvelope const& pending,
                                                      rooms::RoomVersionPolicy const& policy,
                                                      std::string_view our_server)
        -> std::optional<federation::InboundPduEnvelope>
    {
        auto const parsed = canonicaljson::parse_lossless(pending.json);
        if (parsed.error != canonicaljson::ParseError::none ||
            filter_verified_send_join_events(runtime, canonicaljson::Array{parsed.value}, policy, our_server).empty())
        {
            return std::nullopt;
        }
        auto envelope = federation::rebuild_inbound_pdu_envelope(pending.json, policy.id, pending.origin);
        if (!envelope.has_value() || envelope->room_id != pending.room_id)
        {
            return std::nullopt;
        }
        envelope->room_version = std::string{policy.id};
        return envelope;
    }

    // The room versions a join advertises to a resident: every one this server implements
    // (rooms::RoomVersionPolicy.cpp is the single source of truth, pinned by
    // tests/conformance/test_room_version_table_conformance.cpp).
    [[nodiscard]] auto implemented_room_versions() -> std::vector<std::string>
    {
        auto versions = std::vector<std::string>{};
        for (auto const& policy : rooms::known_room_versions())
        {
            versions.emplace_back(policy.id);
        }
        return versions;
    }

    // ADR-0288: waits for the events of `room_id` that another thread is applying now, so
    // that a decision made next sees them. Ingestion applies a received event under the
    // room's stripe mutex and then `runtime.mutex`; this releases `runtime.mutex`, takes
    // and drops the stripe, and restores `runtime.mutex`, which is the order ingestion takes
    // them in. Anything read from runtime state before the call must be read again after it.
    auto wait_for_in_flight_room_events(HomeserverRuntime& runtime, RuntimeLock& guard, std::string_view room_id)
        -> void
    {
        auto const stripe = std::hash<std::string>{}(std::string{room_id}) % room_mutex_stripe_count;
        auto const released = RuntimeLockRelease{guard};
        // Taken and dropped: waits for any ingestion holding the stripe to finish.
        auto const barrier = std::lock_guard{runtime.room_stripe_mutexes[stripe]};
    }

    // True when `event_id` is stored in `room_id` as an accepted join of `user_id` and is the event
    // that gives `user_id` their joined membership there now. Call with `runtime.mutex` held.
    [[nodiscard]] auto join_event_made_member(HomeserverRuntime const& runtime, std::string_view room_id,
                                              std::string_view user_id, std::string_view event_id) -> bool
    {
        auto const& store = runtime.database.persistent_store;
        auto const stored = store.events.find(event_id);
        if (stored == store.events.end() || stored->room_id != room_id || stored->sender_user_id != user_id ||
            stored->status != "accepted")
        {
            return false;
        }
        auto const member_event_id = database::find_current_state_event_id(store, room_id, "m.room.member", user_id);
        if (!member_event_id.has_value() || *member_event_id != event_id)
        {
            return false;
        }
        return std::ranges::any_of(store.memberships, [&](database::PersistentMembership const& membership) {
            return membership.room_id == room_id && membership.user_id == user_id && membership.membership == "join";
        });
    }

    // ADR-0287. This server is resident in `room_id` and the restricted-join decision found
    // that `user_id` meets an allow condition but no user of this server can authorise the
    // join (server-server-api.md "Restricted rooms": M_UNABLE_TO_GRANT_JOIN, "the joining
    // server should try a different server"). Joins `user_id` through one of `candidates`
    // with make_join and send_join, and stores the resident's co-signed join as a received
    // event: the room's state is already here, so none of the answer's state is taken (see
    // `FederatedJoinPurpose`). The caller holds the MembershipExchangeClaim for the pair and
    // `runtime.mutex` through `guard`; the network exchange and the signature checks run with
    // it released.
    [[nodiscard]] auto join_through_other_resident(HomeserverRuntime& runtime, RuntimeLock& guard,
                                                   std::string_view room_id, std::string const& user_id,
                                                   std::vector<std::string> candidates,
                                                   std::optional<http::InFlightBudget::Slot>* outbound_slot = nullptr)
        -> OperationResult
    {
        auto const our_server = runtime.config.server().server_name;
        // The room's own version is the only one offered, so a template for any other is
        // not a template for this room.
        auto const room_version = stored_room_version(runtime.database.persistent_store, room_id);
        if (!room_version.has_value())
        {
            return make_operation_result(false, {}, "the room's version is unknown", 500U);
        }
        wire_federation_callbacks(runtime);
        if (!runtime.federation.pdu_sink)
        {
            return make_operation_result(false, {}, "federation is not available", 503U);
        }
        auto const signing_key = find_active_server_signing_key(runtime);
        auto const key_id = signing_key.has_value() ? signing_key->key_id : std::string{};
        auto secret_key = core::SecretBuffer{runtime.database.signing_secret_key.bytes()};
        auto const joining_profile = database::find_profile(runtime.database.persistent_store, user_id);
        auto joined = [&] {
            auto const released = RuntimeLockRelease{guard};
            return perform_federated_join(runtime, room_id, user_id, our_server, std::move(candidates),
                                          std::vector<std::string>{*room_version}, signing_key, key_id,
                                          std::move(secret_key), joining_profile,
                                          FederatedJoinPurpose::join_through_resident, outbound_slot);
        }();
        if (joined.failure.has_value())
        {
            return *joined.failure;
        }
        if (joined.policy.id != *room_version)
        {
            return make_operation_result(false, {}, "the resident's template is for another room version", 502U);
        }
        auto envelope = federation::parse_inbound_pdu_envelope(joined.resident_signed_event_json, joined.policy.id);
        if (!envelope.has_value() || envelope->room_id != room_id || envelope->sender != user_id ||
            envelope->event_type != "m.room.member" || envelope->state_key != std::optional<std::string>{user_id})
        {
            return make_operation_result(false, {}, "the resident's signed join is not this user's join", 502U);
        }
        envelope->origin = joined.remote_server;
        // The sink takes the room stripe and then runtime.mutex itself: drop every level
        // this thread holds, as the pending-PDU drain after an ordinary join does.
        auto const ingested = [&] {
            auto const released = RuntimeLockRelease{guard};
            return runtime.federation.pdu_sink(*envelope);
        }();
        // The same join may have reached this server first, in a transaction from the resident sent
        // while the send_join was being answered (server-server-api.md "Joining Rooms"): the event ID
        // is the same whatever the signatures, so the sink answers `already_stored`. That is the join
        // done only if that event is the one that made the user a member; a copy stored any other way
        // (an outlier, soft-failed, rejected) did not, and the join has not happened. An `accepted` join
        // is checked the same way: accepted means it passed the auth rules, but state resolution across
        // the room's forward extremities can still leave another member event for the user current.
        auto const stored_or_accepted = ingested.status == federation::PduIngestionStatus::accepted ||
                                        ingested.status == federation::PduIngestionStatus::already_stored;
        if (!stored_or_accepted || !join_event_made_member(runtime, room_id, user_id, joined.event_id_result.event_id))
        {
            auto const refused = ingested.status == federation::PduIngestionStatus::rejected_auth ||
                                 ingested.status == federation::PduIngestionStatus::soft_failed ||
                                 ingested.status == federation::PduIngestionStatus::rejected_invalid;
            log_diagnostic("room.join.rejected",
                           {
                               {"actor",         user_id,                 false},
                               {"room_id",       std::string{room_id},    false},
                               {"status",        refused ? "403" : "502", false},
                               {"remote_server", joined.remote_server,    false},
                               {"reason",        ingested.reason,         false}
            },
                           observability::LogEventSeverity::warning);
            return make_operation_result(false, {}, "the resident's join was not applied: " + ingested.reason,
                                         refused ? 403U : 502U);
        }
        append_local_audit(runtime.database, observability::AuditCategory::admin, "room.joined_via_other_resident",
                           user_id, room_id, "joined through " + joined.remote_server);
        log_diagnostic("room.join.accepted_via_other_resident",
                       {
                           {"actor",         user_id,                         false},
                           {"room_id",       std::string{room_id},            false},
                           {"remote_server", joined.remote_server,            false},
                           {"event_id",      joined.event_id_result.event_id, false}
        },
                       observability::LogEventSeverity::info);
        notify_room_changed(runtime, room_id);
        return make_operation_result(true, std::string{room_id});
    }

} // namespace

[[nodiscard]] auto join_room(HomeserverRuntime& runtime, std::string_view access_token, std::string_view room_id,
                             std::vector<std::string> const& via_servers,
                             canonicaljson::Object const* third_party_signed, std::string_view client_key)
    -> OperationResult
{
    auto guard = RuntimeLock{runtime.mutex};
    log_diagnostic("room.join.started", {
                                            {"room_id",          std::string{room_id},                    false},
                                            {"has_access_token", access_token.empty() ? "false" : "true", false}
    });
    auto const user_id = authenticated_user(runtime, access_token);
    if (!user_id.has_value())
    {
        log_diagnostic("room.join.rejected", {
                                                 {"room_id", std::string{room_id}, false},
                                                 {"status",  "401",                false},
                                                 {"reason",  "unauthenticated",    false}
        });
        return make_operation_result(false, {}, "unauthenticated", 401U);
    }
    if (auto refused = membership_exchange_refusal(runtime, room_id, *user_id); refused.has_value())
    {
        return *refused;
    }

    auto* room = find_room(runtime.database, room_id);
    // Guard: if the room is known in-memory but the user's PERSISTENT membership is
    // not "join" (e.g. it was downgraded to "invite" by a stale federated invite
    // while LocalRoom.members still listed them as joined), the in-memory state is
    // stale. Erase the invalid record so the federation join path below can
    // re-establish membership correctly on both the local server and the remote.
    //
    // This handles the following failure mode:
    //   1. User successfully joins a remote room via federation → membership="join"
    //   2. Remote server re-sends an invite (state divergence) → membership overwritten
    //      to "invite" in the persistent store (Bug: invite handler didn't guard this)
    //   3. User clicks Join → find_room returns the stale LocalRoom → room_has_member
    //      returns true → already_member fires → returns 200 OK without federating
    //   4. delete_invite removes invite metadata → persistent membership stays "invite"
    //   5. Sync: room suppressed from rooms.join; shows as empty invite → loop
    {
        auto const our_server_name = runtime.config.server().server_name;
        auto const room_domain = server_name_from_room_id(room_id);
        auto const is_remote_room = !room_domain.empty() && room_domain != our_server_name;
        if (room != nullptr && is_remote_room && room_has_member(*room, *user_id))
        {
            auto const mem_it = std::ranges::find_if(runtime.database.persistent_store.memberships,
                                                     [&](database::PersistentMembership const& m) {
                                                         return m.room_id == room_id && m.user_id == *user_id;
                                                     });
            auto const persistently_joined =
                mem_it != runtime.database.persistent_store.memberships.end() && mem_it->membership == "join";
            if (!persistently_joined)
            {
                // Remove the stale in-memory record. The persistent event store
                // retains all previously stored events, so the federation join
                // path below can populate a fresh LocalRoom on success.
                auto erase_it = std::ranges::find_if(runtime.database.rooms, [room_id](LocalRoom const& r) {
                    return r.room_id == room_id;
                });
                if (erase_it != runtime.database.rooms.end())
                {
                    runtime.database.rooms.erase(erase_it);
                }
                log_diagnostic("room.join.stale_membership_cleared",
                               {
                                   {"actor",   *user_id,             false},
                                   {"room_id", std::string{room_id}, false},
                                   {"reason",
                                    "in-memory join but persistent membership is not join; "
                                    "retrying federation",           false}
                });
                room = nullptr; // triggers the federation join path below
            }
        }
    }
    // ADR-0244: a room this server still knows, but which none of its users is joined
    // to, is a room this server is not in. Its state stops at our last user's leave, so
    // a join composed here would be judged by nobody who holds the room's current
    // state; it goes through a resident, which decides it (Server-Server API, "Joining
    // Rooms"). The exception is a room created here that no server is known to be in
    // any more: there is no resident to ask and no newer state than ours, so the join
    // is composed here and the auth rules judge it. A room created elsewhere is never
    // composed here: what this server last held of it may be stale.
    // Joining Rooms: "the joining server may use the server that sent the invite as a candidate". A client
    // that accepts an invite names no server (Complement's plain `POST /join/{roomId}`), and a version 12
    // room ID has no domain to fall back on, so the inviter's server is the via when none is named.
    auto joining_via = via_servers;
    if (joining_via.empty())
    {
        if (auto inviter = invite_sender_server(runtime, room_id, *user_id); !inviter.empty())
        {
            joining_via.push_back(std::move(inviter));
            // Kept as a fallback behind the inviter, as it was before the inviter was a candidate.
            if (auto const domain = std::string{server_name_from_room_id(room_id)}; !domain.empty())
            {
                joining_via.push_back(domain);
            }
        }
    }
    auto const no_resident_known = [&] {
        auto const our_server = runtime.config.server().server_name;
        return join_candidate_servers(joining_via, room_id, our_server).empty() &&
               last_known_resident_servers(runtime, room_id).empty();
    };
    if (room != nullptr && !this_server_is_in_room(runtime, room_id) &&
        !(no_resident_known() && room_created_here(runtime, room_id)))
    {
        auto const erase_it = std::ranges::find_if(runtime.database.rooms, [room_id](LocalRoom const& r) {
            return r.room_id == room_id;
        });
        if (erase_it != runtime.database.rooms.end())
        {
            runtime.database.rooms.erase(erase_it);
        }
        log_diagnostic("room.join.not_resident",
                       {
                           {"actor",   *user_id,             false},
                           {"room_id", std::string{room_id}, false}
        });
        room = nullptr; // triggers the federation join path below
    }
    if (room == nullptr)
    {
        if (third_party_signed != nullptr)
        {
            log_diagnostic("room.join.rejected",
                           {
                               {"actor",   *user_id,                                           false},
                               {"room_id", std::string{room_id},                               false},
                               {"status",  "403",                                              false},
                               {"reason",  "third-party join via federation is not supported", false}
            });
            return make_operation_result(false, {}, "third-party join via federation is not supported", 403U);
        }
        // Remote room: attempt make_join → sign → send_join. The candidate resident
        // servers come from the join endpoint's via/server_name parameters, plus the
        // room ID's domain for room versions < 12 (v12 IDs are domain-less, MSC4291).
        auto const our_server = runtime.config.server().server_name;
        auto candidates = join_candidate_servers(joining_via, room_id, our_server);
        if (candidates.empty())
        {
            // A room this server has left, named with no other server: the residents
            // of the state it last held (ADR-0244).
            candidates = last_known_resident_servers(runtime, room_id);
        }
        if (candidates.empty())
        {
            log_diagnostic("room.join.rejected", {
                                                     {"actor",   *user_id,                                    false},
                                                     {"room_id", std::string{room_id},                        false},
                                                     {"status",  "404",                                       false},
                                                     {"reason",  "no resident server (via required for v12)", false}
            });
            return make_operation_result(false, {}, "unknown room: no resident server to join via", 404U);
        }
        // Cap the candidate count before spawning any make_join probes: every
        // candidate gets an OS thread immediately (std::launch::async), only
        // throttled to RUN by join_parallelism, not to spawn — an unbounded via
        // list would otherwise mean unbounded upfront thread creation.
        if (candidates.size() > runtime.federation.config.join_max_candidates)
        {
            log_diagnostic(
                "room.join.candidates_truncated",
                {
                    {"actor",           *user_id,                                                      false},
                    {"room_id",         std::string{room_id},                                          false},
                    {"candidate_count", std::to_string(candidates.size()),                             false},
                    {"max_candidates",  std::to_string(runtime.federation.config.join_max_candidates), false}
            });
            candidates = cap_join_candidates(std::move(candidates), runtime.federation.config.join_max_candidates);
        }
        wire_federation_callbacks(runtime);
        // Advertise every room version this server actually implements (v3-v12;
        // v1 and v2 are not supported, ADR-0076). rooms::RoomVersionPolicy.cpp
        // is the single source of truth, pinned by
        // tests/conformance/test_room_version_table_conformance.cpp. A resident server picks
        // a room's actual version from this list and replies 400
        // M_INCOMPATIBLE_ROOM_VERSION if none match — so a hardcoded {"10","11","12"}
        // here made every join fail against any room not on those three versions,
        // even though the rest of the join pipeline (validate_make_join_event,
        // sign_event_for_server, make_reference_hash_event_id) already handles
        // whatever version the response reports via find_room_version_policy.
        auto const supported_versions = implemented_room_versions();
        // Best-effort: load the key_id from the persistent store. If no usable key
        // record exists, perform_sync_outbound_call fails with "server signing key not
        // initialized", which join_room surfaces as 502 — the correct status for an
        // upstream federation failure. The signing secret is copied into an owned
        // mlocked SecretBuffer while we still hold runtime.mutex, then moved into the
        // outbound calls; the workers release runtime.mutex before signing so the
        // copy protects them from the runtime key being rotated underneath them.
        auto const signing_key = find_active_server_signing_key(runtime);
        auto const key_id = signing_key.has_value() ? signing_key->key_id : std::string{};
        auto secret_key = core::SecretBuffer{runtime.database.signing_secret_key.bytes()};
        // The whole federated join — make_join race, sign, send_join, and
        // signature verification of the state it returns — runs with
        // runtime.mutex released. RuntimeLockRelease drops every level this
        // thread holds, so a caller that reached join_room while already
        // holding the mutex (the client-server dispatcher, the local router)
        // does not leave it locked across the round trip; the destructor
        // restores exactly what it released, on the throwing path too.
        // Read under the lock: the profile goes into the join event the released region signs.
        auto const joining_profile = database::find_profile(runtime.database.persistent_store, *user_id);
        // Releasing the mutex frees it, not this request's thread: the exchange holds a slot until it returns.
        auto outbound_slot = admit_client_outbound_proxy(runtime, std::string{client_key});
        if (!outbound_slot.has_value())
        {
            return client_outbound_limit_result(runtime);
        }
        auto pending_join = PendingJoinLease{runtime, room_id};
        if (!pending_join.acquired())
        {
            return make_operation_result(false, {}, "outbound join already active or capacity exhausted", 429U);
        }
        auto const exchange = MembershipExchangeClaim{runtime, room_id, *user_id};
        auto joined = [&] {
            auto const released = RuntimeLockRelease{guard};
            return perform_federated_join(runtime, room_id, *user_id, our_server, std::move(candidates),
                                          supported_versions, signing_key, key_id, std::move(secret_key),
                                          joining_profile, FederatedJoinPurpose::enter_room, &outbound_slot);
        }();
        if (joined.failure.has_value())
        {
            return *joined.failure;
        }
        auto const& policy = joined.policy;
        auto const& remote_server = joined.remote_server;
        auto const& signed_event = joined.signed_event;
        auto const& signed_event_value = joined.signed_event_value;
        auto const& event_id_result = joined.event_id_result;
        auto const& verified_state = joined.verified_state;
        auto const& verified_auth_chain = joined.verified_auth_chain;
        // Persist the room locally with the joined user as a member.
        // State events from the remote response are persisted to the
        // database so the room has enough state for auth checks.
        auto joined_members = std::vector<std::string>{*user_id};
        // ingest_send_join_state correctly handles events with empty state_key
        // (m.room.encryption, m.room.create, m.room.power_levels, etc.) by
        // checking the raw JSON for the presence of the "state_key" field
        // rather than its emptiness.
        auto send_join_state = ingest_send_join_state(runtime, room_id, verified_state, policy);
        // Never open/drain admission on an incomplete or failed initial state
        // commit. The verified snapshot must contain create and every verified
        // state entry must have been persisted by the bootstrap writer.
        auto const recorded_create = std::ranges::any_of(send_join_state.state_entries, [](auto const& entry) {
            return entry.event_type == "m.room.create" && entry.state_key.empty();
        });
        if (send_join_state.recorded_state_events != verified_state.size() || !recorded_create)
        {
            // Complement run 10 (F14) saw this 500 under load with nothing logged.
            // A failed commit records nothing (and sqlite_store logs why); a short
            // count with a commit is an entry the writer could not keep.
            log_diagnostic("room.join.rejected",
                           {
                               {"actor",           *user_id,                                              false},
                               {"room_id",         std::string{room_id},                                  false},
                               {"status",          "500",                                                 false},
                               {"reason",          "initial join state persistence failed",               false},
                               {"verified_state",  std::to_string(verified_state.size()),                 false},
                               {"recorded_state",  std::to_string(send_join_state.recorded_state_events), false},
                               {"recorded_create", recorded_create ? "true" : "false",                    false}
            },
                           observability::LogEventSeverity::warning);
            return make_operation_result(false, {}, "initial join state persistence failed", 500U);
        }
        for (auto const& m : send_join_state.joined_members)
        {
            append_unique_member(joined_members, m);
        }
        // Persist auth chain events for auth-rule resolution. Signatures were
        // already verified inside perform_federated_join, with runtime.mutex
        // released.
        auto auth_chain_rows = std::vector<database::PersistentEvent>{};
        // Each ordering is reserved for the whole of the released commit below (ADR-0247): no sync position passes
        // the oldest until its row is in memory. Destroyed with the lock held.
        auto reserved_orderings = std::deque<PendingStreamOrdering>{};
        // One block of orderings, one persisted watermark, for the whole chain: `allocate_stream_ordering` per event
        // was one backend commit each. An ordering the filters leave unused is a gap, as a failed event leaves one.
        auto const first_auth_ordering = allocate_stream_orderings(runtime.database, verified_auth_chain.size());
        auto auth_orderings_used = std::uint64_t{0U};
        for (auto const& auth_entry : verified_auth_chain)
        {
            if (send_join_event_room_id(auth_entry, policy) != room_id)
            {
                continue; // FED-1: already filtered; kept at the writer as well
            }
            auto const serialized = canonicaljson::serialize_canonical(events::without_unsigned(auth_entry));
            if (serialized.error == canonicaljson::CanonicalJsonError::none)
            {
                auto const parsed = events::parse_event_envelope(auth_entry);
                if (parsed.error.empty())
                {
                    auto const* entry_obj = std::get_if<canonicaljson::Object>(&auth_entry.storage());
                    auto event_id = std::string{};
                    if (entry_obj != nullptr)
                    {
                        if (policy.event_id_format == rooms::EventIdFormat::reference_hash)
                        {
                            auto const eid = events::make_reference_hash_event_id(auth_entry, policy);
                            event_id = eid.event_id;
                        }
                        else
                        {
                            auto const* id_field = json_string_member(*entry_obj, "event_id");
                            if (id_field != nullptr)
                            {
                                event_id = *id_field;
                            }
                        }
                    }
                    auto depth = std::uint64_t{0U};
                    if (entry_obj != nullptr)
                    {
                        if (auto const* d = json_integer_member(*entry_obj, "depth"); d != nullptr && *d >= 0)
                        {
                            depth = static_cast<std::uint64_t>(*d);
                        }
                    }
                    auto prev_ids = std::vector<std::string>{};
                    auto auth_ids = std::vector<std::string>{};
                    if (entry_obj != nullptr)
                    {
                        if (auto const* pv = json_object_member(*entry_obj, "prev_events"); pv != nullptr)
                        {
                            prev_ids = json_string_array(*pv);
                        }
                        if (auto const* av = json_object_member(*entry_obj, "auth_events"); av != nullptr)
                        {
                            auth_ids = json_string_array(*av);
                        }
                    }
                    auto const stream_ordering = first_auth_ordering + auth_orderings_used++;
                    reserved_orderings.emplace_back(runtime.database, stream_ordering);
                    auto pe = database::PersistentEvent{};
                    pe.event_id = event_id;
                    pe.room_id = std::string{room_id};
                    pe.sender_user_id = parsed.event.sender;
                    pe.json = serialized.output;
                    pe.depth = depth;
                    pe.stream_ordering = stream_ordering;
                    pe.prev_event_ids = std::move(prev_ids);
                    pe.auth_event_ids = std::move(auth_ids);
                    pe.signatures = parsed.event.signatures;
                    // ADR-0064 phase B1: auth-chain events are historical
                    // ancestors kept for auth-rule resolution, not part of
                    // our timeline — outlier, same reasoning as
                    // ingest_send_join_state's critical-state events above,
                    // except these do NOT contribute to the join's snapshot
                    // (the auth chain can include state later superseded,
                    // unlike the state array, which is the room's state as
                    // of just before the join).
                    //
                    // FED-1 (ADR-0083): and so they are never applied as
                    // current state either — no current_state row, even for
                    // a state event (the same rule ADR-0070 applies to other
                    // auth-only outliers). The room's current state comes
                    // from the `state` snapshot above.
                    pe.status = "outlier";
                    auth_chain_rows.push_back(std::move(pe));
                }
            }
        }
        // C03 (ADR-0714): every auth-chain event goes in one transaction, written with runtime.mutex released. The rows
        // are prepared here, with the lock held, and applied here again; the commit reads no store state. The events
        // write their own rows only (no current_state, no membership), and this room is not held: the outbound join
        // lease defers its PDUs and refuses an overlapping join, and `exchange` is this user's claim.
        auto auth_chain_batch =
            database::prepare_outlier_events_batch(runtime.database.persistent_store, std::move(auth_chain_rows));
        if (!auth_chain_batch.has_value())
        {
            return make_operation_result(false, {}, "join auth-chain persistence failed", 500U);
        }
        auto const auth_chain_committed = [&] {
            auto const released = RuntimeLockRelease{guard};
            return database::commit_prepared_outlier_batch(runtime.database.persistent_store, *auth_chain_batch);
        }();
        if (!auth_chain_committed)
        {
            return make_operation_result(false, {}, "join auth-chain persistence failed", 500U);
        }
        database::apply_prepared_outlier_batch(runtime.database.persistent_store, *auth_chain_batch);
        reserved_orderings.clear();
        auto const room_known = std::ranges::any_of(runtime.database.persistent_store.rooms,
                                                    [&](database::PersistentRoom const& persistent_room) {
                                                        return persistent_room.room_id == room_id;
                                                    });
        if (!room_known && !database::store_room(runtime.database.persistent_store, {std::string{room_id}, *user_id}))
        {
            log_diagnostic("room.join.rejected", {
                                                     {"actor",   *user_id,                  false},
                                                     {"room_id", std::string{room_id},      false},
                                                     {"status",  "500",                     false},
                                                     {"reason",  "room persistence failed", false}
            });
            return make_operation_result(false, {}, "room persistence failed", 500U);
        }
        // Create the local room record and persist the membership.
        // Allocate a stream ordering for the local join event first so it is
        // contiguous with the membership row.
        auto const membership_stream = allocate_stream_ordering(runtime.database);

        // Persist the local user's join event in the event store and update the
        // m.room.member current_state entry to point to it.
        //
        // Without this, current_state still points to the old invite event
        // (membership="invite") even though the membership table says "join".
        // joined_membership_changed_since reads current_state, not the membership
        // table, so it returns false and the room is silently suppressed from
        // rooms.join in every incremental sync until the client does a full re-sync.
        //
        // GCOVR_EXCL_START — reachable only after a live make_join/send_join exchange
        // with a remote federation server; covered by the sync regression test that
        // directly exercises the underlying store functions.
        {
            auto join_depth = std::uint64_t{0U};
            auto join_prev_ids = std::vector<std::string>{};
            auto join_auth_ids = std::vector<std::string>{};
            if (auto const* obj = std::get_if<canonicaljson::Object>(&signed_event_value.storage()))
            {
                if (auto const* d = json_integer_member(*obj, "depth"); d != nullptr && *d >= 0)
                {
                    join_depth = static_cast<std::uint64_t>(*d);
                }
                if (auto const* pv = json_object_member(*obj, "prev_events"); pv != nullptr)
                {
                    join_prev_ids = json_string_array(*pv);
                }
                if (auto const* av = json_object_member(*obj, "auth_events"); av != nullptr)
                {
                    join_auth_ids = json_string_array(*av);
                }
            }
            auto join_pe = database::PersistentEvent{};
            join_pe.event_id = event_id_result.event_id;
            join_pe.room_id = std::string{room_id};
            join_pe.sender_user_id = *user_id;
            join_pe.json = signed_event.event_json;
            join_pe.depth = join_depth;
            join_pe.stream_ordering = membership_stream;
            join_pe.prev_event_ids = std::move(join_prev_ids);
            join_pe.auth_event_ids = std::move(join_auth_ids);
            auto const join_state = std::optional<database::PersistentStateEvent>{
                database::PersistentStateEvent{std::string{room_id}, "m.room.member", *user_id,
                                               event_id_result.event_id}
            };
            // The join event either inserts a new state row or UPDATEs the
            // existing one (invite → join). Either path leaves current_state pointing
            // at the join event at membership_stream, which joined_membership_changed_since
            // then detects correctly. DB-4: the user's membership row and the end of
            // their invite are committed with it.
            //
            // ADR-0064 phase B1: the join also seeds this room's state
            // bookkeeping, so the FIRST inbound PDU after it does not hit
            // missing_prev_state. The send_join response's state array (stored
            // above as outliers by ingest_send_join_state, returned here as
            // state_entries) is the room's state immediately BEFORE the join;
            // the join event's after-state is that plus the join itself,
            // recorded as one snapshot group, and the join becomes the room's
            // sole forward extremity.
            //
            // Sole: any extremity already recorded here is left from an earlier
            // stay in the room (concurrent PDUs are deferred until the join
            // commits). The resident's DAG has moved past it, and the join's
            // real prev_events are events this server does not hold, so it is
            // retired here. Kept, it made every later local event resolve the
            // old stay's state against the new one, and a leave from a large
            // public room failed with 500 (0.12.48).
            //
            // ADR-0228: the event, the membership, the state group, its mapping,
            // the forward extremities and current state commit together, so a
            // refused write leaves the user not joined rather than joined with
            // no state to build the next event on.
            auto const join_event_id = join_pe.event_id;
            auto bookkeeping = EventBookkeeping{};
            bookkeeping.state_after = compute_state_after(send_join_state.state_entries, join_event_id, "m.room.member",
                                                          std::string{*user_id});
            bookkeeping.replaced_extremities =
                database::find_forward_extremities(runtime.database.persistent_store, room_id);
            auto const stored = store_event_with_bookkeeping(
                runtime.database.persistent_store, policy, std::move(join_pe), join_state,
                database::MembershipProjection{*user_id, "join", membership_stream, std::nullopt}, bookkeeping,
                state_resolution_limits(runtime.config.security().federation.state_resolution));
            if (!stored.ok)
            {
                log_diagnostic("room.join.failed",
                               {
                                   {"actor",   *user_id,             false},
                                   {"room_id", std::string{room_id}, false},
                                   {"status",  "500",                false},
                                   {"step",    stored.step,          false},
                                   {"reason",  stored.reason,        false}
                },
                               observability::LogEventSeverity::warning);
                return make_operation_result(false, {}, "join event persistence failed: " + stored.reason, 500U);
            }
        }
        // GCOVR_EXCL_STOP

        // C03 (ADR-0714): the member rows of the whole answer in one transaction, not one INSERT commit each.
        {
            auto member_rows = std::vector<database::PersistentMembership>{};
            member_rows.reserve(joined_members.size());
            auto const first_member_ordering = allocate_stream_orderings(runtime.database, joined_members.size());
            auto member_orderings_used = std::uint64_t{0U};
            for (auto const& joined_member : joined_members)
            {
                if (joined_member == *user_id)
                {
                    continue;
                }
                member_rows.push_back(
                    {std::string{room_id}, joined_member, "join", first_member_ordering + member_orderings_used++});
            }
            if (!database::store_memberships_batch(runtime.database.persistent_store, std::move(member_rows)))
            {
                log_diagnostic("room.join.failed",
                               {
                                   {"actor",   *user_id,                    false},
                                   {"room_id", std::string{room_id},        false},
                                   {"reason",  "member persistence failed", false}
                },
                               observability::LogEventSeverity::warning);
            }
        }
        runtime.database.rooms.push_back({std::string{room_id}, *user_id, std::move(joined_members)});
        if (!record_room_share_started_device_changes(runtime, room_id, *user_id) ||
            !record_own_device_list_change(runtime, *user_id))
        {
            log_diagnostic("room.join.rejected", {
                                                     {"actor",   *user_id,                                false},
                                                     {"room_id", std::string{room_id},                    false},
                                                     {"status",  "500",                                   false},
                                                     {"reason",  "device list change persistence failed", false}
            });
            return make_operation_result(false, {}, "device list change persistence failed", 500U);
        }
        append_local_audit(runtime.database, observability::AuditCategory::admin, "room.joined_remote", *user_id,
                           room_id, "joined via federation");
        log_diagnostic("room.join.accepted_remote",
                       {
                           {"actor",         *user_id,                                                     false},
                           {"room_id",       std::string{room_id},                                         false},
                           {"remote_server", std::string{remote_server},                                   false},
                           {"event_id",      event_id_result.event_id,                                     false},
                           {"member_count",  std::to_string(runtime.database.rooms.back().members.size()), false}
        },
                       observability::LogEventSeverity::info);
        // Membership change from remote join is visible in /sync; advance
        // the sync stream counter so the publish wakes clients.
        auto const sync_stream_id = database::allocate_sync_stream_id(runtime.database.persistent_store);
        if (runtime.sync_notifier != nullptr)
        {
            runtime.sync_notifier->publish(visible_stream_position(runtime.database), sync_stream_id);
        }
        // Tell the federation worker to refresh its copy of this room now that
        // we are a resident participant — otherwise its PersistentStore stays
        // frozen at its own startup snapshot and a remote server's inbound
        // make_join/state query against us 404s despite this server having
        // just completed the join (see docs/architecture.md, "Federation
        // worker room staleness"). The room's whole state, every member
        // included, is persisted above (ADR-0241).
        notify_room_changed(runtime, room_id);
        auto const pending_pdus = pending_join.take_committed();
        // F-44, ADR-0370: each was received before the room's create event was stored, so its event ID and signatures
        // were checked under a guess at the room version. It is checked afresh under the version the create declares.
        auto const* const stored_policy = stored_room_version_policy(runtime.database.persistent_store, room_id);
        {
            // The sink takes room stripe then runtime mutex. Drop ALL global
            // recursion levels first, including a dispatcher's outer guard,
            // and restore them before guard/lease destruction on every path.
            auto const released = RuntimeLockRelease{guard};
            for (auto const& pdu : pending_pdus)
            {
                try
                {
                    auto const replayed = stored_policy != nullptr
                                              ? pending_pdu_under_room_version(runtime, pdu, *stored_policy, our_server)
                                              : std::nullopt;
                    if (!replayed.has_value())
                    {
                        LOG_WARNING("Dropped a PDU parked during a join: not valid under the room's version; room_id=" +
                                    std::string{room_id} + " received_as=" + pdu.event_id);
                        continue;
                    }
                    std::ignore = runtime.federation.pdu_sink(*replayed);
                }
                catch (...)
                {
                    // The join is already committed. A best-effort backlog
                    // drain must not turn it into a failed join after storing
                    // some queued PDUs. Drop the rest of this transient queue;
                    // subsequent transactions use ordinary joined admission.
                    LOG_WARNING("Pending join PDU drain failed after local join commit; room_id=" +
                                std::string{room_id});
                    break;
                }
            }
        }
        return make_operation_result(true, std::string{room_id});
    }
    if (!room_has_member(*room, *user_id))
    {
        if (third_party_signed != nullptr)
        {
            if (!verify_third_party_signed(*third_party_signed, *user_id, runtime.database.persistent_store, room_id))
            {
                log_diagnostic("room.join.rejected", {
                                                         {"actor",   *user_id,                                 false},
                                                         {"room_id", std::string{room_id},                     false},
                                                         {"status",  "403",                                    false},
                                                         {"reason",  "third_party_signed verification failed", false}
                });
                return make_operation_result(false, {}, "third_party_signed verification failed", 403U);
            }

            auto const* inviter = string_member(*third_party_signed, "sender");
            auto const inviter_id = inviter == nullptr ? std::string{} : std::string{*inviter};
            auto const invite_event_json =
                serialize_third_party_invite_member_event_json(*user_id, *third_party_signed);
            if (!invite_event_json.has_value())
            {
                log_diagnostic("room.join.rejected",
                               {
                                   {"actor",   *user_id,                                        false},
                                   {"room_id", std::string{room_id},                            false},
                                   {"status",  "500",                                           false},
                                   {"reason",  "third-party invite event serialization failed", false}
                });
                return make_operation_result(false, {}, "third-party invite event serialization failed", 500U);
            }
            auto const invite_composition = compose_signed_event(runtime, room_id, inviter_id, *invite_event_json);
            if (invite_composition.failure == ComposeFailure::too_large)
            {
                return event_too_large_result();
            }
            auto const& composed_invite = invite_composition.event;
            if (!composed_invite.has_value())
            {
                log_diagnostic("room.join.rejected", {
                                                         {"actor",   *user_id,                            false},
                                                         {"room_id", std::string{room_id},                false},
                                                         {"status",  "403",                               false},
                                                         {"reason",  "third-party invite event rejected", false}
                });
                return make_operation_result(false, {}, "third-party invite event rejected", 403U);
            }
            if (persist_composed_event(runtime, room_id, inviter_id, *composed_invite) == PersistOutcome::not_stored)
            {
                log_diagnostic("room.join.rejected",
                               {
                                   {"actor",   *user_id,                                      false},
                                   {"room_id", std::string{room_id},                          false},
                                   {"status",  "500",                                         false},
                                   {"reason",  "third-party invite event persistence failed", false}
                });
                return make_operation_result(false, {}, "third-party invite event persistence failed", 500U);
            }
            federate_local_event(runtime, room_id, *room, *composed_invite);
            // The invite is an m.room.member event for `user_id`, who may be one of an
            // appservice's virtual users; it was stored here and nowhere else queued it.
            queue_event_for_appservices(runtime, *room, *composed_invite, inviter_id);
        }

        // Audit R04 (ADR-0185): a join into a restricted room this server is
        // resident in. client-server-api.md "Restricted rooms": "When joining
        // without an invite, the server MUST verify that the requesting user
        // meets at least one of the conditions. If no conditions can be
        // verified or no conditions are satisfied, the user will not be able
        // to join." When one holds, the join names a user of this server who
        // can invite (join_authorised_via_users_server); this server signs the
        // join, which is that user's server's signature (rule 4.2.1).
        auto authorising_user = std::string{};
        if (third_party_signed == nullptr)
        {
            auto decision = decide_restricted_join(runtime.database.persistent_store, room_id, *user_id,
                                                   runtime.config.server().server_name);
            if (decision.verdict == RestrictedJoinVerdict::unable_to_grant)
            {
                // ADR-0287, ADR-0288: the user meets a condition but no user of this server can
                // authorise the join. An event for the room that is being applied now may give a
                // local user the power, so wait for it and decide again; if it still cannot be
                // authorised here, join through another resident (server-server-api.md
                // "Restricted rooms": "the joining server should try a different server").
                auto const exchange = MembershipExchangeClaim{runtime, room_id, *user_id};
                wait_for_in_flight_room_events(runtime, guard, room_id);
                room = find_room(runtime.database, room_id);
                if (room == nullptr || room_has_member(*room, *user_id))
                {
                    auto changed =
                        make_operation_result(false, {}, "the room changed while the join was decided", 429U);
                    changed.retry_after_ms = membership_exchange_retry_after_ms;
                    return changed;
                }
                decision = decide_restricted_join(runtime.database.persistent_store, room_id, *user_id,
                                                  runtime.config.server().server_name);
                if (decision.verdict == RestrictedJoinVerdict::unable_to_grant)
                {
                    auto const our_server = runtime.config.server().server_name;
                    auto candidates = restricted_join_fallback_candidates(
                        join_candidate_servers(joining_via, room_id, our_server),
                        last_known_resident_servers(runtime, room_id), our_server,
                        std::min<std::size_t>(
                            max_restricted_join_fallback_candidates,
                            std::max(std::uint32_t{1U}, runtime.federation.config.join_max_candidates)));
                    if (!candidates.empty())
                    {
                        auto outbound_slot = admit_client_outbound_proxy(runtime, std::string{client_key});
                        if (!outbound_slot.has_value())
                        {
                            return client_outbound_limit_result(runtime);
                        }
                        auto joined_elsewhere = join_through_other_resident(runtime, guard, room_id, *user_id,
                                                                            std::move(candidates), &outbound_slot);
                        if (joined_elsewhere.ok)
                        {
                            return joined_elsewhere;
                        }
                        // The client is told the refusal that sent it elsewhere (below).
                    }
                }
            }
            if (decision.verdict == RestrictedJoinVerdict::authorised)
            {
                authorising_user = decision.authorising_user;
            }
            else if (decision.verdict != RestrictedJoinVerdict::not_restricted &&
                     decision.verdict != RestrictedJoinVerdict::already_permitted)
            {
                log_diagnostic("room.join.rejected", {
                                                         {"actor",   *user_id,             false},
                                                         {"room_id", std::string{room_id}, false},
                                                         {"status",  "403",                false},
                                                         {"reason",  decision.reason,      false}
                });
                return make_operation_result(false, {}, decision.reason, 403U);
            }
        }
        auto const join_event_json =
            serialize_own_join_event_json(runtime.database.persistent_store, *user_id, authorising_user);
        if (!join_event_json.has_value())
        {
            log_diagnostic("room.join.rejected", {
                                                     {"actor",   *user_id,                                false},
                                                     {"room_id", std::string{room_id},                    false},
                                                     {"status",  "500",                                   false},
                                                     {"reason",  "membership event serialization failed", false}
            });
            return make_operation_result(false, {}, "membership event serialization failed", 500U);
        }
        auto const composition = compose_signed_event(runtime, room_id, *user_id, *join_event_json);
        if (composition.failure == ComposeFailure::too_large)
        {
            return event_too_large_result();
        }
        auto const& composed = composition.event;
        if (!composed.has_value())
        {
            log_diagnostic("room.join.rejected", {
                                                     {"actor",   *user_id,                    false},
                                                     {"room_id", std::string{room_id},        false},
                                                     {"status",  "403",                       false},
                                                     {"reason",  "membership event rejected", false}
            });
            return make_operation_result(false, {}, "membership event rejected", 403U);
        }
        if (persist_composed_event(runtime, room_id, *user_id, *composed) == PersistOutcome::not_stored)
        {
            log_diagnostic("room.join.rejected", {
                                                     {"actor",   *user_id,                              false},
                                                     {"room_id", std::string{room_id},                  false},
                                                     {"status",  "500",                                 false},
                                                     {"reason",  "membership event persistence failed", false}
            });
            return make_operation_result(false, {}, "membership event persistence failed", 500U);
        }
        federate_local_event(runtime, room_id, *room, *composed);

        // persist_composed_event has already projected the join (CSAZ-6).
        log_diagnostic("room.join.membership_persisted",
                       {
                           {"actor",        *user_id,                             false},
                           {"room_id",      std::string{room_id},                 false},
                           {"member_count", std::to_string(room->members.size()), false}
        });
        // Push delivery: a self-join has no distinct recipient to add (the
        // extra_recipient equals the sender and is filtered as such), but is
        // still routed through the same pipeline as every other membership
        // transition — see persist_membership_transition's push comment
        // above for why this is a no-op against the default ruleset today.
        dispatch_membership_push_notification(runtime, *room, *composed, *user_id, *user_id);
    }
    else if (!database::delete_invite(runtime.database.persistent_store, room_id, *user_id))
    {
        log_diagnostic("room.join.rejected", {
                                                 {"actor",   *user_id,                         false},
                                                 {"room_id", std::string{room_id},             false},
                                                 {"status",  "500",                            false},
                                                 {"reason",  "invite metadata cleanup failed", false}
        });
        return make_operation_result(false, {}, "invite metadata cleanup failed", 500U);
    }
    else
    {
        log_diagnostic("room.join.already_member", {
                                                       {"actor",        *user_id,                             false},
                                                       {"room_id",      std::string{room_id},                 false},
                                                       {"member_count", std::to_string(room->members.size()), false}
        });
    }

    append_local_audit(runtime.database, observability::AuditCategory::admin, "room.joined", *user_id, room_id,
                       "joined");
    log_diagnostic("room.join.accepted",
                   {
                       {"actor",        *user_id,                             false},
                       {"room_id",      std::string{room_id},                 false},
                       {"member_count", std::to_string(room->members.size()), false}
    },
                   observability::LogEventSeverity::info);
    // Membership change from local join is visible in /sync; advance
    // the sync stream counter so the publish wakes clients.
    auto const sync_stream_id = database::allocate_sync_stream_id(runtime.database.persistent_store);
    if (runtime.sync_notifier != nullptr)
    {
        runtime.sync_notifier->publish(visible_stream_position(runtime.database), sync_stream_id);
    }
    notify_room_changed(runtime, room_id);
    return make_operation_result(true, std::string{room_id});
}

[[nodiscard]] auto leave_room(HomeserverRuntime& runtime, std::string_view access_token, std::string_view room_id,
                              std::string_view client_key) -> OperationResult
{
    auto guard = RuntimeLock{runtime.mutex};
    log_diagnostic("room.leave.started", {
                                             {"room_id",          std::string{room_id},                    false},
                                             {"has_access_token", access_token.empty() ? "false" : "true", false}
    });
    auto const user_id = authenticated_user(runtime, access_token);
    if (!user_id.has_value())
    {
        log_diagnostic("room.leave.rejected", {
                                                  {"room_id", std::string{room_id}, false},
                                                  {"status",  "401",                false},
                                                  {"reason",  "unauthenticated",    false}
        });
        return make_operation_result(false, {}, "unauthenticated", 401U);
    }
    if (auto refused = membership_exchange_refusal(runtime, room_id, *user_id); refused.has_value())
    {
        return *refused;
    }

    // Look up the membership row. If missing, attempt recovery from current_state:
    // a server restart or partial persistence can leave the room known but the
    // membership row absent. If current_state still carries an m.room.member event
    // for this user, synthesise the matching membership row so `/leave` can behave
    // idempotently and later `/forget` can still observe the terminal state.
    auto membership_it = std::ranges::find_if(runtime.database.persistent_store.memberships,
                                              [&](database::PersistentMembership const& current) {
                                                  return current.room_id == room_id && current.user_id == *user_id;
                                              });

    if (membership_it == runtime.database.persistent_store.memberships.end())
    {
        auto const member_event_id = database::find_current_state_event_id(runtime.database.persistent_store, room_id,
                                                                           "m.room.member", *user_id);
        if (member_event_id.has_value())
        {
            auto const event_it = runtime.database.persistent_store.events.find(*member_event_id);
            if (event_it != runtime.database.persistent_store.events.end())
            {
                auto const parsed = canonicaljson::parse_lossless(event_it->json);
                auto const* obj = std::get_if<canonicaljson::Object>(&parsed.value.storage());
                auto const* content = obj == nullptr ? nullptr : object_member_as_object(*obj, "content");
                auto const* mem = content == nullptr ? nullptr : string_member(*content, "membership");
                if (mem != nullptr)
                {
                    // Re-create the missing membership row so the leave path can proceed
                    // or observe that the user has already left.
                    auto const recovered_stream = allocate_stream_ordering(runtime.database);
                    std::ignore = store_or_update_membership(runtime.database.persistent_store, room_id, *user_id, *mem,
                                                             recovered_stream);
                    log_diagnostic("room.leave.membership_recovered",
                                   {
                                       {"actor",   *user_id,             false},
                                       {"room_id", std::string{room_id}, false}
                    });
                    // Re-find: push_back may have reallocated the vector.
                    membership_it =
                        std::ranges::find_if(runtime.database.persistent_store.memberships,
                                             [&](database::PersistentMembership const& current) {
                                                 return current.room_id == room_id && current.user_id == *user_id;
                                             });
                }
            }
        }
    }

    if (membership_it == runtime.database.persistent_store.memberships.end())
    {
        log_diagnostic("room.leave.accepted",
                       {
                           {"actor",   *user_id,             false},
                           {"room_id", std::string{room_id}, false}
        },
                       observability::LogEventSeverity::info);
        return make_operation_result(true, std::string{room_id});
    }
    // Leaving rejects an invite and retracts a knock (Client-Server API v1.19,
    // "Leaving rooms"); a remote knock is retracted over federation as an invite
    // is rejected (Server-Server API v1.19, "Knocking upon a room").
    if (membership_it->membership != "join" && membership_it->membership != "invite" &&
        membership_it->membership != "knock")
    {
        // Idempotent per spec on `membership` alone — but a caller retrying
        // /leave is itself evidence its view is stale (it still thinks it's
        // joined), most likely because an earlier leave's stream_ordering
        // never advanced (see the 0.10.15 update_membership fix). Refresh
        // stream_ordering and re-notify on every repeat call so a row stuck
        // in that state before the fix self-heals instead of staying
        // invisible to /sync forever.
        auto const membership_stream = allocate_stream_ordering(runtime.database);
        std::ignore = store_or_update_membership(runtime.database.persistent_store, room_id, *user_id,
                                                 membership_it->membership, membership_stream);
        auto const sync_stream_id = database::allocate_sync_stream_id(runtime.database.persistent_store);
        if (runtime.sync_notifier != nullptr)
        {
            runtime.sync_notifier->publish(visible_stream_position(runtime.database), sync_stream_id);
        }
        log_diagnostic("room.leave.accepted",
                       {
                           {"actor",   *user_id,             false},
                           {"room_id", std::string{room_id}, false}
        },
                       observability::LogEventSeverity::info);
        notify_room_changed(runtime, room_id);
        return make_operation_result(true, std::string{room_id});
    }

    // For rooms hosted on a remote server, perform a federated leave:
    // make_leave (get a signed template) → sign → send_leave.
    // A knock this server sent over federation is withdrawn through the resident
    // that accepted it (ADR-0251): the room ID's domain need not be in the room,
    // and a version 12 room ID names no server at all.
    auto const our_server = runtime.config.server().server_name;
    auto remote_server = std::string{};
    if (membership_it->membership == "knock")
    {
        if (auto const knock = database::find_invite(runtime.database.persistent_store, room_id, *user_id);
            knock.has_value())
        {
            remote_server = knock->resident_server;
        }
    }
    // Server-Server API, "Leaving Rooms (Rejecting Invites)": a remote invite "do[es] not involve the
    // server in the graph", so the leave goes to a resident server, and "the resident server may be the
    // server which sent the invite". The inviter's server is the one that holds the room for certain
    // (its user sent the invite), and a version 12 room ID names no server at all, so it comes first.
    // A server that is in the room (another of its users is joined) composes the leave itself.
    auto const rejecting_invite = membership_it->membership == "invite";
    if (rejecting_invite && !this_server_is_in_room(runtime, room_id))
    {
        remote_server = invite_sender_server(runtime, room_id, *user_id);
    }
    if (auto const room_domain = server_name_from_room_id(room_id);
        remote_server.empty() && !room_domain.empty() && room_domain != our_server)
    {
        remote_server = std::string{room_domain};
    }

    if (!remote_server.empty())
    {
        wire_federation_callbacks(runtime);
        auto const signing_key = find_active_server_signing_key(runtime);
        auto const key_id = signing_key.has_value() ? signing_key->key_id : std::string{};
        auto secret_key = core::SecretBuffer{runtime.database.signing_secret_key.bytes()};

        // Consumed after the released scope below closes (the membership write
        // in step 5 needs the lock), so it must outlive that scope.
        auto send_ok = false;
        auto send_body = std::string{};
        // The signed leave this server authored to reject an invite to a room it holds no state of. Kept
        // as an outlier, like the invite it ends, so the user's next /sync reports the leave event itself
        // under rooms.leave (Client-Server API, GET /sync: `timeline` is "the timeline of messages and
        // state changes in the room up to the point when the user left").
        auto leave_outlier = std::optional<database::PersistentEvent>{};
        // An invite whose inviting server no longer has the room, or will not take the leave (403,
        // 404), cannot be rejected through a resident: no leave event can be authored without a
        // template from one. The spec defines no other route, so the invite is dropped here, as a
        // leave in this server's own records, and nothing is sent.
        auto reject_locally = false;
        auto const outbound_slot = admit_client_outbound_proxy(runtime, std::string{client_key});
        if (!outbound_slot.has_value())
        {
            return client_outbound_limit_result(runtime);
        }
        auto const exchange = MembershipExchangeClaim{runtime, room_id, *user_id};

        // The whole remote-leave exchange runs with runtime.mutex released:
        // three federation round trips must not freeze every other request.
        // Scoped rather than a hand-written unlock/lock pair so the guard is
        // restored on EVERY exit — including a throw out of
        // perform_sync_outbound_call, which previously left the mutex down for
        // this thread and the next request it served.
        {
            auto const released = merovingian::homeserver::RuntimeLockRelease{guard};

            // Step 1: make_leave — fetch a leave event template from the remote server.
            auto make_leave_tx = federation::make_outbound_make_membership(
                federation::FederationEndpoint::make_leave, remote_server, our_server, room_id, *user_id, {});
            log_diagnostic("room.leave.remote.make_leave", {
                                                               {"actor",         *user_id,             false},
                                                               {"room_id",       std::string{room_id}, false},
                                                               {"remote_server", remote_server,        false}
            });
            // Two outbound calls need the same key; make the second copy before
            // moving the first into the make_leave call.
            auto secret_key_for_send = core::SecretBuffer{secret_key.bytes()};
            auto const make_leave_call = perform_outbound_call(
                runtime, OutboundAnswerTrust::unverified, room_id, make_leave_tx, key_id, std::move(secret_key),
                "room.leave.remote.make_leave_failed", runtime.federation.config.remote_timeout_seconds,
                membership_template_max_response_bytes, std::nullopt);
            auto const make_ok = make_leave_call.ok;
            auto const& make_body = make_leave_call.body;
            if (!make_ok && rejecting_invite &&
                (make_leave_call.remote_status == 403U || make_leave_call.remote_status == 404U))
            {
                reject_locally = true;
                send_ok = true;
                log_diagnostic("room.leave.invite_rejected_locally",
                               {
                                   {"actor",         *user_id,                                      false},
                                   {"room_id",       std::string{room_id},                          false},
                                   {"remote_server", remote_server,                                 false},
                                   {"remote_status", std::to_string(make_leave_call.remote_status), false}
                },
                               observability::LogEventSeverity::info);
            }
            else if (!make_ok)
            {
                log_diagnostic("room.leave.rejected",
                               {
                                   {"actor",   *user_id,             false},
                                   {"room_id", std::string{room_id}, false},
                                   {"status",  "502",                false},
                                   {"reason",  "make_leave failed",  false}
                },
                               observability::LogEventSeverity::warning);
                return make_operation_result(false, {}, "make_leave failed: " + make_body, 502U);
            }

            if (!reject_locally)
            {
                // Step 2: validate the leave event template.
                auto const make_response = canonicaljson::parse_lossless(make_body);
                auto const* make_obj = std::get_if<canonicaljson::Object>(&make_response.value.storage());
                if (make_obj == nullptr)
                {
                    log_diagnostic("room.leave.rejected", {
                                                              {"actor",   *user_id,                    false},
                                                              {"room_id", std::string{room_id},        false},
                                                              {"status",  "502",                       false},
                                                              {"reason",  "malformed make_leave body", false}
                    });
                    return make_operation_result(false, {}, "malformed make_leave response", 502U);
                }
                auto const validated = validate_make_leave_event(room_id, *user_id, *make_obj);
                if (!validated.ok)
                {
                    log_diagnostic("room.leave.rejected", {
                                                              {"actor",   *user_id,             false},
                                                              {"room_id", std::string{room_id}, false},
                                                              {"status",  "502",                false},
                                                              {"reason",  validated.reason,     false}
                    });
                    return make_operation_result(false, {}, validated.reason, 502U);
                }
                auto const room_version = validated.room_version;
                auto const* policy = rooms::find_room_version_policy(room_version);
                if (policy == nullptr)
                {
                    log_diagnostic("room.leave.rejected", {
                                                              {"actor",   *user_id,                      false},
                                                              {"room_id", std::string{room_id},          false},
                                                              {"status",  "500",                         false},
                                                              {"reason",  "room version policy missing", false}
                    });
                    return make_operation_result(false, {}, "room version policy missing", 500U);
                }
                auto event_object = validated.event;
                claim_membership_event_template(event_object, our_server, event_clock_now_ms(runtime));
                // C18: only the membership is kept of the resident's content.
                std::ignore = restrict_membership_template_content(event_object, our_server, false);
                // Held to the room version's event format before it is hashed and signed as the user's own (F-13).
                if (auto const violation = membership_template_format_refusal(event_object, *policy);
                    !violation.empty())
                {
                    log_diagnostic("room.leave.rejected", {
                                                              {"actor",   *user_id,             false},
                                                              {"room_id", std::string{room_id}, false},
                                                              {"status",  "502",                false},
                                                              {"reason",  violation,            false}
                    });
                    return make_operation_result(false, {}, "make_leave template refused: " + violation, 502U);
                }

                // Step 3: add content hash and sign the leave event.
                auto const content_hash = events::make_content_hash(canonicaljson::Value{event_object});
                if (!content_hash.error.empty())
                {
                    log_diagnostic("room.leave.rejected", {
                                                              {"actor",   *user_id,             false},
                                                              {"room_id", std::string{room_id}, false},
                                                              {"status",  "500",                false},
                                                              {"reason",  content_hash.error,   false}
                    });
                    return make_operation_result(false, {}, "leave event content hash failed", 500U);
                }
                auto hashes_obj = canonicaljson::Object{};
                hashes_obj.push_back(canonicaljson::make_member("sha256", canonicaljson::Value{content_hash.sha256}));
                replace_or_add_member(event_object, "hashes", canonicaljson::Value{std::move(hashes_obj)});

                auto event_to_sign = canonicaljson::Value{event_object};
                if (runtime.crypto_provider == nullptr)
                {
                    log_diagnostic("room.leave.rejected",
                                   {
                                       {"actor",   *user_id,                                false},
                                       {"room_id", std::string{room_id},                    false},
                                       {"status",  "500",                                   false},
                                       {"reason",  "server signing provider not available", false}
                    });
                    return make_operation_result(false, {}, "server signing provider not available", 500U);
                }
                auto key_store = RuntimeSigningKeyStore{our_server, signing_key.value()};
                auto const signed_event = events::sign_event_for_server(event_to_sign, *policy, key_store,
                                                                        *runtime.crypto_provider, our_server);
                if (!signed_event.error.empty())
                {
                    log_diagnostic("room.leave.rejected", {
                                                              {"actor",   *user_id,             false},
                                                              {"room_id", std::string{room_id}, false},
                                                              {"status",  "500",                false},
                                                              {"reason",  signed_event.error,   false}
                    });
                    return make_operation_result(false, {}, "event signing failed", 500U);
                }
                auto const signed_value = canonicaljson::parse_lossless(signed_event.event_json);
                auto const event_id_result = events::make_reference_hash_event_id(signed_value.value, *policy);
                if (!event_id_result.error.empty() || event_id_result.event_id.empty())
                {
                    log_diagnostic("room.leave.rejected", {
                                                              {"actor",   *user_id,                      false},
                                                              {"room_id", std::string{room_id},          false},
                                                              {"status",  "500",                         false},
                                                              {"reason",  "event_id computation failed", false}
                    });
                    return make_operation_result(false, {}, "event_id computation failed", 500U);
                }

                // Every rejection keeps the leave it authored (ADR-0294): the resident sends an accepted
                // send_leave on to the room's other servers but never back to the server that sent it, so no
                // transaction will bring this event here, whether or not this server's held state is current.
                if (rejecting_invite)
                {
                    auto const ids_of = [&event_object](std::string_view key) {
                        auto ids = std::vector<std::string>{};
                        auto const* member = object_member(event_object, key);
                        auto const* array =
                            member == nullptr ? nullptr : std::get_if<canonicaljson::Array>(&member->storage());
                        for (auto const& entry : array == nullptr ? canonicaljson::Array{} : *array)
                        {
                            if (auto const* id = std::get_if<std::string>(&entry.storage()); id != nullptr)
                            {
                                ids.push_back(*id);
                            }
                        }
                        return ids;
                    };
                    auto outlier = database::PersistentEvent{};
                    outlier.event_id = event_id_result.event_id;
                    outlier.room_id = std::string{room_id};
                    outlier.sender_user_id = *user_id;
                    outlier.json = signed_event.event_json;
                    auto const* depth = integer_member(event_object, "depth");
                    outlier.depth =
                        depth == nullptr || *depth < 0 ? std::uint64_t{0U} : static_cast<std::uint64_t>(*depth);
                    outlier.prev_event_ids = ids_of("prev_events");
                    outlier.auth_event_ids = ids_of("auth_events");
                    outlier.status = "outlier";
                    leave_outlier = std::move(outlier);
                }

                // Step 4: send_leave — deliver the signed leave event to the remote server.
                auto send_leave_tx = federation::make_outbound_send_membership(
                    federation::FederationEndpoint::send_leave, remote_server, our_server, room_id,
                    event_id_result.event_id, signed_event.event_json);
                log_diagnostic("room.leave.remote.send_leave", {
                                                                   {"actor",         *user_id,                 false},
                                                                   {"room_id",       std::string{room_id},     false},
                                                                   {"remote_server", remote_server,            false},
                                                                   {"event_id",      event_id_result.event_id, false}
                });
                std::tie(send_ok, send_body) =
                    perform_sync_outbound_call(runtime, OutboundAnswerTrust::unverified, room_id, send_leave_tx, key_id,
                                               std::move(secret_key_for_send), "room.leave.remote.send_leave_failed",
                                               runtime.federation.config.remote_timeout_seconds);
            }
        }

        if (!send_ok)
        {
            log_diagnostic("room.leave.rejected",
                           {
                               {"actor",   *user_id,             false},
                               {"room_id", std::string{room_id}, false},
                               {"status",  "502",                false},
                               {"reason",  "send_leave failed",  false}
            },
                           observability::LogEventSeverity::warning);
            return make_operation_result(false, {}, "send_leave failed: " + send_body, 502U);
        }

        // Step 5: update local membership, device lists and in-memory state. DB-4:
        // the row and the end of any invite commit together.
        auto const membership_stream = allocate_stream_ordering(runtime.database);
        auto const leave_stored = [&] {
            auto projection = database::MembershipProjection{*user_id, "leave", membership_stream, std::nullopt};
            if (!leave_outlier.has_value())
            {
                return database::store_membership_projection(runtime.database.persistent_store, room_id, projection);
            }
            leave_outlier->stream_ordering = membership_stream;
            auto const leave_event_id = leave_outlier->event_id;
            return database::store_event_with_state(
                runtime.database.persistent_store, std::move(*leave_outlier),
                database::PersistentStateEvent{std::string{room_id}, "m.room.member", *user_id, leave_event_id},
                std::move(projection));
        }();
        if (!leave_stored)
        {
            log_diagnostic("room.leave.rejected", {
                                                      {"actor",   *user_id,                        false},
                                                      {"room_id", std::string{room_id},            false},
                                                      {"status",  "500",                           false},
                                                      {"reason",  "membership persistence failed", false}
            });
            return make_operation_result(false, {}, "membership persistence failed", 500U);
        }
        if (!record_room_share_ended_device_changes(runtime, room_id, *user_id))
        {
            log_diagnostic("room.leave.rejected", {
                                                      {"actor",   *user_id,                                false},
                                                      {"room_id", std::string{room_id},                    false},
                                                      {"status",  "500",                                   false},
                                                      {"reason",  "device list change persistence failed", false}
            });
            return make_operation_result(false, {}, "device list change persistence failed", 500U);
        }
        apply_runtime_membership(runtime.database, room_id, *user_id, "leave");
        auto const sync_stream_id = database::allocate_sync_stream_id(runtime.database.persistent_store);
        if (runtime.sync_notifier != nullptr)
        {
            runtime.sync_notifier->publish(visible_stream_position(runtime.database), sync_stream_id);
        }
        append_local_audit(runtime.database, observability::AuditCategory::admin, "room.left_remote", *user_id, room_id,
                           "left via federation");
        log_diagnostic("room.leave.accepted",
                       {
                           {"actor",   *user_id,             false},
                           {"room_id", std::string{room_id}, false}
        },
                       observability::LogEventSeverity::info);
        notify_room_changed(runtime, room_id);
        return make_operation_result(true, std::string{room_id});
    }

    // Local room: compose, sign and persist a leave event through the standard path.
    auto const result = persist_membership_transition(runtime, room_id, *user_id, *user_id, "leave");
    if (!result.ok)
    {
        log_diagnostic("room.leave.rejected",
                       {
                           {"actor",   *user_id,                                                    false},
                           {"room_id", std::string{room_id},                                        false},
                           {"status",  std::to_string(result.status),                               false},
                           {"reason",  result.reason.empty() ? "membership failed" : result.reason, false}
        });
        return result;
    }

    append_local_audit(runtime.database, observability::AuditCategory::admin, "room.left", *user_id, room_id, "left");
    log_diagnostic("room.leave.accepted",
                   {
                       {"actor",   *user_id,             false},
                       {"room_id", std::string{room_id}, false}
    },
                   observability::LogEventSeverity::info);
    notify_room_changed(runtime, room_id);
    return make_operation_result(true, std::string{room_id});
}

namespace
{

    // What the answer of an invited user's server to `PUT /v2/invite` amounts to once checked (ADR-0293).
    // `refusal` is empty when the answer was good.
    struct CheckedInviteAnswer final
    {
        std::string cosigned_event_json{};
        std::vector<events::EventSignature> cosigned_signatures{};
        std::string refusal{};
    };

    // Server-Server API, PUT /v2/invite: the 200 response is "The event with the invited server's
    // signature added. All other fields of the events should remain untouched." So the answer must be
    // the event this server sent (same reference-hash event ID, so nothing the hash covers changed) and
    // carry a valid signature by the invited user's server (appendices.md "Checking for a Signature";
    // an unknown or expired key is skipped, a known one that does not verify refuses, and one must
    // verify). What is returned is this server's own event with only those verified signatures added to
    // it, never the invited server's copy. The key lookup is a network round trip: call with
    // `runtime.mutex` RELEASED, with every argument owned by the caller.
    // `deadline` is the offer's own (ADR-0307): resolving the invitee server's keys draws from what the
    // exchange left of it, never from a fresh timeout.
    [[nodiscard]] auto check_invite_answer(HomeserverRuntime& runtime, std::string_view room_version,
                                           std::string_view invitee_server, std::string_view event_id,
                                           std::string_view own_event_json, std::string_view answer_body,
                                           std::chrono::steady_clock::time_point deadline) -> CheckedInviteAnswer
    {
        auto const refused = [](std::string reason) {
            return CheckedInviteAnswer{{}, {}, std::move(reason)};
        };
        auto const* policy = rooms::find_room_version_policy(room_version);
        if (policy == nullptr)
        {
            return refused("the room's version is not known");
        }
        auto const answer = canonicaljson::parse_lossless(answer_body);
        auto const* root = std::get_if<canonicaljson::Object>(&answer.value.storage());
        auto const* answered = answer.error != canonicaljson::ParseError::none || root == nullptr
                                   ? nullptr
                                   : object_member(*root, "event");
        if (answered == nullptr || !std::holds_alternative<canonicaljson::Object>(answered->storage()))
        {
            return refused("the invited user's server sent a malformed invite response");
        }
        auto const id = events::make_reference_hash_event_id(*answered, *policy);
        if (!id.error.empty() || id.event_id != event_id)
        {
            return refused("the invited user's server returned a different event from the invite");
        }
        auto const returned = events::parse_event_envelope(*answered);
        if (!returned.error.empty() || runtime.crypto_provider == nullptr)
        {
            return refused("the invited user's server returned an event that could not be checked");
        }
        auto const own_event = canonicaljson::parse_lossless(own_event_json);
        if (own_event.error != canonicaljson::ParseError::none)
        {
            return refused("the invite could not be read back");
        }
        // Only keys that resolved can have been verified; those are the signatures merged.
        auto resolved_key_ids = std::vector<std::string>{};
        auto const decision = federation::verify_server_signatures_on_event(
            *answered, *policy, invitee_server, returned.event.signatures,
            [&](std::string_view server_name, std::string_view key_id) {
                if (server_name != invitee_server)
                {
                    return federation::VerificationKeyResolution{};
                }
                auto key = federation::resolve_join_state_key(runtime.federation, server_name, key_id, deadline);
                if (key.has_value())
                {
                    resolved_key_ids.emplace_back(key_id);
                }
                return federation::VerificationKeyResolution{std::move(key), false};
            },
            *runtime.crypto_provider, deadline);
        if (!decision.accepted || resolved_key_ids.empty())
        {
            return refused("the invited user's server did not validly sign the invite: " + decision.reason);
        }
        auto const combined =
            with_server_signatures(own_event.value, returned.event.signatures, invitee_server, resolved_key_ids);
        if (!combined.has_value())
        {
            return refused("the invited user's signatures could not be added to the invite");
        }
        auto serialized = canonicaljson::serialize_canonical(*combined);
        if (serialized.error != canonicaljson::CanonicalJsonError::none ||
            serialized.output.size() > events::max_event_size_bytes)
        {
            return refused("the invite with the invited user's signatures is not a valid event");
        }
        auto result = CheckedInviteAnswer{std::move(serialized.output), {}, {}};
        for (auto const& signature : returned.event.signatures)
        {
            if (signature.server_name == invitee_server &&
                std::ranges::find(resolved_key_ids, signature.key_id) != resolved_key_ids.end())
            {
                result.cosigned_signatures.push_back(signature);
            }
        }
        return result;
    }

} // namespace

[[nodiscard]] auto deliver_remote_invite(HomeserverRuntime& runtime, RuntimeLock& guard, std::string_view room_id,
                                         std::string_view invitee_server, std::string_view event_id,
                                         std::string_view event_json, std::uint32_t timeout_seconds)
    -> RemoteInviteResult
{
    // One deadline for the whole offer: the exchange and the checks of the answer (its key lookups) draw from
    // it, so a caller offering several invites under one deadline is not held past it (ADR-0307). 0 means the
    // offer budget (remote_invite_offer_seconds, lowered to remote_timeout when configured).
    auto const offer_seconds = timeout_seconds > 0U
                                   ? timeout_seconds
                                   : effective_client_outbound_deadline(runtime, remote_invite_offer_seconds);
    auto const offer_deadline = std::chrono::steady_clock::now() + std::chrono::seconds{offer_seconds};
    wire_federation_callbacks(runtime);
    auto const signing_key = find_active_server_signing_key(runtime);
    if (!signing_key.has_value())
    {
        return {RemoteInviteOutcome::unreachable, 502U, "server signing key not available"};
    }
    auto const& store = runtime.database.persistent_store;
    auto const room_version = stored_room_version(store, room_id).value_or("10");
    auto const transaction =
        federation::make_outbound_invite(invitee_server, runtime.config.server().server_name, room_id, event_id,
                                         room_version, event_json, stripped_state_pdus(store, room_id));
    auto const key_id = signing_key->key_id;
    auto secret_key = core::SecretBuffer{runtime.database.signing_secret_key.bytes()};

    // The exchange runs with runtime.mutex released: it is a federation round trip to a peer this server
    // does not control, and every other request would wait behind it. Everything read from the runtime
    // was copied above.
    auto const call = [&] {
        auto const released = RuntimeLockRelease{guard};
        // Bounded: discovery and the request draw from one deadline, so the exchange stays within the offer's
        // budget instead of giving each its own `offer_seconds` (ADR-0307).
        return perform_bounded_outbound_call_with_status(runtime, OutboundAnswerTrust::unverified, room_id, transaction,
                                                         key_id, std::move(secret_key), "room.invite.remote_failed",
                                                         offer_seconds);
    }();

    if (call.ok)
    {
        // Server-Server API, PUT /invite: the response is `{"event": <the signed invite event>}`. It is
        // checked, and the invited server's signature merged into this server's own event, with the
        // mutex released: resolving that server's signing key can be a round trip to it. A response
        // that does not check out is a refusal, not a delivery (ADR-0293).
        auto const checked = [&] {
            auto const released = RuntimeLockRelease{guard};
            return check_invite_answer(runtime, room_version, invitee_server, event_id, event_json, call.body,
                                       offer_deadline);
        }();
        if (!checked.refusal.empty())
        {
            log_diagnostic("room.invite.remote_answer_refused",
                           {
                               {"room_id",        std::string{room_id},        false},
                               {"invitee_server", std::string{invitee_server}, false},
                               {"reason",         checked.refusal,             false}
            },
                           observability::LogEventSeverity::warning);
            return {RemoteInviteOutcome::refused, 502U, checked.refusal};
        }
        return {RemoteInviteOutcome::delivered, 200U, {}, checked.cosigned_event_json, checked.cosigned_signatures};
    }
    // An answer that says no is final: the same invite would be refused again. A server that gave no
    // answer, or only an overloaded or failing one, is asked again later by the outbound queue.
    auto const status = call.remote_status;
    auto const final_refusal = status >= 400U && status < 500U && status != 408U && status != 429U;
    if (final_refusal)
    {
        auto const blocked = status == 403U && call.remote_errcode == invite_blocked_errcode;
        auto refusal = RemoteInviteResult{
            RemoteInviteOutcome::refused, status == 403U ? std::uint16_t{403U} : std::uint16_t{502U},
            blocked ? "the invited user is not accepting invites" : "the invited user's server refused the invite"};
        refusal.errcode = blocked ? std::string{invite_blocked_errcode} : std::string{};
        return refusal;
    }
    return {RemoteInviteOutcome::unreachable, 502U, call.body};
}

[[nodiscard]] auto store_cosigned_invite(HomeserverRuntime& runtime, std::string_view room_id,
                                         std::string_view event_id, std::string_view cosigned_event_json) -> bool
{
    auto& store = runtime.database.persistent_store;
    auto const stored = store.events.find(event_id);
    if (stored == store.events.end() || stored->room_id != room_id)
    {
        return false;
    }
    return database::replace_event_json(store, event_id, std::string{cosigned_event_json});
}

auto queue_remote_invite(HomeserverRuntime& runtime, std::string_view room_id, std::string_view invitee_server,
                         std::string_view event_id, std::string_view event_json) -> bool
{
    wire_federation_callbacks(runtime);
    if (runtime.dispatch_worker == nullptr)
    {
        return false;
    }
    auto const& store = runtime.database.persistent_store;
    auto transaction = federation::make_outbound_invite(invitee_server, runtime.config.server().server_name, room_id,
                                                        event_id, stored_room_version(store, room_id).value_or("10"),
                                                        event_json, stripped_state_pdus(store, room_id));
    transaction.transaction_id = federation::make_federation_transaction_id();
    return runtime.dispatch_worker->enqueue(std::move(transaction));
}

namespace
{

    // True when the room's auth rules, applied to `composed` against the room's CURRENT state, still allow it. The
    // compose step judged the event against the state of its time; an offer to another server runs with
    // runtime.mutex released, so the inviter's power level or standing may have changed since (C18). Reads the
    // runtime, so the caller holds runtime.mutex.
    [[nodiscard]] auto composed_event_is_still_authorised(HomeserverRuntime& runtime, std::string_view room_id,
                                                          std::string_view sender, ComposedEvent const& composed)
        -> bool
    {
        auto const* policy = rooms::find_room_version_policy(composed.room_version);
        auto const parsed = canonicaljson::parse_lossless(composed.json);
        if (policy == nullptr || parsed.error != canonicaljson::ParseError::none)
        {
            return false;
        }
        auto const auth_map =
            build_auth_event_map(runtime.database.persistent_store, room_id, sender,
                                 composed.state_key.value_or(std::string{}), composed.event_type, parsed.value);
        auto const decision = events::authorize_event_against_auth_events(parsed.value, *policy, auth_map);
        if (!decision.allowed)
        {
            log_diagnostic("event.auth.rejected", {
                                                      {"room_id",    std::string{room_id},            false},
                                                      {"sender",     std::string{sender},             false},
                                                      {"event_type", composed.event_type,             false},
                                                      {"rule_hook",  std::string{decision.rule_hook}, false},
                                                      {"rule_step",  std::string{decision.rule_step}, false},
                                                      {"reason",     std::string{decision.reason},    false}
            });
        }
        return decision.allowed;
    }

    // The tail shared by an invite a client sends (`invite_user`) and one issued for a third-party invite
    // (`exchange_third_party_invite`): `invite_event` is composed and signed for a user of ANOTHER server and not yet
    // stored. It is offered to that user's server, then stored and sent to the room's other servers
    // (Server-Server API, "Inviting to a room"). Runs with `guard` held, releasing it for the exchange; `client_key`
    // names the ADR-0079 outbound budget the offer draws on.
    [[nodiscard]] auto offer_and_store_remote_invite(HomeserverRuntime& runtime, RuntimeLock& guard,
                                                     std::string_view room_id, std::string const& inviter,
                                                     std::string_view target_user_id, ComposedEvent invite_event,
                                                     std::string_view client_key) -> OperationResult
    {
        auto const invitee_server = std::string{auth::user_id_server_name(target_user_id)};
        // ADR-0079: the offer holds a client-outbound slot, waited for within its deadline (ADR-0306). The wait
        // releases runtime.mutex, as the exchange does; the room is found again below. With no slot the invite
        // takes the unreachable path: queued, and stored only if the queue takes it (ADR-0307).
        auto const offer_deadline =
            OutboundDeadline{effective_client_outbound_deadline(runtime, remote_invite_offer_seconds)};
        auto const offer_slot =
            admit_client_outbound_proxy_waiting(runtime, std::string{client_key}, guard, offer_deadline);
        // A slot taken on the last poll can come after the deadline. Read the time left once: remaining_seconds()
        // rounds up, so 0 means it has passed, and a 0 passed on would mean "the outbound default" to
        // deliver_remote_invite.
        auto const seconds_left = offer_deadline.remaining_seconds();
        auto const delivery =
            offer_slot.has_value() && seconds_left > 0U
                ? deliver_remote_invite(runtime, guard, room_id, invitee_server, invite_event.event_id,
                                        invite_event.json, seconds_left)
                : RemoteInviteResult{RemoteInviteOutcome::unreachable, 503U, "no client-outbound slot for the offer"};
        if (delivery.outcome == RemoteInviteOutcome::refused)
        {
            auto refused = make_operation_result(false, {}, delivery.reason, delivery.status);
            refused.errcode = delivery.errcode;
            return refused;
        }

        // runtime.mutex was down for the exchange: the room, or the inviter's place in it, may have changed.
        auto* room = find_room(runtime.database, room_id);
        if (room == nullptr)
        {
            return make_operation_result(false, {}, "room not found", 404U);
        }
        if (!room_has_member(*room, inviter))
        {
            return make_operation_result(false, {}, "user is not joined", 403U);
        }
        // Being joined is not enough: the inviter may have been banned, or lost the power to invite, during the
        // exchange. The event composed before it is judged again against the current state (C18).
        if (!composed_event_is_still_authorised(runtime, room_id, inviter, invite_event))
        {
            return make_operation_result(false, {}, "inviter is no longer allowed to invite", 403U);
        }
        if (delivery.outcome == RemoteInviteOutcome::delivered)
        {
            // Signed by both servers now: this is the event that is stored and sent to the room's servers.
            invite_event.json = delivery.cosigned_event_json;
            invite_event.signatures.insert(invite_event.signatures.end(), delivery.cosigned_signatures.begin(),
                                           delivery.cosigned_signatures.end());
        }
        // An unreachable invitee's server gets the invite from the retry queue. Queued before the invite is
        // stored: once stored, the invite cannot be taken back, and an invite that was neither delivered nor
        // queued reaches nobody, so the client must not be told it was sent (ADR-0307).
        if (delivery.outcome == RemoteInviteOutcome::unreachable &&
            !queue_remote_invite(runtime, room_id, invitee_server, invite_event.event_id, invite_event.json))
        {
            log_diagnostic("room.invite.not_queued",
                           {
                               {"actor",          inviter,                     false},
                               {"room_id",        std::string{room_id},        false},
                               {"invitee_server", std::string{invitee_server}, false}
            },
                           observability::LogEventSeverity::warning);
            return make_operation_result(false, {}, "the invitee's server cannot be reached and no retry can be queued",
                                         503U);
        }
        auto const stored =
            store_composed_membership(runtime, room_id, inviter, target_user_id, "invite", invite_event);
        if (!stored.ok)
        {
            return stored;
        }
        append_local_audit(runtime.database, observability::AuditCategory::admin, "room.invited", inviter,
                           target_user_id, std::string{room_id});
        notify_room_changed(runtime, room_id);
        return make_operation_result(true, std::string{room_id});
    }

} // namespace

[[nodiscard]] auto invite_user(HomeserverRuntime& runtime, std::string_view access_token, std::string_view room_id,
                               std::string_view target_user_id, std::string_view reason, std::string_view client_key)
    -> OperationResult
{
    auto guard = RuntimeLock{runtime.mutex};
    auto const user_id = authenticated_user(runtime, access_token);
    if (!user_id.has_value())
    {
        return make_operation_result(false, {}, "unauthenticated", 401U);
    }
    // F-20. The invitee may be on another server, so the federated user ID grammar applies. Refused before any
    // event is composed: an invalid state_key must never reach the room.
    if (!auth::user_id_is_valid_federated(target_user_id))
    {
        auto result = make_operation_result(false, {}, "user_id is not a valid Matrix user ID", 400U);
        result.errcode = "M_INVALID_PARAM";
        return result;
    }
    auto* room = find_room(runtime.database, room_id);
    if (room == nullptr)
    {
        return make_operation_result(false, {}, "room not found", 404U);
    }
    if (!room_has_member(*room, *user_id))
    {
        return make_operation_result(false, {}, "user is not joined", 403U);
    }
    if (auto refused = sync_stream_refusal(runtime); refused.has_value())
    {
        return *refused;
    }

    auto const invitee_server = std::string{auth::user_id_server_name(target_user_id)};
    if (invitee_server.empty() || invitee_server == runtime.config.server().server_name)
    {
        if (invite_permission_blocks(runtime.database.persistent_store, target_user_id))
        {
            return invite_blocked_result();
        }
        auto const result = persist_membership_transition(runtime, room_id, *user_id, target_user_id, "invite", reason);
        if (!result.ok)
        {
            return result;
        }
        append_local_audit(runtime.database, observability::AuditCategory::admin, "room.invited", *user_id,
                           target_user_id, std::string{room_id});
        notify_room_changed(runtime, room_id);
        return make_operation_result(true, std::string{room_id});
    }

    // Server-Server API, "Inviting to a room": "when a user invites another user on a different homeserver,
    // a request to that homeserver to have the event signed and verified must be made", and "Once the event
    // has been signed by both the inviting homeserver and the invited homeserver, it can be sent to all of
    // the servers in the room". So the invite is composed, offered to the invitee's server, and only then
    // stored and sent on to the room's other servers. A client that is told the invite succeeded can rely
    // on the invitee's server holding it (Complement TestFederationRejectInvite).
    auto composed = compose_membership_transition(runtime, room_id, *user_id, target_user_id, "invite", reason);
    if (!composed.event.has_value())
    {
        return composed.failure;
    }
    return offer_and_store_remote_invite(runtime, guard, room_id, *user_id, target_user_id, std::move(*composed.event),
                                         client_key);
}

namespace
{

    // The `display_name` of the room's `m.room.third_party_invite` for `token`, or nullopt when the room has none.
    [[nodiscard]] auto third_party_invite_display_name(database::PersistentStore const& store, std::string_view room_id,
                                                       std::string_view token) -> std::optional<std::string>
    {
        auto const event_id = database::find_current_state_event_id(store, room_id, "m.room.third_party_invite", token);
        if (!event_id.has_value())
        {
            return std::nullopt;
        }
        auto const event = find_event_json(store, *event_id);
        auto const* object = std::get_if<canonicaljson::Object>(&event.storage());
        auto const* content_value = object == nullptr ? nullptr : object_member(*object, "content");
        auto const* content =
            content_value == nullptr ? nullptr : std::get_if<canonicaljson::Object>(&content_value->storage());
        auto const* display_name = content == nullptr ? nullptr : string_member(*content, "display_name");
        return display_name == nullptr ? std::string{} : *display_name;
    }

    [[nodiscard]] auto third_party_member_event_json(std::string_view target_user_id, std::string_view display_name,
                                                     std::string_view signed_json) -> std::optional<std::string>
    {
        auto const signed_value = canonicaljson::parse_json(signed_json);
        if (signed_value.error != canonicaljson::ParseError::none)
        {
            return std::nullopt;
        }
        auto invite = canonicaljson::Object{};
        invite.push_back(canonicaljson::make_member("display_name", canonicaljson::Value{std::string{display_name}}));
        invite.push_back(canonicaljson::make_member("signed", signed_value.value));
        auto content = canonicaljson::Object{};
        content.push_back(canonicaljson::make_member("membership", canonicaljson::Value{std::string{"invite"}}));
        content.push_back(canonicaljson::make_member("third_party_invite", canonicaljson::Value{std::move(invite)}));
        auto event = canonicaljson::Object{};
        event.push_back(canonicaljson::make_member("type", canonicaljson::Value{std::string{"m.room.member"}}));
        event.push_back(canonicaljson::make_member("state_key", canonicaljson::Value{std::string{target_user_id}}));
        event.push_back(canonicaljson::make_member("content", canonicaljson::Value{std::move(content)}));
        return serialize_canonical_string(canonicaljson::Value{std::move(event)});
    }

} // namespace

auto exchange_third_party_invite(HomeserverRuntime& runtime, federation::ThirdPartyInviteExchange const& exchange,
                                 std::string_view client_key) -> OperationResult
{
    auto guard = RuntimeLock{runtime.mutex};
    if (auto refused = sync_stream_refusal(runtime); refused.has_value())
    {
        return *refused;
    }
    // This server can sign only for its own users (ADR-0485): the spec's caller asks "the inviting homeserver", which
    // is the server of the user who sent the original m.room.third_party_invite.
    auto const& our_server = runtime.config.server().server_name;
    if (auth::user_id_server_name(exchange.sender) != our_server)
    {
        return make_operation_result(false, {}, "the sender of the third-party invite is not a user of this server",
                                     403U);
    }
    auto* room = find_room(runtime.database, exchange.room_id);
    if (room == nullptr)
    {
        return make_operation_result(false, {}, "room not found", 404U);
    }
    if (!room_has_member(*room, exchange.sender))
    {
        return make_operation_result(false, {}, "the sender of the third-party invite is not in the room", 403U);
    }
    auto const& store = runtime.database.persistent_store;
    auto const display_name = third_party_invite_display_name(store, exchange.room_id, exchange.signed_invite.token);
    if (!display_name.has_value())
    {
        return make_operation_result(false, {}, "the room has no third-party invite for the token", 403U);
    }
    // The auth rules let a third-party invite stand in for the usual membership checks, so a member who is already
    // in the room, or banned, would be moved to `invite` by a replayed `signed` object (ADR-0485).
    auto const membership = current_membership_of(store, exchange.room_id, exchange.target_user_id);
    if (membership == "join" || membership == "ban")
    {
        return make_operation_result(false, {}, "the invited user is already in the room or banned from it", 403U);
    }
    if (membership == "invite")
    {
        return make_operation_result(true, exchange.room_id);
    }
    auto const target_is_local = auth::user_id_server_name(exchange.target_user_id) == our_server;
    if (target_is_local && !std::ranges::any_of(runtime.database.users, [&](LocalUser const& user) {
            return user.user_id == exchange.target_user_id && !user.deactivated;
        }))
    {
        return make_operation_result(false, {}, "the invited user is not a user of this server", 404U);
    }
    // A local invitee who blocks invites (SS7, ADR-0552) is refused here as on every other invite path, before an
    // event is composed or signed.
    if (target_is_local && invite_permission_blocks(store, exchange.target_user_id))
    {
        return invite_blocked_result();
    }
    auto const event_json =
        third_party_member_event_json(exchange.target_user_id, *display_name, exchange.signed_invite.json);
    if (!event_json.has_value())
    {
        return make_operation_result(false, {}, "the signed object could not be read", 400U);
    }
    // Composing runs the full authorisation rules, rule 4.3.1 among them: the matching m.room.third_party_invite,
    // the sender being its sender, and a signature in `signed` that verifies against one of its public keys. Anything
    // else is refused here, before an event exists.
    auto composition = compose_signed_event(runtime, exchange.room_id, exchange.sender, *event_json);
    if (composition.failure == ComposeFailure::too_large)
    {
        return event_too_large_result();
    }
    if (!composition.event.has_value())
    {
        log_diagnostic("room.third_party_invite.exchange_refused",
                       {
                           {"room_id", exchange.room_id,                     false},
                           {"sender",  exchange.sender,                      false},
                           {"target",  exchange.target_user_id,              false},
                           {"reason",  "the third-party invite was refused", false}
        },
                       observability::LogEventSeverity::warning);
        return make_operation_result(false, {}, "the third-party invite was not authorised", 403U);
    }
    auto result = OperationResult{};
    if (target_is_local)
    {
        result = store_composed_membership(runtime, exchange.room_id, exchange.sender, exchange.target_user_id,
                                           "invite", *composition.event);
        if (result.ok)
        {
            append_local_audit(runtime.database, observability::AuditCategory::admin, "room.invited", exchange.sender,
                               exchange.target_user_id, exchange.room_id);
            notify_room_changed(runtime, exchange.room_id);
        }
    }
    else
    {
        result = offer_and_store_remote_invite(runtime, guard, exchange.room_id, exchange.sender,
                                               exchange.target_user_id, std::move(*composition.event), client_key);
    }
    if (result.ok)
    {
        log_diagnostic("room.third_party_invite.exchanged",
                       {
                           {"room_id", exchange.room_id,        false},
                           {"sender",  exchange.sender,         false},
                           {"target",  exchange.target_user_id, false}
        },
                       observability::LogEventSeverity::info);
    }
    return result;
}

auto request_third_party_invite_exchange(HomeserverRuntime& runtime,
                                         federation::ThirdPartyInviteExchange const& exchange,
                                         std::uint32_t timeout_seconds) -> OperationResult
{
    auto guard = RuntimeLock{runtime.mutex};
    wire_federation_callbacks(runtime);
    auto const destination = std::string{auth::user_id_server_name(exchange.sender)};
    auto const body = federation::build_third_party_invite_exchange_body(exchange);
    if (destination.empty() || destination == runtime.config.server().server_name || body.empty())
    {
        return make_operation_result(false, {}, "the third-party invite cannot be forwarded", 400U);
    }
    auto const signing_key = find_active_server_signing_key(runtime);
    if (!signing_key.has_value())
    {
        return make_operation_result(false, {}, "server signing key not available", 502U);
    }
    auto const transaction = federation::make_outbound_exchange_third_party_invite(
        destination, runtime.config.server().server_name, exchange.room_id, body);
    auto const key_id = signing_key->key_id;
    auto secret_key = core::SecretBuffer{runtime.database.signing_secret_key.bytes()};
    auto const call = std::invoke([&] {
        auto const released = RuntimeLockRelease{guard};
        return perform_bounded_outbound_call_with_status(runtime, OutboundAnswerTrust::unverified, exchange.room_id,
                                                         transaction, key_id, std::move(secret_key),
                                                         "room.third_party_invite.forward_failed", timeout_seconds);
    });
    if (!call.ok)
    {
        return make_operation_result(false, {}, "the inviting server did not accept the exchange",
                                     call.remote_status == 0U ? std::uint16_t{502U} : call.remote_status);
    }
    return make_operation_result(true, exchange.room_id);
}

auto notify_third_party_bind(HomeserverRuntime& runtime, federation::ThirdPartyBindNotification const& notification,
                             std::string_view client_key) -> OperationResult
{
    // `/3pid/onbind` has no authentication (Server-Server API: "Requires authentication: No"), so what it can cost is
    // bounded here (ADR-0484): one outbound slot for the whole request, one deadline for every invite in it, at most
    // `max_third_party_bind_invites` of them, and each one is acted on only if the user it names is an account here.
    // Nothing is believed from the body: the signature on each `signed` is checked by the server that holds the room.
    auto const slot = admit_client_outbound_proxy(runtime, std::string{client_key});
    if (!slot.has_value())
    {
        return make_operation_result(false, {}, "too many outbound requests", 429U);
    }
    {
        auto const guard = RuntimeLock{runtime.mutex};
        // An unknown, deactivated or foreign user is answered like a known one, so the endpoint tells nobody which
        // accounts exist.
        auto const known = auth::user_id_server_name(notification.mxid) == runtime.config.server().server_name &&
                           std::ranges::any_of(runtime.database.users, [&](LocalUser const& user) {
                               return user.user_id == notification.mxid && !user.deactivated;
                           });
        if (!known)
        {
            return make_operation_result(true, {});
        }
    }
    if (notification.dropped != 0U)
    {
        // Entries past the cap, malformed ones and ones naming another user: counted by the parser, never acted on.
        log_diagnostic("room.third_party_invite.bind_invites_dropped",
                       {
                           {"user_id", notification.mxid,                           false},
                           {"dropped", std::to_string(notification.dropped),        false},
                           {"kept",    std::to_string(notification.invites.size()), false}
        },
                       observability::LogEventSeverity::warning);
    }
    auto const deadline = OutboundDeadline{effective_client_outbound_deadline(runtime, remote_invite_offer_seconds)};
    for (auto const& invite : notification.invites)
    {
        auto const seconds_left = deadline.remaining_seconds();
        if (seconds_left == 0U)
        {
            break;
        }
        auto const exchange = federation::ThirdPartyInviteExchange{invite.room_id, invite.sender, notification.mxid,
                                                                   invite.signed_invite};
        auto const own_user = std::invoke([&] {
            auto const guard = RuntimeLock{runtime.mutex};
            return auth::user_id_server_name(invite.sender) == runtime.config.server().server_name;
        });
        auto const outcome = own_user ? exchange_third_party_invite(runtime, exchange, client_key)
                                      : request_third_party_invite_exchange(runtime, exchange, seconds_left);
        if (!outcome.ok)
        {
            log_diagnostic("room.third_party_invite.bind_invite_failed",
                           {
                               {"room_id", invite.room_id,                 false},
                               {"sender",  invite.sender,                  false},
                               {"status",  std::to_string(outcome.status), false}
            },
                           observability::LogEventSeverity::warning);
        }
    }
    return make_operation_result(true, {});
}

namespace
{

    // What the identity-server round trip in `invite_user_by_threepid` hands back
    // across the re-lock. An engaged `failure` means the IS did not produce a
    // usable invite, and the caller returns it verbatim.
    struct ThirdPartyInviteFetch final
    {
        std::optional<OperationResult> failure{};
        std::string event_json{};
    };

    [[nodiscard]] auto third_party_invite_failure(std::string reason, std::uint16_t status) -> ThirdPartyInviteFetch
    {
        auto fetch = ThirdPartyInviteFetch{};
        fetch.failure = make_operation_result(false, {}, std::move(reason), status);
        return fetch;
    }

} // namespace

[[nodiscard]] auto invite_user_by_threepid(HomeserverRuntime& runtime, std::string_view access_token,
                                           std::string_view room_id, std::string_view id_server,
                                           std::string_view medium, std::string_view address,
                                           std::string_view id_access_token, std::uint32_t max_total_seconds)
    -> OperationResult
{
    // The identity server — not the homeserver — generates the invite token and
    // the ephemeral key that signs the join-side `signed` blob. A local-only
    // invite would be unverifiable on join, so this function refuses to mint one
    // unless `id_server` is an operator-trusted IS it can actually reach, and
    // fails closed on any IS error. Spec: client-server-api.md § Inviting a user
    // via a third-party identifier; identity-service-api.md § store-invite.
    auto guard = RuntimeLock{runtime.mutex};

    // Validation under the lock: auth, room, membership, and that `id_server`
    // names an operator-trusted identity server.
    auto const user_id = authenticated_user(runtime, access_token);
    if (!user_id.has_value())
    {
        return make_operation_result(false, {}, "unauthenticated", 401U);
    }
    if (auto refused = sync_stream_refusal(runtime); refused.has_value())
    {
        return *refused;
    }
    auto* room = find_room(runtime.database, room_id);
    if (room == nullptr)
    {
        return make_operation_result(false, {}, "room not found", 404U);
    }
    if (!room_has_member(*room, *user_id))
    {
        return make_operation_result(false, {}, "user is not joined", 403U);
    }

    auto const& identity_config = runtime.config.server().identity_server;
    auto const parsed_base = merovingian::identity::parse_identity_server_url("https://" + std::string{id_server});
    if (!parsed_base.has_value())
    {
        return make_operation_result(false, {}, "identity server is not trusted", 403U);
    }
    // Match the client-supplied `id_server` (a host[:port]) against a trusted
    // IS base URL by host+port, then use the trusted entry as the call target so
    // an operator-configured path prefix is preserved.
    auto const trusted_match =
        std::ranges::find_if(identity_config.trusted_servers, [&parsed_base](std::string const& trusted) {
            auto const parsed_trusted = merovingian::identity::parse_identity_server_url(trusted);
            return parsed_trusted.has_value() && parsed_trusted->host == parsed_base->host &&
                   parsed_trusted->port == parsed_base->port;
        });
    if (trusted_match == identity_config.trusted_servers.end())
    {
        return make_operation_result(false, {}, "identity server is not trusted", 403U);
    }
    if (!merovingian::identity::threepid_bind_domain_permitted(identity_config.allowed_bind_domains, medium, address))
    {
        auto denied = make_operation_result(
            false, {}, "this server does not permit that third-party identifier to be sent to an identity server",
            403U);
        denied.errcode = "M_THREEPID_DENIED";
        return denied;
    }
    auto const base_url = std::string{*trusted_match};

    // The IS store-invite round trip is network-bound and runs with
    // runtime.mutex released. RuntimeLockRelease drops every recursion level
    // this thread holds, not just this function’s own guard: the client-server
    // dispatcher already holds the mutex for the whole request, so releasing
    // one level left it locked for the length of the IS call and stalled every
    // other request behind it — the 0.12.1 create_room defect and the 0.12.3
    // leave_room defect, in a third place. Regression cover:
    // tests/integration/test_request_lock_contention_flow.cpp.
    //
    // The block is a lambda so the scope boundary is the lock boundary: every
    // value it produces is returned rather than declared above the release and
    // assigned inside it.
    auto const fetched = [&]() -> ThirdPartyInviteFetch {
        auto const released = RuntimeLockRelease{guard};
        if (runtime.outbound_client == nullptr || runtime.cached_discovery == nullptr)
        {
            return third_party_invite_failure("identity server is not reachable", 502U);
        }
        // A caller that shares one deadline among several calls (createRoom's invite_3pid, ADR-0474) passes
        // what is left of it; the configured timeouts then never exceed that.
        auto bounded_config = runtime.config.server().identity_server;
        if (max_total_seconds != 0U)
        {
            bounded_config.total_timeout_seconds = std::min(bounded_config.total_timeout_seconds, max_total_seconds);
            bounded_config.connect_timeout_seconds =
                std::min(bounded_config.connect_timeout_seconds, bounded_config.total_timeout_seconds);
        }
        auto id_client =
            merovingian::identity::IdentityServerClient{*runtime.outbound_client, *runtime.cached_discovery,
                                                        bounded_config, &runtime.test_forced_identity_resolution};
        auto const invite = id_client.store_invite(base_url, id_access_token, medium, address, room_id, *user_id);
        if (!invite.ok)
        {
            return third_party_invite_failure("identity server is not reachable", 502U);
        }
        if (invite.status != 200U)
        {
            // IS-level rejection (e.g. 401 bad id_access_token, 404 unbound
            // 3PID). Fail closed; never fall back to a local-only,
            // unverifiable invite.
            return third_party_invite_failure("identity server rejected the invite", invite.status);
        }
        auto const parsed = merovingian::identity::parse_store_invite_response(invite.body);
        if (!parsed.has_value() || parsed->public_keys.empty())
        {
            return third_party_invite_failure("identity server returned a malformed store-invite response", 502U);
        }

        // The ephemeral key (last entry) signs the join-side `signed` blob; the
        // long-term key is first. Carry the ephemeral key as the top-level
        // public_key and list every key in public_keys so joining servers can
        // verify via key_validity_url.
        auto const& ephemeral = parsed->public_keys.back();
        auto const display_name = parsed->display_name.empty() ? std::string{address} : parsed->display_name;
        auto const serialized = serialize_third_party_invite_event_json(
            parsed->token, ephemeral.public_key, ephemeral.key_validity_url, parsed->public_keys, display_name);
        if (!serialized.has_value())
        {
            return third_party_invite_failure("third-party invite event serialization failed", 500U);
        }
        auto fetch = ThirdPartyInviteFetch{};
        fetch.event_json = *serialized;
        return fetch;
    }();
    if (fetched.failure.has_value())
    {
        return *fetched.failure;
    }
    auto const& event_json = fetched.event_json;

    // Room state may have changed during the IS round-trip, so re-validate now
    // that the mutex is held again.
    auto* room_after = find_room(runtime.database, room_id);
    if (room_after == nullptr)
    {
        return make_operation_result(false, {}, "room not found", 404U);
    }
    if (!room_has_member(*room_after, *user_id))
    {
        return make_operation_result(false, {}, "user is not joined", 403U);
    }
    auto const composition = compose_signed_event(runtime, room_id, *user_id, event_json);
    if (composition.failure == ComposeFailure::too_large)
    {
        return event_too_large_result();
    }
    auto const& composed = composition.event;
    if (!composed.has_value())
    {
        return make_operation_result(false, {}, "third-party invite event rejected", 403U);
    }
    if (persist_composed_event(runtime, room_id, *user_id, *composed) == PersistOutcome::not_stored)
    {
        return make_operation_result(false, {}, "third-party invite persistence failed", 500U);
    }

    auto* room_for_push = find_room(runtime.database, room_id);
    if (room_for_push != nullptr)
    {
        federate_local_event(runtime, room_id, *room_for_push, *composed);
    }

    auto const sync_stream_id = database::allocate_sync_stream_id(runtime.database.persistent_store);
    if (runtime.sync_notifier != nullptr)
    {
        runtime.sync_notifier->publish(visible_stream_position(runtime.database), sync_stream_id);
    }

    // Push delivery: no real mxid to add as an extra recipient here -- the
    // m.room.third_party_invite event's state_key is a signed token, not a
    // Matrix user ID (the invitee has no account yet; the identity server's
    // store-invite call above is what actually reaches them, by email/SMS).
    // Passing *user_id (the sender) as the "extra recipient" is a no-op --
    // build_pending_push_deliveries always filters the sender out -- so this
    // still routes through the same pipeline as every other membership
    // transition for consistency: today it evaluates to nothing against the
    // default ruleset (see persist_membership_transition's push comment
    // above), but it means any existing joined member's custom push rules
    // still see the event.
    if (room_for_push != nullptr)
    {
        dispatch_membership_push_notification(runtime, *room_for_push, *composed, *user_id, *user_id);
    }

    append_local_audit(runtime.database, observability::AuditCategory::admin, "room.third_party_invited", *user_id,
                       room_id, std::string{address});
    log_diagnostic("room.third_party_invite.accepted",
                   {
                       {"actor",   *user_id,             false},
                       {"room_id", std::string{room_id}, false},
                       {"medium",  std::string{medium},  false},
                       {"address", std::string{address}, false}
    },
                   observability::LogEventSeverity::info);
    notify_room_changed(runtime, room_id);
    return make_operation_result(true, std::string{room_id});
}

[[nodiscard]] auto ban_user(HomeserverRuntime& runtime, std::string_view access_token, std::string_view room_id,
                            std::string_view target_user_id, std::string_view reason) -> OperationResult
{
    auto guard = RuntimeLock{runtime.mutex};
    auto const user_id = authenticated_user(runtime, access_token);
    if (!user_id.has_value())
    {
        return make_operation_result(false, {}, "unauthenticated", 401U);
    }
    if (auto refused = refuse_invalid_membership_target(target_user_id); refused.has_value())
    {
        return *refused;
    }
    auto* room = find_room(runtime.database, room_id);
    if (room == nullptr)
    {
        return make_operation_result(false, {}, "room not found", 404U);
    }
    if (!room_has_member(*room, *user_id))
    {
        return make_operation_result(false, {}, "user is not joined", 403U);
    }

    auto const result = persist_membership_transition(runtime, room_id, *user_id, target_user_id, "ban", reason);
    if (!result.ok)
    {
        return result;
    }
    append_local_audit(runtime.database, observability::AuditCategory::admin, "room.banned", *user_id, target_user_id,
                       std::string{room_id});
    notify_room_changed(runtime, room_id);
    return make_operation_result(true, std::string{room_id});
}

[[nodiscard]] auto kick_user(HomeserverRuntime& runtime, std::string_view access_token, std::string_view room_id,
                             std::string_view target_user_id, std::string_view reason) -> OperationResult
{
    auto guard = RuntimeLock{runtime.mutex};
    auto const user_id = authenticated_user(runtime, access_token);
    if (!user_id.has_value())
    {
        return make_operation_result(false, {}, "unauthenticated", 401U);
    }
    if (auto refused = refuse_invalid_membership_target(target_user_id); refused.has_value())
    {
        return *refused;
    }
    auto* room = find_room(runtime.database, room_id);
    if (room == nullptr)
    {
        return make_operation_result(false, {}, "room not found", 404U);
    }
    if (!room_has_member(*room, *user_id))
    {
        return make_operation_result(false, {}, "user is not joined", 403U);
    }

    // Spec (POST /kick, 403): "The kickee is not currently in the room." A user is in the room
    // while their membership is join, invite or knock, the three states a leave event can end
    // (room version auth rules, `m.room.member` with membership `leave`). A user who left, was
    // banned (unban is the way out) or never had a membership is not in the room.
    auto const target_membership = std::ranges::find_if(
        runtime.database.persistent_store.memberships, [&](database::PersistentMembership const& current) {
            return current.room_id == room_id && current.user_id == target_user_id;
        });
    if (target_membership == runtime.database.persistent_store.memberships.end() ||
        (target_membership->membership != "join" && target_membership->membership != "invite" &&
         target_membership->membership != "knock"))
    {
        return make_operation_result(false, {}, "the user is not currently in the room", 403U);
    }

    auto const result = persist_membership_transition(runtime, room_id, *user_id, target_user_id, "leave", reason);
    if (!result.ok)
    {
        return result;
    }
    append_local_audit(runtime.database, observability::AuditCategory::admin, "room.kicked", *user_id, target_user_id,
                       std::string{room_id});
    notify_room_changed(runtime, room_id);
    return make_operation_result(true, std::string{room_id});
}

[[nodiscard]] auto unban_user(HomeserverRuntime& runtime, std::string_view access_token, std::string_view room_id,
                              std::string_view target_user_id) -> OperationResult
{
    auto guard = RuntimeLock{runtime.mutex};
    auto const user_id = authenticated_user(runtime, access_token);
    if (!user_id.has_value())
    {
        return make_operation_result(false, {}, "unauthenticated", 401U);
    }
    if (auto refused = refuse_invalid_membership_target(target_user_id); refused.has_value())
    {
        return *refused;
    }
    auto* room = find_room(runtime.database, room_id);
    if (room == nullptr)
    {
        return make_operation_result(false, {}, "room not found", 404U);
    }
    if (!room_has_member(*room, *user_id))
    {
        return make_operation_result(false, {}, "user is not joined", 403U);
    }

    auto const membership = std::ranges::find_if(
        runtime.database.persistent_store.memberships, [&](database::PersistentMembership const& current) {
            return current.room_id == room_id && current.user_id == target_user_id;
        });
    if (membership == runtime.database.persistent_store.memberships.end() || membership->membership != "ban")
    {
        return make_operation_result(false, {}, "user is not banned", 403U);
    }

    auto const result = persist_membership_transition(runtime, room_id, *user_id, target_user_id, "leave");
    if (!result.ok)
    {
        return result;
    }
    append_local_audit(runtime.database, observability::AuditCategory::admin, "room.unbanned", *user_id, target_user_id,
                       std::string{room_id});
    notify_room_changed(runtime, room_id);
    return make_operation_result(true, std::string{room_id});
}

[[nodiscard]] auto forget_room(HomeserverRuntime& runtime, std::string_view access_token, std::string_view room_id)
    -> OperationResult
{
    auto guard = RuntimeLock{runtime.mutex};
    auto const user_id = authenticated_user(runtime, access_token);
    if (!user_id.has_value())
    {
        return make_operation_result(false, {}, "unauthenticated", 401U);
    }
    if (!room_exists(runtime, room_id))
    {
        return make_operation_result(false, {}, "room not found", 404U);
    }

    auto const membership = std::ranges::find_if(runtime.database.persistent_store.memberships,
                                                 [&](database::PersistentMembership const& current) {
                                                     return current.room_id == room_id && current.user_id == *user_id;
                                                 });
    if (membership == runtime.database.persistent_store.memberships.end())
    {
        return make_operation_result(false, {}, "user has no membership in room", 403U);
    }
    if (membership->membership != "leave" && membership->membership != "ban")
    {
        return make_operation_result(false, {}, "user must leave room before forgetting", 400U);
    }
    // ADR-0315: before the delete, so a counter at its ceiling leaves the membership in place.
    auto sync_stream_id = std::uint64_t{0U};
    try
    {
        sync_stream_id = database::allocate_sync_stream_id(runtime.database.persistent_store);
    }
    catch (std::overflow_error const&)
    {
        return make_operation_result(false, {}, "sync stream counter exhausted", 500U);
    }
    if (!database::delete_membership(runtime.database.persistent_store, room_id, *user_id))
    {
        return make_operation_result(false, {}, "membership delete failed", 500U);
    }
    if (!database::delete_invite(runtime.database.persistent_store, room_id, *user_id))
    {
        return make_operation_result(false, {}, "invite metadata cleanup failed", 500U);
    }

    if (runtime.sync_notifier != nullptr)
    {
        runtime.sync_notifier->publish(visible_stream_position(runtime.database), sync_stream_id);
    }
    append_local_audit(runtime.database, observability::AuditCategory::admin, "room.forgotten", *user_id, room_id,
                       "forgotten");
    return make_operation_result(true, std::string{room_id});
}

namespace
{

    // What a knock on a room on another server comes to, produced with
    // runtime.mutex released: a failure, or the signed knock event and the
    // resident's knock_room_state entries whose signatures checked out.
    struct FederatedKnockOutcome final
    {
        std::optional<OperationResult> failure{};
        std::string event_id{};
        std::string signed_event_json{};
        std::vector<std::string> knock_state_json{};
        // The resident that accepted the knock: where its withdrawal goes (ADR-0251).
        std::string resident_server{};
    };

    [[nodiscard]] auto federated_knock_failure(std::string reason, std::uint16_t status) -> FederatedKnockOutcome
    {
        auto outcome = FederatedKnockOutcome{};
        outcome.failure = make_operation_result(false, {}, std::move(reason), status);
        return outcome;
    }

    // The knock_room_state array of a send_knock response, or nullptr.
    [[nodiscard]] auto knock_room_state_of(canonicaljson::Value const& response) -> canonicaljson::Array const*
    {
        auto const* object = std::get_if<canonicaljson::Object>(&response.storage());
        auto const* value = object == nullptr ? nullptr : object_member(*object, "knock_room_state");
        return value == nullptr ? nullptr : std::get_if<canonicaljson::Array>(&value->storage());
    }

    // make_knock, sign, send_knock (Server-Server API, "Knocking upon a room").
    // Everything it reads from runtime state is passed in; it runs with
    // runtime.mutex released, so it must not touch state the mutex guards.
    [[nodiscard]] auto perform_federated_knock(HomeserverRuntime& runtime, std::string_view room_id,
                                               std::string const& user_id, std::string_view reason,
                                               std::vector<std::string> const& candidates,
                                               std::string const& our_server,
                                               database::PersistentServerSigningKey const& signing_key,
                                               core::SecretBuffer const& secret_key) -> FederatedKnockOutcome
    {
        // Only versions that define the knock membership (v7+) are offered.
        auto supported_versions = std::vector<std::string>{};
        for (auto const& policy : rooms::known_room_versions())
        {
            if (policy.knock_join_rule)
            {
                supported_versions.emplace_back(policy.id);
            }
        }
        auto remote_server = std::string{};
        auto make_body = std::string{};
        auto last_error = std::string{"no server offered a knock template"};
        auto refused = false;
        // One deadline for every make_knock attempt and the send_knock, as join_room
        // bounds its race: a client naming many unreachable servers must not hold a
        // request thread for one remote timeout per server.
        auto const deadline = OutboundDeadline{runtime.federation.config.join_race_deadline_seconds > 0U
                                                   ? runtime.federation.config.join_race_deadline_seconds
                                                   : runtime.federation.config.remote_timeout_seconds};
        auto const call_timeout = [&runtime, &deadline] {
            return std::min(runtime.federation.config.remote_timeout_seconds, deadline.remaining_seconds());
        };
        // Passed with each call so the time server discovery takes counts against the
        // deadline too: perform_outbound_call recomputes what is left after it.
        auto const bounds = std::optional<BoundedOutboundLimits>{
            BoundedOutboundLimits{deadline,
                                  std::chrono::seconds{runtime.client_outbound_proxy_policy.worker_margin_seconds}}
        };
        for (auto const& candidate : candidates)
        {
            if (call_timeout() == 0U)
            {
                last_error = "knock deadline exceeded";
                break;
            }
            log_diagnostic("room.knock.remote.make_knock", {
                                                               {"actor",         user_id,              false},
                                                               {"room_id",       std::string{room_id}, false},
                                                               {"remote_server", candidate,            false}
            });
            auto const tx =
                federation::make_outbound_make_membership(federation::FederationEndpoint::make_knock, candidate,
                                                          our_server, room_id, user_id, supported_versions);
            auto call =
                perform_outbound_call(runtime, OutboundAnswerTrust::unverified, room_id, tx, signing_key.key_id,
                                      core::SecretBuffer{secret_key.bytes()}, "room.knock.remote.make_knock_failed",
                                      call_timeout(), membership_template_max_response_bytes, bounds);
            if (call.ok)
            {
                remote_server = candidate;
                make_body = std::move(call.body);
                break;
            }
            refused = refused || call.remote_status == 403U;
            last_error = std::move(call.body);
        }
        if (remote_server.empty())
        {
            // Spec (CS API, POST /knock, 403): "You are not allowed to knock on the room."
            return federated_knock_failure("make_knock failed: " + last_error, refused ? 403U : 502U);
        }

        auto const make_response = canonicaljson::parse_lossless(make_body);
        auto const* make_object = std::get_if<canonicaljson::Object>(&make_response.value.storage());
        if (make_response.error != canonicaljson::ParseError::none || make_object == nullptr)
        {
            return federated_knock_failure("malformed make_knock response", 502U);
        }
        auto const validated = validate_make_knock_event(room_id, user_id, *make_object);
        if (!validated.ok)
        {
            return federated_knock_failure(validated.reason, 502U);
        }
        auto const* policy = rooms::find_room_version_policy(validated.room_version);
        if (policy == nullptr || !policy->knock_join_rule)
        {
            return federated_knock_failure("room version " + validated.room_version + " does not support knocking",
                                           502U);
        }
        auto event_object = validated.event;
        claim_membership_event_template(event_object, our_server, event_clock_now_ms(runtime));
        // C18: only the membership is kept of the resident's content; the reason is the user's own.
        std::ignore = restrict_membership_template_content(event_object, our_server, false);
        if (!reason.empty())
        {
            auto content = *object_member_as_object(event_object, "content");
            replace_or_add_member(content, "reason", canonicaljson::Value{std::string{reason}});
            replace_or_add_member(event_object, "content", canonicaljson::Value{std::move(content)});
        }
        // Held to the room version's event format before it is hashed and signed as the user's own (F-13).
        if (auto const violation = membership_template_format_refusal(event_object, *policy); !violation.empty())
        {
            return federated_knock_failure("make_knock template refused: " + violation, 502U);
        }
        auto const content_hash = events::make_content_hash(canonicaljson::Value{event_object});
        if (!content_hash.error.empty())
        {
            return federated_knock_failure("knock event content hash failed", 500U);
        }
        auto hashes = canonicaljson::Object{};
        hashes.push_back(canonicaljson::make_member("sha256", canonicaljson::Value{content_hash.sha256}));
        replace_or_add_member(event_object, "hashes", canonicaljson::Value{std::move(hashes)});
        auto key_store = RuntimeSigningKeyStore{our_server, signing_key};
        auto const signed_event = events::sign_event_for_server(canonicaljson::Value{std::move(event_object)}, *policy,
                                                                key_store, *runtime.crypto_provider, our_server);
        if (!signed_event.error.empty())
        {
            return federated_knock_failure("event signing failed", 500U);
        }
        auto const signed_value = canonicaljson::parse_lossless(signed_event.event_json);
        auto const event_id = events::make_reference_hash_event_id(signed_value.value, *policy);
        if (!event_id.error.empty() || event_id.event_id.empty())
        {
            return federated_knock_failure("event_id computation failed", 500U);
        }

        auto const send_tx =
            federation::make_outbound_send_membership(federation::FederationEndpoint::send_knock, remote_server,
                                                      our_server, room_id, event_id.event_id, signed_event.event_json);
        log_diagnostic("room.knock.remote.send_knock", {
                                                           {"actor",         user_id,              false},
                                                           {"room_id",       std::string{room_id}, false},
                                                           {"remote_server", remote_server,        false},
                                                           {"event_id",      event_id.event_id,    false}
        });
        if (call_timeout() == 0U)
        {
            return federated_knock_failure("knock deadline exceeded before send_knock", 502U);
        }
        auto send =
            perform_outbound_call(runtime, OutboundAnswerTrust::unverified, room_id, send_tx, signing_key.key_id,
                                  core::SecretBuffer{secret_key.bytes()}, "room.knock.remote.send_knock_failed",
                                  call_timeout(), knock_answer_max_response_bytes, bounds);
        if (!send.ok)
        {
            return federated_knock_failure("send_knock failed: " + send.body, send.remote_status == 403U ? 403U : 502U);
        }

        // knock_room_state is a list of PDUs; "entries which are improperly signed or
        // formatted SHOULD be removed". Each must name this room and carry a valid
        // signature from its sender's server, as send_join state must. A response
        // without the list still records the knock, which the resident has accepted.
        auto outcome = FederatedKnockOutcome{};
        outcome.event_id = event_id.event_id;
        outcome.signed_event_json = signed_event.event_json;
        outcome.resident_server = remote_server;
        auto const send_response = canonicaljson::parse_lossless(send.body);
        if (auto const* knock_state = knock_room_state_of(send_response.value); knock_state != nullptr)
        {
            // The bounds come first, so a resident's list costs no signature check past them (ADR-0620).
            auto const bounded = bounded_knock_room_state(*knock_state, user_id, *policy);
            auto const verified = filter_verified_send_join_events(
                runtime, filter_send_join_events_for_room(bounded, room_id, *policy), *policy, our_server);
            for (auto const& entry : verified)
            {
                if (auto serialized = canonicaljson::serialize_canonical(events::without_unsigned(entry));
                    serialized.error == canonicaljson::CanonicalJsonError::none)
                {
                    outcome.knock_state_json.push_back(std::move(serialized.output));
                }
            }
        }
        return outcome;
    }

} // namespace

[[nodiscard]] auto knock_room(HomeserverRuntime& runtime, std::string_view access_token, std::string_view room_id,
                              std::vector<std::string> const& via_servers, std::string_view reason,
                              std::string_view client_key) -> OperationResult
{
    auto guard = RuntimeLock{runtime.mutex};
    auto const user_id = authenticated_user(runtime, access_token);
    if (!user_id.has_value())
    {
        return make_operation_result(false, {}, "unauthenticated", 401U);
    }
    if (auto refused = membership_exchange_refusal(runtime, room_id, *user_id); refused.has_value())
    {
        return *refused;
    }
    if (this_server_is_in_room(runtime, room_id))
    {
        auto const result = persist_membership_transition(runtime, room_id, *user_id, *user_id, "knock", reason);
        if (!result.ok)
        {
            return result;
        }
        append_local_audit(runtime.database, observability::AuditCategory::admin, "room.knocked", *user_id, room_id,
                           "knocked");
        return make_operation_result(true, std::string{room_id});
    }

    auto const our_server = std::string{runtime.config.server().server_name};
    auto const candidates = cap_join_candidates(join_candidate_servers(via_servers, room_id, our_server),
                                                runtime.federation.config.join_max_candidates);
    if (candidates.empty())
    {
        return make_operation_result(false, {}, "room not found", 404U);
    }
    wire_federation_callbacks(runtime);
    auto const signing_key = find_active_server_signing_key(runtime);
    if (!signing_key.has_value() || runtime.crypto_provider == nullptr)
    {
        return make_operation_result(false, {}, "server signing key not available", 500U);
    }
    // Past the user's limit the resident is never asked (ADR-0619): a knock it accepted could not be recorded here.
    if (database::invite_is_over_store_caps(
            runtime.database.persistent_store,
            database::PersistentInvite{std::string{room_id}, *user_id, *user_id, {}, {}, {}, 0U, candidates.front()}))
    {
        return make_operation_result(false, {}, "too many knocks are pending for this user", 403U);
    }
    auto const secret_key = core::SecretBuffer{runtime.database.signing_secret_key.bytes()};
    auto const user = *user_id;
    auto const outbound_slot = admit_client_outbound_proxy(runtime, std::string{client_key});
    if (!outbound_slot.has_value())
    {
        return client_outbound_limit_result(runtime);
    }
    auto const exchange = MembershipExchangeClaim{runtime, room_id, user};
    auto knocked = [&] {
        auto const released = RuntimeLockRelease{guard};
        return perform_federated_knock(runtime, room_id, user, reason, candidates, our_server, *signing_key,
                                       secret_key);
    }();
    if (knocked.failure.has_value())
    {
        log_diagnostic("room.knock.rejected",
                       {
                           {"actor",   user,                                    false},
                           {"room_id", std::string{room_id},                    false},
                           {"status",  std::to_string(knocked.failure->status), false},
                           {"reason",  knocked.failure->reason,                 false}
        },
                       observability::LogEventSeverity::warning);
        return *knocked.failure;
    }

    // DB-4: the knock membership and the record /sync shows as knock_state commit
    // together (ADR-0243).
    auto const stream_ordering = allocate_stream_ordering(runtime.database);
    auto record = database::PersistentInvite{std::string{room_id},
                                             user,
                                             user,
                                             knocked.event_id,
                                             knocked.signed_event_json,
                                             std::move(knocked.knock_state_json),
                                             stream_ordering,
                                             std::move(knocked.resident_server)};
    if (!database::store_membership_projection(runtime.database.persistent_store, room_id,
                                               {user, "knock", stream_ordering, std::move(record)}))
    {
        return make_operation_result(false, {}, "membership persistence failed", 500U);
    }
    auto const sync_stream_id = database::allocate_sync_stream_id(runtime.database.persistent_store);
    if (runtime.sync_notifier != nullptr)
    {
        runtime.sync_notifier->publish(visible_stream_position(runtime.database), sync_stream_id);
    }
    append_local_audit(runtime.database, observability::AuditCategory::admin, "room.knocked_remote", user, room_id,
                       "knocked via federation");
    log_diagnostic(
        "room.knock.accepted_remote",
        {
            {"actor",    user,                 false},
            {"room_id",  std::string{room_id}, false},
            {"event_id", knocked.event_id,     false}
    },
        observability::LogEventSeverity::info);
    return make_operation_result(true, std::string{room_id});
}

namespace
{

    // One pusher targeted for delivery, paired with the fully-built Push
    // Gateway API notification body for that specific pusher (counts and the
    // event_id_only field trim are computed per recipient/per pusher, so each
    // delivery gets its own PushGatewayNotification even though several may
    // share the same event).
    // Hashes a string_view the same as the string it views, so a set of strings is searched without
    // building one.
    struct TransparentStringHash final
    {
        using is_transparent = void;

        [[nodiscard]] auto operator()(std::string_view text) const noexcept -> std::size_t
        {
            return std::hash<std::string_view>{}(text);
        }
    };

    // The local users who exist and are not deactivated: what asserted_user_is_active answers for
    // each of them, from one pass over runtime.database.users. A user with no row is not in it,
    // which is how asserted_user_is_active treats one too.
    [[nodiscard]] auto active_local_user_ids(HomeserverRuntime const& runtime)
        -> std::unordered_set<std::string, TransparentStringHash, std::equal_to<>>
    {
        auto active = std::unordered_set<std::string, TransparentStringHash, std::equal_to<>>{};
        for (auto const& user : runtime.database.users)
        {
            if (!user.deactivated)
            {
                active.insert(user.user_id);
            }
        }
        return active;
    }

    struct PendingPushDelivery final
    {
        database::PersistentPusher pusher{};
        push::PushGatewayNotification notification{};
    };

    // Bounds how many of one recipient's registered pushers are processed for
    // a single notify-worthy event. POST /pushers/set (ClientServerRuntime.cpp) has
    // no per-user limit on distinct (app_id, pushkey) pairs, and every later
    // matching event copies the recipient's whole pusher list and processes
    // it SEQUENTIALLY inside one dispatch_push_deliveries background task —
    // up to server.push.total_timeout_seconds (default 30s) per pusher. An
    // unbounded list therefore lets one recipient's pusher count alone keep a
    // task (and repeatedly occupy a background-delivery slot) for minutes to
    // hours. The configured cap bounds sequential gateway calls per event.

    // Reconstructs a spec-shaped `actions` array (Matrix v1.19 CS API
    // §push-rules-api, referenced by GET /notifications' Notification.actions)
    // from a PushEvaluationResult. PushRules.hpp deliberately does not keep
    // the matched rule's raw actions array — it pre-resolves outcomes to
    // notify/tweak_sound/tweak_highlight (see PushEvaluationResult's doc
    // comment) — so this rebuilds the conventional shape ("notify" plus one
    // set_tweak object per active tweak, matching how DefaultPushRuleset.hpp
    // itself writes actions) for storage in PersistentNotification::actions.
    [[nodiscard]] auto push_notification_actions_json(push::PushEvaluationResult const& result) -> std::string
    {
        auto actions = canonicaljson::Array{};
        actions.push_back(canonicaljson::Value{std::string{"notify"}});
        if (result.tweak_sound.has_value())
        {
            auto tweak = canonicaljson::Object{};
            tweak.push_back(canonicaljson::make_member("set_tweak", canonicaljson::Value{std::string{"sound"}}));
            tweak.push_back(canonicaljson::make_member("value", canonicaljson::Value{*result.tweak_sound}));
            actions.push_back(canonicaljson::Value{std::move(tweak)});
        }
        if (result.tweak_highlight)
        {
            auto tweak = canonicaljson::Object{};
            tweak.push_back(canonicaljson::make_member("set_tweak", canonicaljson::Value{std::string{"highlight"}}));
            tweak.push_back(canonicaljson::make_member("value", canonicaljson::Value{true}));
            actions.push_back(canonicaljson::Value{std::move(tweak)});
        }
        return serialize_canonical_string(canonicaljson::Value{std::move(actions)}).value_or(R"(["notify"])");
    }

    // Notes a notification for one email pusher (ADR-0219). A full queue drops it, as push
    // delivery past its caps does (ADR-0028): the notification is still in GET /notifications.
    auto note_email_notification(push::EmailDigestQueue& queue, std::string const& user_id, std::string const& pushkey,
                                 push::EmailDigestPolicy const& policy) -> void
    {
        if (queue.note_notification(push::EmailDigestKey{user_id, pushkey}, std::chrono::steady_clock::now(), policy) ==
            push::EmailDigestAdmission::queue_full)
        {
            log_diagnostic("push.email.dropped",
                           {
                               {"recipient", user_id,      false},
                               {"reason",    "queue full", false}
            },
                           observability::LogEventSeverity::warning);
        }
    }

    // Evaluates push rules for `composed` against every local, joined,
    // eligible (not ignoring the sender) recipient of `room` (everyone except
    // `sender`), plus anyone named in `extra_recipients`, and:
    //   1. Records a GET /_matrix/client/v3/notifications history row (see
    //      database::store_notification) for every recipient whose evaluation
    //      says "notify" — unconditionally, regardless of whether that
    //      recipient has a pusher or `server.push.enabled` is set. Spec: the
    //      endpoint returns events the user "has been, or would have been
    //      notified about" — a user with push turned off must still see this
    //      history when they open the client.
    //   2. Returns one PendingPushDelivery per (recipient, "http" pusher) pair
    //      for Push Gateway delivery — only when push.enabled is set.
    //   3. Notes the notification for each of the recipient's "email" pushers
    //      in runtime.email_digest_queue_ — only when server.email.smtp_url is
    //      set (ADR-0219). Nothing is sent here: the email job sends a delayed,
    //      throttled digest that carries only the unread count.
    //
    // `extra_recipients` exists for membership transitions: an invitee is
    // not a joined member of `room` (store_or_update_membership only adds to
    // room.members on "join" — see apply_runtime_membership), so without it
    // .m.rule.invite_for_me could never reach the person actually being
    // invited. Entries equal to `sender` or already present in room.members
    // are silently skipped, so callers may pass the membership target
    // unconditionally (self-transitions included) without special-casing.
    //
    // In-memory state reads, JSON parsing, and rule evaluation, plus a
    // synchronous local notification-history write per notify-worthy
    // recipient (no network I/O — a single-row SQLite/PostgreSQL insert, the
    // same kind of synchronous write send_event() already does for the event
    // itself). Safe to call under runtime.mutex, which send_event() already
    // holds when it calls this. Only the Push Gateway network calls happen
    // later, off the request path — see dispatch_push_deliveries.
    [[nodiscard]] auto build_pending_push_deliveries(HomeserverRuntime& runtime, LocalRoom const& room,
                                                     ComposedEvent const& composed, std::string_view sender,
                                                     std::span<std::string const> extra_recipients = {})
        -> std::vector<PendingPushDelivery>
    {
        auto deliveries = std::vector<PendingPushDelivery>{};
        auto& store = runtime.database.persistent_store;
        auto const& server_name = runtime.config.server().server_name;
        // Gateway delivery (the network call) is gated on push.enabled — see
        // the `push_delivery_enabled` check below and run_pending_push_
        // deliveries — but rule evaluation and notification-history recording
        // are not: see this function's doc comment above.
        auto const push_delivery_enabled = runtime.config.server().push.enabled;
        // Email pushers have their own switch: an SMTP relay is configured (ADR-0219).
        auto const email_delivery_enabled =
            email_push_configured(runtime.config) && runtime.email_digest_queue_ != nullptr;
        auto const email_policy =
            push::EmailDigestPolicy{std::chrono::seconds{runtime.config.server().email.notification_delay_seconds},
                                    std::chrono::seconds{runtime.config.server().email.notification_throttle_seconds}};

        auto event_parsed = canonicaljson::parse_lossless(composed.json);
        if (event_parsed.error != canonicaljson::ParseError::none)
        {
            return deliveries;
        }

        // ComposedEvent::stream_ordering is always 0 -- compose_signed_event
        // builds it before the real position is allocated (allocate_stream_
        // ordering runs afterwards, in persist_composed_event/send_event) and
        // never writes the allocated value back into the struct. Every caller
        // of this function persists `composed` (via persist_composed_event or
        // the equivalent inline store_event_with_state in send_event) before
        // calling it, so the authoritative value already lives in
        // store.events by now; look it up there instead of trusting
        // composed.stream_ordering; used below both for the pagination key
        // and, indirectly, for the read/unread threshold.
        auto const persisted_stream_ordering = [&]() -> std::uint64_t {
            auto const event_row = store.events.find(composed.event_id);
            return event_row != store.events.end() ? event_row->stream_ordering : composed.stream_ordering;
        }();

        // The room's power levels, notification levels and member count, read once for every
        // recipient. Shared with unread counting (PushRoomFacts.hpp, R15), so the two decide
        // "does this notify" the same way.
        auto const room_facts = push_room_facts(store, room.room_id, static_cast<std::uint64_t>(room.members.size()));

        // Spec (push-gateway-api.md): "content" is "the content field from the
        // event, if present" — omitted (along with the other event-detail
        // fields below) for pushers whose data.format is "event_id_only".
        auto const content_json = [&]() -> std::string {
            auto const* root = std::get_if<canonicaljson::Object>(&event_parsed.value.storage());
            auto const* content = root != nullptr ? object_member(*root, "content") : nullptr;
            return content != nullptr ? serialize_canonical_string(*content).value_or(std::string{}) : std::string{};
        }();
        auto const sender_display_name = [&]() -> std::string {
            auto const profile = database::find_profile(store, sender);
            return profile.has_value() ? profile->displayname : std::string{};
        }();
        // GET /notifications' Notification.ts: "The unix timestamp at which
        // the event notification was sent, in milliseconds" — the triggering
        // event's own origin_server_ts, embedded at composition time (see
        // compose_signed_event).
        auto const notification_ts = [&]() -> std::uint64_t {
            auto const* root = std::get_if<canonicaljson::Object>(&event_parsed.value.storage());
            auto const* origin_server_ts = root != nullptr ? integer_member(*root, "origin_server_ts") : nullptr;
            return origin_server_ts != nullptr && *origin_server_ts > 0 ? static_cast<std::uint64_t>(*origin_server_ts)
                                                                        : std::uint64_t{0U};
        }();
        auto const is_member_event = composed.event_type == "m.room.member";

        // Ignoring Users (spec: docs/matrix-v1.19-spec/client-server-api.md
        // #ignoring-users, Server behaviour). Computed once for this event —
        // state-key presence and, for membership events, the membership
        // value are properties of the event itself, not of the recipient —
        // and reused per recipient below via trust_safety::is_delivery_
        // suppressed rather than re-parsing per iteration.
        auto const is_state_event = [&]() -> bool {
            auto const* root = std::get_if<canonicaljson::Object>(&event_parsed.value.storage());
            return root != nullptr && object_member(*root, "state_key") != nullptr;
        }();
        auto const membership_value = [&]() -> std::string {
            if (!is_member_event)
            {
                return {};
            }
            auto const* root = std::get_if<canonicaljson::Object>(&event_parsed.value.storage());
            auto const* content = root != nullptr ? object_member(*root, "content") : nullptr;
            auto const* content_object =
                content != nullptr ? std::get_if<canonicaljson::Object>(&content->storage()) : nullptr;
            auto const* membership = content_object != nullptr ? string_member(*content_object, "membership") : nullptr;
            return membership != nullptr ? *membership : std::string{};
        }();

        // The history rows of every recipient this event notifies, committed together after the loop (ADR-0440).
        auto notified = std::vector<database::PersistentNotification>{};
        // What the badges of every recipient of this event may spend between them (ADR-0608).
        auto badge_budget = PushBadgeBudget{};
        // Built on the first recipient with a pusher (see the check below).
        auto active_users = std::optional<std::unordered_set<std::string, TransparentStringHash, std::equal_to<>>>{};
        auto recipients = room.members;
        for (auto const& extra : extra_recipients)
        {
            if (std::ranges::find(recipients, extra) == recipients.end())
            {
                recipients.push_back(extra);
            }
        }

        // Recipients draw on the shared badge budget from a point that moves with the event's stream
        // ordering, so when it runs short the same members are not always the ones left without a count
        // (ADR-0608). Nothing below depends on the order: each recipient's checks and caps are its own,
        // and the history rows are committed together after the loop.
        auto const draw_start = push_badge_draw_start(persisted_stream_ordering, recipients.size());
        for (auto position = std::size_t{0U}; position < recipients.size(); ++position)
        {
            auto const& member = recipients[(draw_start + position) % recipients.size()];
            if (member == sender || events::domain_of(member) != server_name)
            {
                continue;
            }

            // A recipient's own m.ignored_user_list gates whether this event
            // reaches them at all: state events are still delivered (the
            // spec's exemption keeps room state accurate for the viewer),
            // but a room invite from an ignored sender must not be — that
            // override takes precedence over the state-event exemption even
            // though an invite is itself an m.room.member state event.
            auto const ignored_by_recipient = trust_safety::resolve_ignored_users(store, member);
            auto const is_new_room_invite_for_member = is_member_event && composed.state_key.has_value() &&
                                                       *composed.state_key == member && membership_value == "invite";
            if (trust_safety::is_delivery_suppressed(ignored_by_recipient, sender, is_state_event,
                                                     is_new_room_invite_for_member))
            {
                continue;
            }

            // Evaluate push rules for every eligible recipient regardless of
            // whether they have a pusher or push delivery is enabled — GET
            // /notifications history recording just below depends on this
            // either way (see this function's doc comment).
            // The recipient's own rules (R19, ADR-0204): the server defaults with their stored
            // m.push_rules applied.
            auto const ruleset = load_push_ruleset(
                store, member, static_cast<std::size_t>(runtime.config.server().client_api.max_push_rules_per_user));
            // contains_display_name matches against the recipient's display
            // name IN THIS ROOM, not their account-wide profile — see
            // room_member_display_name's doc comment.
            auto const context = push_evaluation_context(room_facts, member,
                                                         room_member_display_name(store, room.room_id, member), sender);
            auto const result = push::evaluate_push_rules(ruleset, event_parsed.value, context);
            if (result.glob_budget_exhausted)
            {
                // The recipient's content globs met a body too costly to match in full (ADR-0343):
                // the ones that could not finish did not match.
                log_diagnostic("push.glob_budget.exhausted",
                               {
                                   {"user_id",  std::string{member},                    false},
                                   {"event_id", composed.event_id,                      false},
                                   {"steps",    std::to_string(result.glob_steps_used), false}
                },
                               observability::LogEventSeverity::warning);
            }
            if (!result.notify)
            {
                continue;
            }

            // Record notification history (PersistentNotification) for GET
            // /_matrix/client/v3/notifications — unconditionally: independent
            // of push.enabled and of whether `member` has a pusher at all.
            // profile_tag is left empty: it names a specific pusher's
            // configured tag, but this recording happens once per (user,
            // event) rather than once per pusher.
            notified.push_back(database::PersistentNotification{
                std::string{member}, room.room_id, composed.event_id, persisted_stream_ordering, notification_ts,
                push_notification_actions_json(result), std::string{}, result.tweak_highlight});

            if (!push_delivery_enabled && !email_delivery_enabled)
            {
                continue;
            }
            auto pushers = database::list_pushers_for_user(store, member);
            auto const max_pushers_per_delivery =
                static_cast<std::size_t>(runtime.config.server().push.max_pushers_per_delivery);
            if (pushers.empty())
            {
                continue;
            }
            // A deactivated account keeps no pusher (ADR-0411), and nobody can sign in to it to
            // remove one that survived, so it is never notified, as EmailPush.cpp does not mail it.
            // The users are read once per call, on the first recipient with a pusher, not once per
            // recipient: this runs under runtime.mutex for every event. Recipients are local here
            // (remote members were skipped above), and a user with no row is not active.
            if (!active_users.has_value())
            {
                active_users = active_local_user_ids(runtime);
            }
            if (!active_users->contains(member))
            {
                continue;
            }
            if (pushers.size() > max_pushers_per_delivery)
            {
                // Mirrors dispatch_push_deliveries's push.delivery.dropped log
                // below: never truncate silently. The recipient still gets
                // notified (on the pushers kept), but the operator can see a
                // user is registering far more pushers than any real client
                // count, which the notification-history row above cannot
                // surface on its own.
                log_diagnostic("push.pushers.truncated",
                               {
                                   {"user_id",   std::string{member},                      false},
                                   {"total",     std::to_string(pushers.size()),           false},
                                   {"processed", std::to_string(max_pushers_per_delivery), false}
                },
                               observability::LogEventSeverity::warning);
                pushers.resize(max_pushers_per_delivery);
            }

            // The badge count walks the event table (ADR-0207): only count when an http pusher
            // will carry it. An email reports the count it finds when it is sent.
            // Absent when the event's badge budget was spent: the notification then omits `unread`.
            auto unread = std::optional<std::uint32_t>{};
            auto unread_counted = false;
            for (auto const& pusher : pushers)
            {
                if (pusher.kind == "email")
                {
                    if (email_delivery_enabled)
                    {
                        note_email_notification(*runtime.email_digest_queue_, member, pusher.pushkey, email_policy);
                    }
                    continue;
                }
                if (!push_delivery_enabled || pusher.kind != "http" || pusher.data_url.empty())
                {
                    continue;
                }
                if (!unread_counted)
                {
                    unread = push_badge_unread_count(runtime, member, ruleset, badge_budget);
                    unread_counted = true;
                }
                auto notification = push::PushGatewayNotification{};
                notification.event_id = composed.event_id;
                notification.room_id = room.room_id;
                notification.counts = {unread, 0U};
                notification.prio = "high";
                auto const event_id_only = pusher.data_format == "event_id_only";
                if (!event_id_only)
                {
                    notification.type = composed.event_type;
                    notification.sender = std::string{sender};
                    notification.sender_display_name = sender_display_name;
                    notification.content_json = content_json;
                    notification.user_is_target =
                        is_member_event && composed.state_key.has_value() && *composed.state_key == member;
                }

                auto device = push::PushGatewayDevice{};
                device.app_id = pusher.app_id;
                device.pushkey = pusher.pushkey;
                if (!pusher.data_format.empty())
                {
                    device.data_format = pusher.data_format;
                }
                // Every OTHER member of the pusher's registered `data`
                // dictionary besides url/format MUST reach the gateway
                // verbatim (Matrix v1.19 Push Gateway API: "data dictionary
                // passed in at pusher creation minus the url key"). Silently
                // skip a malformed value rather than failing the whole
                // delivery — this only ever contains what parse_pusher_set_
                // body itself serialized in ClientServerRuntime.cpp.
                if (!pusher.data_extra_json.empty())
                {
                    auto const parsed_extra = canonicaljson::parse_lossless(pusher.data_extra_json);
                    if (parsed_extra.error == canonicaljson::ParseError::none)
                    {
                        if (auto const* extra = std::get_if<canonicaljson::Object>(&parsed_extra.value.storage());
                            extra != nullptr)
                        {
                            device.data_extra = *extra;
                        }
                    }
                }
                device.tweak_sound = result.tweak_sound;
                device.tweak_highlight = result.tweak_highlight;
                notification.devices.push_back(std::move(device));

                deliveries.push_back(PendingPushDelivery{pusher, std::move(notification)});
            }
        }
        // One transaction for the whole event, not one commit per recipient. A failure writes none of the rows and
        // leaves memory equal to the database; the push deliveries above do not depend on them.
        if (!database::store_notifications(
                store, std::move(notified),
                static_cast<std::size_t>(runtime.config.server().client_api.max_notifications_retained_per_user)))
        {
            log_diagnostic("push.notification_history.persist_failed",
                           {
                               {"event_id", composed.event_id, false}
            },
                           observability::LogEventSeverity::warning);
        }
        return deliveries;
    }

    // Fires the actual Push Gateway API network calls for `deliveries` — all
    // of which were computed synchronously, in-memory, under runtime.mutex by
    // build_pending_push_deliveries above. This function runs the deliveries
    // entirely OFF that lock and off the request path: it is invoked from
    // send_event() via std::async(std::launch::async, ...) and the resulting
    // future is parked in runtime.orphan_futures_ (see the orphan_futures_ doc
    // comment on HomeserverRuntime: runtime's destructor blocks until every
    // such future has drained, so the captured `runtime&` reference stays
    // valid for as long as this task can run).
    //
    // Each delivery is one attempt_push_delivery (PushRetry.hpp): an open circuit or a failure
    // the spec says to retry ("If the endpoint returns an HTTP error code, the homeserver SHOULD
    // retry for a reasonable amount of time using exponential backoff") goes to the retry queue,
    // which the push retry job drains (R14, ADR-0206); a rejected pushkey loses its pusher and its
    // queued retries. A slow, hostile, or unreachable gateway therefore cannot block or fail the
    // request that triggered it: by the time any of this runs, send_event() has already returned
    // its response to the client.
    auto run_pending_push_deliveries(HomeserverRuntime& runtime, std::vector<PendingPushDelivery> deliveries) -> void
    {
        auto client = push::PushGatewayClient{
            *runtime.outbound_client, *runtime.cached_discovery, runtime.config.server().push,
            &runtime.test_forced_push_gateway_resolution, std::ref(*runtime.push_gateway_in_flight_)};
        // F-79 (ADR-0409): this batch holds one of the in-flight slots until the loop ends, and each
        // attempt can take the whole timeout. Past the deadline the pushers not yet reached are
        // queued for retry instead of being contacted now, so the slot is held for the deadline and
        // one attempt, not for as many timeouts as the recipient has pushers.
        auto const batch_started = std::chrono::steady_clock::now();
        auto const batch_deadline = push_batch_deadline(runtime.config.server().push);
        for (auto& delivery : deliveries)
        {
            auto attempt = push::PushRetry{};
            attempt.user_id = delivery.pusher.user_id;
            attempt.app_id = delivery.pusher.app_id;
            attempt.pushkey = delivery.pusher.pushkey;
            attempt.gateway_url = delivery.pusher.data_url;
            attempt.notification = std::move(delivery.notification);
            if (std::chrono::steady_clock::now() - batch_started >= batch_deadline)
            {
                defer_push_delivery(runtime, std::move(attempt), std::chrono::steady_clock::now());
                continue;
            }
            attempt_push_delivery(runtime, client, std::move(attempt), std::chrono::steady_clock::now());
        }
    }

    // A permit counts one recipient batch against both budgets. Completion
    // uses only atomics: no waiter-held mutex is needed to return admission.
    class PushDeliveryPermit final
    {
    public:
        PushDeliveryPermit(std::atomic<std::size_t>& global,
                           std::shared_ptr<std::atomic<std::size_t>> // SHARED_PTR: reviewed - permit lifetime.
                               recipient) noexcept
            : global_{global}
            , recipient_{std::move(recipient)}
        {
            ++global_.get();
            ++*recipient_;
        }

        ~PushDeliveryPermit() noexcept
        {
            if (active_)
            {
                --*recipient_;
                --global_.get();
            }
        }

        PushDeliveryPermit(PushDeliveryPermit const&) = delete;
        auto operator=(PushDeliveryPermit const&) -> PushDeliveryPermit& = delete;
        PushDeliveryPermit(PushDeliveryPermit&& other) noexcept
            : global_{other.global_}
            , recipient_{std::move(other.recipient_)}
            , active_{std::exchange(other.active_, false)}
        {
        }
        auto operator=(PushDeliveryPermit&&) -> PushDeliveryPermit& = delete;

    private:
        std::reference_wrapper<std::atomic<std::size_t>> global_;
        std::shared_ptr<std::atomic<std::size_t>> // SHARED_PTR: reviewed - permit lifetime.
            recipient_;
        bool active_{true};
    };

    auto log_push_delivery_drop(std::string_view scope, std::size_t in_flight, std::size_t cap,
                                std::size_t deliveries) noexcept -> void
    {
        try
        {
            log_diagnostic("push.delivery.dropped",
                           {
                               {"scope",      std::string{scope},         false},
                               {"in_flight",  std::to_string(in_flight),  false},
                               {"cap",        std::to_string(cap),        false},
                               {"deliveries", std::to_string(deliveries), false}
            },
                           observability::LogEventSeverity::warning);
        }
        catch (...)
        {
            // Logging is best-effort, especially when admission failed due
            // to allocation exhaustion. Never fail a persisted event for it.
        }
    }

    // OUT-3: one independently admitted task per recipient, not per event.
    // A recipient may hold at most eight batches and, for global budgets
    // above one, never every slot. G=1 retains its existing serial/drop policy.
    // The global configured cap and per-recipient pusher truncation remain.

    // Dispatches `deliveries` asynchronously (see run_pending_push_deliveries)
    // and parks the future in runtime.orphan_futures_. No-op when there is
    // nothing to deliver or the runtime has no outbound transport wired
    // (worker/test contexts that never populate outbound_client/cached_discovery).
    //
    // Before parking, reaps every already-completed future from
    // orphan_futures_ (shared with join_room's make_join race — see
    // reap_completed_futures) so the vector does not grow by one entry per
    // event for the life of the runtime, and checks
    // push_delivery_in_flight_ against the configured cap so a
    // busy room or a client sending many events cannot drive unbounded
    // thread creation. At capacity, the delivery is dropped — never spawned,
    // never blocked on — and a warning is logged: a missed push is
    // recoverable (the client still sees the event on its next /sync), an
    // exhausted thread pool is not.
    auto dispatch_push_deliveries(HomeserverRuntime& runtime, std::vector<PendingPushDelivery> deliveries) -> void
    {
        if (deliveries.empty() || runtime.outbound_client == nullptr || runtime.cached_discovery == nullptr)
        {
            return;
        }

        auto batches = std::map<std::string, std::vector<PendingPushDelivery>>{};
        auto const max_in_flight = static_cast<std::size_t>(runtime.config.server().push.max_in_flight_deliveries);
        auto const recipient_cap = max_in_flight > 1U ? std::min(std::size_t{8U}, max_in_flight - 1U) : 1U;
        try
        {
            for (auto& delivery : deliveries)
            {
                auto& batch = batches[delivery.pusher.user_id];
                batch.push_back(std::move(delivery));
            }
        }
        catch (std::exception const&)
        {
            log_push_delivery_drop("allocation", runtime.push_delivery_in_flight_.load(), max_in_flight,
                                   deliveries.size());
            return;
        }

        // ADR-0634: the gateway hosts a batch will contact, and whether each has answered promptly lately.
        auto const& push_config = runtime.config.server().push;
        auto const breaker_policy = push::GatewayCircuitBreakerPolicy{
            push_config.gateway_failure_threshold, std::chrono::seconds{push_config.gateway_cooldown_seconds}};
        for (auto& [recipient, batch] : batches)
        {
            auto const delivery_count = batch.size();
            try
            {
                auto hosts = std::vector<std::string>{};
                auto all_hosts_reachable = true;
                for (auto const& delivery : batch)
                {
                    auto host = push::push_gateway_host(delivery.pusher.data_url);
                    if (!host.has_value() || runtime.push_gateway_breaker_ == nullptr ||
                        !runtime.push_gateway_breaker_->reachable_recently(*host, std::chrono::steady_clock::now(),
                                                                           breaker_policy))
                    {
                        all_hosts_reachable = false;
                    }
                    if (host.has_value())
                    {
                        hosts.push_back(std::move(*host));
                    }
                }
                auto const orphan_lock = std::lock_guard{runtime.orphan_futures_mutex_};
                reap_completed_futures(runtime.orphan_futures_);
                std::erase_if(runtime.push_delivery_in_flight_by_user_, [](auto const& entry) {
                    return entry.second->load() == 0U;
                });
                if (at_background_task_capacity(runtime.push_delivery_in_flight_, max_in_flight))
                {
                    log_push_delivery_drop("global", runtime.push_delivery_in_flight_.load(), max_in_flight,
                                           delivery_count);
                    continue;
                }

                auto user = runtime.push_delivery_in_flight_by_user_.find(recipient);
                if (user == runtime.push_delivery_in_flight_by_user_.end())
                {
                    auto counter = std::make_shared<std::atomic<std::size_t>>(0U);
                    user = runtime.push_delivery_in_flight_by_user_.emplace(recipient, std::move(counter)).first;
                }
                if (at_background_task_capacity(*user->second, recipient_cap))
                {
                    log_push_delivery_drop("recipient", user->second->load(), recipient_cap, delivery_count);
                    continue;
                }

                // ADR-0634: a share of the budget is kept for batches whose hosts answer, and one host carries
                // an eighth of it, so gateways the pushers' owners chose cannot hold every slot.
                auto admission = runtime.push_batch_admission_->admit(runtime.push_delivery_in_flight_.load(),
                                                                      max_in_flight, hosts, all_hosts_reachable);
                if (!admission.slot.has_value())
                {
                    log_push_delivery_drop(admission.refusal == push::PushBatchRefusal::gateway_host
                                               ? "gateway_host"
                                               : (admission.refusal == push::PushBatchRefusal::unproven_share
                                                      ? "unproven_share"
                                                      : "global"),
                                           runtime.push_delivery_in_flight_.load(), max_in_flight, delivery_count);
                    continue;
                }

                // Reserve BEFORE launch and keep the parking mutex held. The
                // following future insertion then needs no allocation, so an
                // allocation failure cannot wait on a running future while
                // this request still owns runtime.mutex.
                runtime.orphan_futures_.reserve(runtime.orphan_futures_.size() + 1U);
                auto permit = PushDeliveryPermit{runtime.push_delivery_in_flight_, user->second};
                auto push_future =
                    std::async(std::launch::async, [&runtime, deliveries = std::move(batch), permit = std::move(permit),
                                                    host_slot = std::move(admission.slot)]() mutable {
                        // Return the counters on work completion (or throw),
                        // not on destruction of the future's retained closure.
                        auto const completion = std::move(permit);
                        auto const host_completion = std::move(host_slot);
                        run_pending_push_deliveries(runtime, std::move(deliveries));
                    });
                runtime.orphan_futures_.push_back(std::move(push_future));
            }
            catch (std::exception const&)
            {
                // Failed allocation/launch is best-effort delivery loss. The
                // permit, if acquired, restores both counters during unwind.
                log_push_delivery_drop("admission", runtime.push_delivery_in_flight_.load(), max_in_flight,
                                       delivery_count);
            }
        }
    }

    // Evaluates push rules and fires (off the request path) any notifications
    // triggered by `composed` for `room`, additionally considering
    // `extra_recipient` — a recipient who is not (yet) a joined member of
    // `room` and so would otherwise be invisible to build_pending_push_
    // deliveries's room.members loop. This is for membership transitions: an
    // invitee is exactly this case — .m.rule.invite_for_me must reach them,
    // but store_or_update_membership for an "invite" does not add the
    // invitee to room.members (only "join" does — see
    // apply_runtime_membership). `extra_recipient` equal to `sender`, or
    // already a joined member, is silently absorbed by
    // build_pending_push_deliveries, so every membership-mutating call site
    // (invite/ban/kick/leave/knock/join, and the 3PID invite) can call this
    // unconditionally rather than special-casing which transitions have a
    // real, distinct recipient. Safe to call under runtime.mutex (see
    // build_pending_push_deliveries).
    auto dispatch_membership_push_notification(HomeserverRuntime& runtime, LocalRoom const& room,
                                               ComposedEvent const& composed, std::string_view sender,
                                               std::string_view extra_recipient) -> void
    {
        auto const extra = std::array<std::string, 1>{std::string{extra_recipient}};
        if (auto deliveries = build_pending_push_deliveries(runtime, room, composed, sender, std::span{extra});
            !deliveries.empty())
        {
            dispatch_push_deliveries(runtime, std::move(deliveries));
        }
        queue_event_for_appservices(runtime, room, composed, sender);
    }

} // namespace

namespace
{

    // True for a client request to send an m.room.redaction whose content has no string `redacts`.
    [[nodiscard]] auto request_is_redaction_without_target(std::string_view event_json) -> bool
    {
        auto const parsed = canonicaljson::parse_lossless(event_json);
        auto const* input = std::get_if<canonicaljson::Object>(&parsed.value.storage());
        if (parsed.error != canonicaljson::ParseError::none || input == nullptr)
        {
            return false;
        }
        auto const* type = string_member(*input, "type");
        if (type == nullptr || *type != "m.room.redaction")
        {
            return false;
        }
        auto const* content = object_member(*input, "content");
        auto const* content_object =
            content == nullptr ? nullptr : std::get_if<canonicaljson::Object>(&content->storage());
        auto const* redacts = content_object == nullptr ? nullptr : string_member(*content_object, "redacts");
        return redacts == nullptr || redacts->empty();
    }

} // namespace

// NOLINTBEGIN(bugprone-easily-swappable-parameters)
namespace
{

    // True when the composed m.room.member event's `content.membership` is "invite".
    [[nodiscard]] auto composed_membership_is_invite(std::string_view event_json) -> bool
    {
        auto const parsed = canonicaljson::parse_lossless(event_json);
        auto const* root = parsed.error == canonicaljson::ParseError::none
                               ? std::get_if<canonicaljson::Object>(&parsed.value.storage())
                               : nullptr;
        auto const* content = root == nullptr ? nullptr : object_member_as_object(*root, "content");
        auto const* membership = content == nullptr ? nullptr : string_member(*content, "membership");
        return membership != nullptr && *membership == "invite";
    }

    // F-19: the content checks of a state event a local client sends with POST /send (and, through it, PUT /state).
    // Only a state event, one with a `state_key` of "", is judged, and only for a sender who may send it: anyone else
    // gets the 403 the compose step gives. An event that is not a JSON object with a string type is left to compose.
    [[nodiscard]] auto sent_state_content_refusal(HomeserverRuntime& runtime, std::string_view user_id,
                                                  std::string_view room_id, std::string_view event_json)
        -> std::optional<OperationResult>
    {
        auto const parsed = canonicaljson::parse_lossless(event_json);
        auto const* event = parsed.error == canonicaljson::ParseError::none
                                ? std::get_if<canonicaljson::Object>(&parsed.value.storage())
                                : nullptr;
        auto const* type = event == nullptr ? nullptr : string_member(*event, "type");
        auto const* state_key = event == nullptr ? nullptr : string_member(*event, "state_key");
        auto const* content = event == nullptr ? nullptr : object_member_as_object(*event, "content");
        if (type == nullptr || state_key == nullptr || content == nullptr || !state_key->empty() ||
            (*type != "m.room.canonical_alias" && *type != "m.room.encryption"))
        {
            return std::nullopt;
        }
        auto const& store = runtime.database.persistent_store;
        if (!may_send_state_event(store, room_id, user_id, *type))
        {
            return std::nullopt;
        }
        auto const refusal =
            state_content_refusal(store, room_id, runtime.config.server().server_name, *type, *state_key, *content);
        if (!refusal.has_value())
        {
            return std::nullopt;
        }
        log_diagnostic("room.event.rejected", {
                                                  {"actor",      std::string{user_id}, false},
                                                  {"room_id",    std::string{room_id}, false},
                                                  {"event_type", *type,                false},
                                                  {"status",     "400",                false},
                                                  {"reason",     refusal->message,     false}
        });
        return state_content_refusal_result(*refusal);
    }

    // send_event once the sender is known. The profile propagation job (ADR-0353) calls it directly: it holds no token.
    // `via_appservice` is set when an application service asserted the sender: the server-administrator override of
    // a redaction is then not applied (ADR-0628).
    [[nodiscard]] auto send_event_as_user(HomeserverRuntime& runtime, std::string const& user_id,
                                          std::string_view room_id, std::string_view event_json,
                                          std::optional<std::int64_t> origin_server_ts, bool via_appservice = false)
        -> OperationResult
    {
        auto* room = find_room(runtime.database, room_id);
        if (room == nullptr)
        {
            log_diagnostic("room.event.rejected", {
                                                      {"actor",   user_id,              false},
                                                      {"room_id", std::string{room_id}, false},
                                                      {"reason",  "unknown room",       false}
            });
            return make_operation_result(false, {}, "unknown room");
        }
        if (!room_has_member(*room, user_id))
        {
            log_diagnostic("room.event.rejected", {
                                                      {"actor",   user_id,              false},
                                                      {"room_id", std::string{room_id}, false},
                                                      {"reason",  "not joined",         false}
            });
            return make_operation_result(false, {}, "not joined", 403U);
        }
        if (event_json.empty())
        {
            log_diagnostic("room.event.rejected", {
                                                      {"actor",   user_id,              false},
                                                      {"room_id", std::string{room_id}, false},
                                                      {"reason",  "empty event",        false}
            });
            return make_operation_result(false, {}, "empty event");
        }

        // CSAZ-11: a redaction must name the event it redacts. Without it there is nothing to compose.
        if (request_is_redaction_without_target(event_json))
        {
            log_diagnostic("room.event.rejected", {
                                                      {"actor",   user_id,                    false},
                                                      {"room_id", std::string{room_id},       false},
                                                      {"status",  "400",                      false},
                                                      {"reason",  "redaction names no event", false}
            });
            return make_operation_result(false, {}, "m.room.redaction content must name the event in redacts", 400U);
        }

        if (auto refusal = sent_state_content_refusal(runtime, user_id, room_id, event_json); refusal.has_value())
        {
            return std::move(*refusal);
        }

        auto const composition = compose_signed_event(runtime, room_id, user_id, event_json, origin_server_ts);
        if (composition.failure == ComposeFailure::invalid_state_key)
        {
            return invalid_state_key_result();
        }
        if (composition.failure == ComposeFailure::too_large)
        {
            return event_too_large_result();
        }
        auto const& composed = composition.event;
        // SS7: PUT .../state/m.room.member/{stateKey} with membership invite is refused for a local invitee who
        // blocks invites, before anything is stored.
        if (composed.has_value() && composed->event_type == "m.room.member" && composed->state_key.has_value() &&
            auth::user_id_server_name(*composed->state_key) == runtime.config.server().server_name &&
            composed_membership_is_invite(composed->json) &&
            invite_permission_blocks(runtime.database.persistent_store, *composed->state_key))
        {
            return invite_blocked_result();
        }
        if (!composed.has_value())
        {
            log_diagnostic("room.event.rejected", {
                                                      {"actor",   user_id,                                 false},
                                                      {"room_id", std::string{room_id},                    false},
                                                      {"status",  "403",                                   false},
                                                      {"reason",  "event authorization or signing failed", false}
            });
            return make_operation_result(false, {}, "event authorization or signing failed", 403U);
        }
        // CSAZ-11. Spec (Client-Server API, PUT /redact): a user may redact their own events, another
        // user's only with the `redact` level, and a server administrator any event sent by a user on
        // their server. Refusing here keeps a redaction that would not be applied out of the room.
        if (composed->event_type == "m.room.redaction")
        {
            auto const sender_is_server_admin = [&] {
                return !via_appservice && std::ranges::any_of(runtime.database.users, [&](LocalUser const& user) {
                    return user.user_id == user_id && user.admin;
                });
            };
            auto const check = check_local_redaction(runtime.database.persistent_store, room_id, composed->json,
                                                     sender_is_server_admin(), runtime.config.server().server_name);
            if (check != LocalRedactionCheck::permitted)
            {
                auto const missing = check == LocalRedactionCheck::target_unknown;
                log_diagnostic(
                    "room.event.rejected",
                    {
                        {"actor",   user_id,                                                          false},
                        {"room_id", std::string{room_id},                                             false},
                        {"status",  missing ? "404" : "403",                                          false},
                        {"reason",  missing ? "redaction target unknown" : "redaction not permitted", false}
                });
                return missing
                           ? make_operation_result(false, {}, "the event to redact was not found in this room", 404U)
                           : make_operation_result(false, {}, "you may not redact that event", 403U);
            }
        }
        // ADR-0064 phase B1: route through the same choke point every other
        // local event path uses, rather than duplicating the raw store call —
        // this is the client-facing send/state-send/redaction endpoint, so it
        // was the one local path most likely to be hit by a real client.
        if (persist_composed_event(runtime, room_id, user_id, *composed) == PersistOutcome::not_stored)
        {
            log_diagnostic("room.event.rejected", {
                                                      {"actor",      user_id,                    false},
                                                      {"room_id",    std::string{room_id},       false},
                                                      {"event_id",   composed->event_id,         false},
                                                      {"event_type", composed->event_type,       false},
                                                      {"status",     "500",                      false},
                                                      {"reason",     "event persistence failed", false}
            });
            return make_operation_result(false, {}, "event persistence failed", 500U);
        }
        append_local_audit(runtime.database, observability::AuditCategory::admin, "room.event_sent", user_id, room_id,
                           "stored");
        // Presence, "Last active ago": sending a message is a pro-active event. A state event (the profile change
        // that send_event_as_user also carries) is not the user's doing, so it does not count (ADR-0492).
        if (!composed->state_key.has_value())
        {
            note_local_message_activity(runtime, user_id);
        }
        log_diagnostic("room.event.accepted",
                       {
                           {"actor",       user_id,                                         false},
                           {"room_id",     std::string{room_id},                            false},
                           {"event_id",    composed->event_id,                              false},
                           {"event_type",  composed->event_type,                            false},
                           {"depth",       std::to_string(composed->depth),                 false},
                           {"prev_events", std::to_string(composed->prev_event_ids.size()), false},
                           {"auth_events", std::to_string(composed->auth_event_ids.size()), false}
        });
        if (runtime.sync_notifier != nullptr)
        {
            // ADR-0437: an event in a room concerns the room's joined and invited members, its sender and, for
            // a membership event, the user it is about (a kick or ban removes them from the room's members).
            auto const member_target = composed->event_type == "m.room.member" && composed->state_key.has_value()
                                           ? std::string_view{*composed->state_key}
                                           : std::string_view{};
            auto const audience = sync_audience_of_room(runtime.database.persistent_store, room_id,
                                                        {std::string_view{user_id}, member_target});
            runtime.sync_notifier->publish(visible_stream_position(runtime.database),
                                           runtime.database.persistent_store.next_sync_stream_id, audience);
        }
        // Refresh any federation worker's snapshot of this room the same way the
        // 7 membership-mutating calls already do (create_room, join_room,
        // leave_room, invite_user, ban_user, kick_user, unban_user) — see
        // docs/architecture.md, "Federation worker room staleness". Without
        // this, an ordinary message never reaches a worker's own PersistentStore
        // (pdu_sink for inbound-relayed events, and this function for
        // locally-sent ones, both write only through main), so
        // backfill/event/state/state_ids/get_missing_events served by a worker
        // for this room could omit every message sent since the room's last
        // membership-triggered reload.
        notify_room_changed(runtime, room_id);
        federate_local_event(runtime, room_id, *room, *composed);
        // Push delivery: evaluate push rules for every local, joined recipient,
        // record GET /_matrix/client/v3/notifications history for every
        // notify-worthy one (regardless of push.enabled/pushers — see
        // build_pending_push_deliveries's doc comment), and fire the Push Gateway
        // API notifications off the request path for those with push.enabled and
        // a registered pusher (see dispatch_push_deliveries above).
        if (auto deliveries = build_pending_push_deliveries(runtime, *room, *composed, user_id); !deliveries.empty())
        {
            dispatch_push_deliveries(runtime, std::move(deliveries));
        }
        queue_event_for_appservices(runtime, *room, *composed, user_id);
        return make_operation_result(true, composed->event_id);
    }

} // namespace

[[nodiscard]] auto send_event(HomeserverRuntime& runtime, std::string_view access_token, std::string_view room_id,
                              std::string_view event_json, std::optional<std::int64_t> origin_server_ts)
    -> OperationResult
{
    log_diagnostic("room.event.started", {
                                             {"room_id",          std::string{room_id},                    false},
                                             {"body_bytes",       std::to_string(event_json.size()),       false},
                                             {"has_access_token", access_token.empty() ? "false" : "true", false}
    });
    auto const user_id = authenticated_user(runtime, access_token);
    if (!user_id.has_value())
    {
        log_diagnostic("room.event.rejected", {
                                                  {"room_id", std::string{room_id}, false},
                                                  {"status",  "401",                false},
                                                  {"reason",  "unauthenticated",    false}
        });
        return make_operation_result(false, {}, "unauthenticated", 401U);
    }

    return send_event_as_user(runtime, *user_id, room_id, event_json, origin_server_ts,
                              appservice::decode_masquerade_token(access_token).has_value());
}
// NOLINTEND(bugprone-easily-swappable-parameters)

namespace
{

    // The content of `user_id`'s current m.room.member state event in the room, or nullopt when the
    // room's state holds none (or its event cannot be read).
    [[nodiscard]] auto current_member_content(database::PersistentStore const& store, std::string_view room_id,
                                              std::string_view user_id) -> std::optional<canonicaljson::Object>
    {
        auto const event_id = database::find_current_state_event_id(store, room_id, "m.room.member", user_id);
        if (!event_id.has_value())
        {
            return std::nullopt;
        }
        auto const event_it = store.events.find(*event_id);
        if (event_it == store.events.end())
        {
            return std::nullopt;
        }
        auto const parsed = canonicaljson::parse_lossless(event_it->json);
        auto const* root = std::get_if<canonicaljson::Object>(&parsed.value.storage());
        auto const* content = root != nullptr ? object_member_as_object(*root, "content") : nullptr;
        if (parsed.error != canonicaljson::ParseError::none || content == nullptr)
        {
            return std::nullopt;
        }
        return *content;
    }

    [[nodiscard]] auto content_string(canonicaljson::Object const& content, std::string_view key) -> std::string
    {
        auto const* value = string_member(content, key);
        return value != nullptr ? *value : std::string{};
    }

    // True when the join `content` already carries `profile`'s display name and avatar URL (an
    // unset field matching an absent one).
    [[nodiscard]] auto member_content_carries_profile(canonicaljson::Object const& content,
                                                      std::optional<database::PersistentProfile> const& profile) -> bool
    {
        auto const wanted_displayname = profile.has_value() ? profile->displayname : std::string{};
        auto const wanted_avatar_url = profile.has_value() ? profile->avatar_url : std::string{};
        return content_string(content, "displayname") == wanted_displayname &&
               content_string(content, "avatar_url") == wanted_avatar_url;
    }

    // What one hold of runtime.mutex may do towards one user's profile change (ADR-0353).
    struct ProfileWalkBudget final
    {
        std::size_t rooms{0U};
        std::size_t member_events{0U};
        std::size_t sends{0U};
    };

    struct ProfileWalkOutcome final
    {
        // The index in database.rooms to resume from, when not finished.
        std::size_t next_room{0U};
        bool finished{false};
        std::size_t sent{0U};
        std::size_t failed{0U};
    };

    // Walks database.rooms from `first_room`, sending the user's current profile to each room whose current state holds
    // them joined without it, until the rooms end or the budget does. Whether to send is decided here, under the same
    // hold as the send, and the profile is read here: a room the user has left is never sent a join that would rejoin
    // them, and a profile changed twice is sent once.
    [[nodiscard]] auto walk_rooms_for_profile(HomeserverRuntime& runtime, std::string const& user_id,
                                              std::size_t first_room, ProfileWalkBudget budget) -> ProfileWalkOutcome
    {
        auto const& store = runtime.database.persistent_store;
        auto const profile = database::find_profile(store, user_id);
        auto const event_json = serialize_own_join_event_json(store, user_id);
        auto outcome = ProfileWalkOutcome{};
        for (outcome.next_room = first_room; outcome.next_room < runtime.database.rooms.size(); ++outcome.next_room)
        {
            if (budget.rooms == 0U || budget.member_events == 0U || budget.sends == 0U)
            {
                return outcome;
            }
            --budget.rooms;
            auto const& room = runtime.database.rooms[outcome.next_room];
            auto const room_id = room.room_id;
            // A room is one the user "is a member of" when its current m.room.member state for them is a join. The
            // runtime member list alone is not enough: it can name a user the room's state says has left (ADR-0182),
            // and in a public room the join sent here would then rejoin them.
            if (!database::find_current_state_event_id(store, room_id, "m.room.member", user_id).has_value() ||
                !room_has_member(room, user_id))
            {
                continue;
            }
            --budget.member_events;
            auto const content = current_member_content(store, room_id, user_id);
            if (!content.has_value() || content_string(*content, "membership") != "join")
            {
                log_diagnostic("profile.propagation.not_member",
                               {
                                   {"actor",   user_id, false},
                                   {"room_id", room_id, false}
                });
                continue;
            }
            if (member_content_carries_profile(*content, profile))
            {
                continue;
            }
            --budget.sends;
            auto const result = event_json.has_value()
                                    ? send_event_as_user(runtime, user_id, room_id, *event_json, std::nullopt)
                                    : make_operation_result(false, {}, "membership serialization failed");
            if (result.ok)
            {
                ++outcome.sent;
                continue;
            }
            ++outcome.failed;
            log_diagnostic("profile.propagation.room_failed",
                           {
                               {"actor",   user_id,                       false},
                               {"room_id", room_id,                       false},
                               {"status",  std::to_string(result.status), false},
                               {"reason",  result.reason,                 false}
            },
                           observability::LogEventSeverity::warning);
        }
        outcome.finished = true;
        return outcome;
    }

} // namespace

[[nodiscard]] auto propagate_profile_change(HomeserverRuntime& runtime, std::string_view access_token)
    -> OperationResult
{
    auto const guard = RuntimeLock{runtime.mutex};
    auto const user_id = authenticated_user(runtime, access_token);
    if (!user_id.has_value())
    {
        return make_operation_result(false, {}, "profile propagation requires authentication", 401U);
    }
    // The request's share (ADR-0353). Starting from the first room, not from any queued position: rooms already passed
    // hold the profile before this change, and the walk skips rooms already current.
    auto const walked = walk_rooms_for_profile(runtime, *user_id, 0U,
                                               {profile_propagation_rooms_walked_per_hold,
                                                profile_propagation_member_events_read_per_hold,
                                                profile_propagation_sends_per_request});
    if (walked.finished)
    {
        runtime.profile_propagation_pending.erase(*user_id);
    }
    else
    {
        runtime.profile_propagation_pending.insert_or_assign(*user_id, walked.next_room);
        if (runtime.profile_propagation_wake)
        {
            runtime.profile_propagation_wake();
        }
    }
    auto const sent = walked.sent;
    auto const failed = walked.failed;
    // The second mechanism: "an m.presence presence status update is sent, again containing the
    // new values of the displayname and avatar_url keys, in addition to the required presence key
    // containing the current presence state of the user". Storing the user's presence again gives
    // it a new sync stream position, so every peer's next /sync carries it; /sync adds the profile.
    // A user who has never set a presence is offline.
    // With presence off (`presence.enabled=false`) none is tracked, so there is none to send.
    auto& mutable_store = runtime.database.persistent_store;
    auto presence_sent = true;
    if (presence_enabled(runtime))
    {
        auto const current = std::ranges::find_if(mutable_store.presence_states, [&](auto const& state) {
            return state.user_id == *user_id;
        });
        auto presence = current != mutable_store.presence_states.end() ? *current : database::PersistentPresence{};
        presence.user_id = *user_id;
        // The stored time since the user was active is as of an earlier moment; record_presence
        // restamps the row, so bring it up to date first.
        presence.last_active_ago = presence_last_active_ago(presence, presence_now_ms());
        // Appservices that receive ephemeral data are sent the new profile the same way (R08).
        presence_sent = record_presence(runtime, presence);
        if (presence_sent && runtime.sync_notifier != nullptr)
        {
            runtime.sync_notifier->publish(visible_stream_position(runtime.database),
                                           mutable_store.next_sync_stream_id);
        }
    }
    // The profile is already stored, so the change has happened whatever follows: the request
    // succeeds (ADR-0182). A room or presence update that failed is left for the next profile
    // change, which sends to every room whose membership does not yet carry the profile.
    auto const complete = failed == 0U && presence_sent;
    log_diagnostic("profile.propagation.completed",
                   {
                       {"actor",    *user_id,                           false},
                       {"rooms",    std::to_string(sent),               false},
                       {"failed",   std::to_string(failed),             false},
                       {"presence", presence_sent ? "sent" : "failed",  false},
                       {"queued",   walked.finished ? "false" : "true", false}
    },
                   complete ? observability::LogEventSeverity::debug : observability::LogEventSeverity::warning);
    return make_operation_result(true, {});
}

auto propagate_queued_profile(HomeserverRuntime& runtime) -> std::chrono::milliseconds
{
    auto const guard = RuntimeLock{runtime.mutex};
    auto& pending = runtime.profile_propagation_pending;
    if (pending.empty())
    {
        return profile_propagation_idle_delay;
    }
    // In turn, so that one user's many rooms do not hold up another user's few.
    auto next = pending.upper_bound(runtime.profile_propagation_last_user);
    if (next == pending.end())
    {
        next = pending.begin();
    }
    auto const user_id = next->first;
    auto const first_room = next->second;
    runtime.profile_propagation_last_user = user_id;

    // Spec, "Account suspension": changing profile data is among the actions recommended forbidden, and a locked
    // account cannot be used. The request was allowed; what it left is not sent once the account has been stopped.
    auto const user = std::ranges::find_if(runtime.database.users, [&](LocalUser const& candidate) {
        return candidate.user_id == user_id;
    });
    if (user == runtime.database.users.end() || user->locked || user->suspended || user->deactivated)
    {
        pending.erase(user_id);
        log_diagnostic("profile.propagation.abandoned", {
                                                            {"actor", user_id, false}
        });
    }
    else
    {
        auto const walked = walk_rooms_for_profile(
            runtime, user_id, first_room,
            {profile_propagation_rooms_walked_per_hold, profile_propagation_member_events_read_per_hold, 1U});
        if (walked.finished)
        {
            pending.erase(user_id);
            log_diagnostic("profile.propagation.queue_finished", {
                                                                     {"actor", user_id, false}
            });
        }
        else
        {
            pending.insert_or_assign(user_id, walked.next_room);
        }
    }
    return pending.empty() ? std::chrono::milliseconds{profile_propagation_idle_delay} : profile_propagation_pace;
}

// See the doc comment in RoomService.hpp. Builds a ComposedEvent-shaped
// view of `envelope` (federation ingestion never produces a real ComposedEvent
// — that type is send_event's own composition output) purely so it can reuse
// build_pending_push_deliveries/dispatch_push_deliveries unchanged rather than
// duplicating their logic for the federation path.
auto deliver_federation_push_notifications(HomeserverRuntime& runtime, federation::InboundPduEnvelope const& envelope,
                                           std::uint64_t accepted_stream_ordering) -> void
{
    // Not called under runtime.mutex by its sole caller (wire_federation_callbacks_impl's pdu_sink), and the
    // push and appservice queues read and write the store and the room's member list. Recursive, so a
    // caller that does hold it is unaffected.
    auto const runtime_guard = RuntimeLock{runtime.mutex};
    auto const* room = find_room(runtime.database, envelope.room_id);
    if (room == nullptr)
    {
        return;
    }

    auto composed = ComposedEvent{};
    composed.event_id = envelope.event_id;
    composed.json = envelope.json;
    composed.depth = envelope.depth;
    composed.stream_ordering = accepted_stream_ordering;
    composed.prev_event_ids = envelope.prev_event_ids;
    composed.auth_event_ids = envelope.auth_event_ids;
    composed.signatures = envelope.signatures;
    composed.event_type = envelope.event_type;
    composed.state_key = envelope.state_key;

    // Mirrors dispatch_membership_push_notification's extra_recipient: a
    // federated invite/ban/kick/knock target may not yet be a joined member
    // of the room (only "join" mutates LocalDatabase::members — see
    // apply_runtime_membership above), so without surfacing state_key here
    // explicitly, .m.rule.invite_for_me could never fire for an invite that
    // arrived over federation rather than locally. Safe to pass
    // unconditionally for every m.room.member PDU: build_pending_push_
    // deliveries silently absorbs an entry equal to the sender or already a
    // joined member.
    auto const extra_recipient =
        composed.event_type == "m.room.member" ? composed.state_key.value_or(std::string{}) : std::string{};
    auto const extra_array = std::array<std::string, 1>{extra_recipient};
    auto const extra_span =
        extra_recipient.empty() ? std::span<std::string const>{} : std::span<std::string const>{extra_array};

    if (auto deliveries = build_pending_push_deliveries(runtime, *room, composed, envelope.sender, extra_span);
        !deliveries.empty())
    {
        dispatch_push_deliveries(runtime, std::move(deliveries));
    }
    queue_event_for_appservices(runtime, *room, composed, envelope.sender);
}

[[nodiscard]] auto fetch_room_state(HomeserverRuntime const& runtime, std::string_view access_token,
                                    std::string_view room_id) -> OperationResult
{
    // `authenticated_user` is non-const because the audit-routing helper
    // (0.5.0) writes a row to audit_log on token rejection. The caller
    // (the read-only fetch path) does not hold the runtime mutex; the
    // const cast is safe because `audit_log` is an append-only log
    // that does not race with the read-only state query.
    auto const user_id = authenticated_user(const_cast<HomeserverRuntime&>(runtime), access_token);
    if (!user_id.has_value())
    {
        return make_operation_result(false, {}, "unauthenticated", 401U);
    }

    auto const* room = find_room(runtime.database, room_id);
    if (room == nullptr)
    {
        return make_operation_result(false, {}, "unknown room", 403U);
    }
    // Spec: 403 "You aren't a member of the room and weren't previously a member of the
    // room." A joined user reads the current state; a user who has left, or was banned, reads
    // the state as of the event that ended their join; an invite, a knock or a declined invite
    // reads nothing (CSAZ-2, sync::room_read_access_for).
    auto const access = sync::room_read_access_for(runtime.database.persistent_store, room_id, *user_id);
    if (access.kind == sync::RoomReadKind::none)
    {
        return make_operation_result(false, {}, "not joined", 403U);
    }
    auto const state_ids = sync::room_state_event_ids(runtime.database.persistent_store, room_id, access, std::nullopt);
    if (!state_ids.has_value())
    {
        // The state as of the user's departure cannot be determined: fail closed.
        return make_operation_result(false, {}, "not joined", 403U);
    }

    // Build a JSON array of the state events the user may read.
    // Spec v1.19: GET /rooms/{roomId}/state returns an array of ClientEvent,
    // so each entry must carry event_id and unsigned.replaces_state.
    auto state_array = canonicaljson::Array{};
    for (auto const& state_event_id : *state_ids)
    {
        auto const& events = runtime.database.persistent_store.events;
        auto const event = events.find(state_event_id);
        if (event != events.end())
        {
            state_array.push_back(client_event_with_id(runtime.database.persistent_store, *event));
        }
    }
    auto serialized = canonicaljson::serialize_canonical(canonicaljson::Value{std::move(state_array)});
    if (serialized.error != canonicaljson::CanonicalJsonError::none)
    {
        return make_operation_result(false, {}, "state serialization failed", 500U);
    }
    return make_operation_result(true, std::move(serialized.output));
}

// Converts a stored persistent event into a client-facing event value,
// injecting server-generated fields: event_id and, for state events,
// unsigned.replaces_state (Matrix v1.19). Shared by /messages, GET
// /rooms/{roomId}/state, and the ClientServerRuntime.cpp event serializer.
[[nodiscard]] auto client_event_with_id(database::PersistentStore const& store, database::PersistentEvent const& event)
    -> canonicaljson::Value
{
    auto const parsed = canonicaljson::parse_lossless(event.json);
    if (parsed.error != canonicaljson::ParseError::none)
    {
        return canonicaljson::Value{canonicaljson::Object{}};
    }
    auto const* obj = std::get_if<canonicaljson::Object>(&parsed.value.storage());
    if (obj == nullptr)
    {
        return canonicaljson::Value{canonicaljson::Object{}};
    }
    // `unsigned` is outside the event's signatures, so whoever relayed the event can put anything in it
    // (CS API, ClientEvent `unsigned`; SS API "Signing events"). The client's `unsigned` is therefore never
    // built from the stored copy, with a list of keys to drop: it is built from what this server computes,
    // which is `replaces_state` below, `redacted_because` (attach_redacted_because), and the viewer's own
    // `transaction_id`, `membership` and `prev_content` that sync::ViewerEventUnsigned adds per request
    // (ADR-0402). This server writes no `unsigned` of its own into a stored event.
    auto client_obj = *obj;
    std::erase_if(client_obj, [](canonicaljson::ObjectMember const& member) {
        return member.key == "unsigned";
    });
    client_obj.push_back(canonicaljson::make_member("event_id", canonicaljson::Value{event.event_id}));
    // ClientEvent `room_id` is required everywhere but /sync. Room version 12 omits it from
    // the m.room.create PDU only, so a client still gets the room it belongs to.
    if (object_member(*obj, "room_id") == nullptr && !event.room_id.empty())
    {
        client_obj.push_back(canonicaljson::make_member("room_id", canonicaljson::Value{event.room_id}));
    }

    auto const find_string = [](canonicaljson::Object const& object, std::string_view key) {
        for (auto const& member : object)
        {
            if (member.key == key)
            {
                return std::get_if<std::string>(&member.value->storage());
            }
        }
        return static_cast<std::string const*>(nullptr);
    };
    auto const* state_key = find_string(*obj, "state_key");
    auto const* event_type = find_string(*obj, "type");
    if (state_key != nullptr && event_type != nullptr)
    {
        auto const* transition =
            database::find_state_transition(store, event.room_id, *event_type, *state_key, event.event_id);
        if (transition != nullptr && !transition->previous_event_id.empty())
        {
            auto unsigned_object = canonicaljson::Object{};
            unsigned_object.push_back(
                canonicaljson::make_member("replaces_state", canonicaljson::Value{transition->previous_event_id}));
            client_obj.push_back(
                canonicaljson::make_member("unsigned", canonicaljson::Value{std::move(unsigned_object)}));
        }
    }
    // CSAZ-11: a redacted event carries unsigned.redacted_because (the stored JSON is already the
    // redacted form); a redaction event carries `redacts` where older and newer clients look for it.
    database::add_redaction_compat(client_obj);
    database::attach_redacted_because(store, event.event_id, client_obj);
    return canonicaljson::Value{std::move(client_obj)};
}

[[nodiscard]] auto make_bundled_aggregations(database::PersistentStore const& store,
                                             sync::HistoryVisibility& visibility, std::string_view user_id,
                                             std::unordered_set<std::string> const& ignored_senders, bool enabled)
    -> sync::BundledAggregations
{
    return sync::BundledAggregations{store,
                                     visibility,
                                     user_id,
                                     ignored_senders,
                                     [&store](database::PersistentEvent const& child) {
                                         return client_event_with_id(store, child);
                                     },
                                     enabled};
}

namespace
{
    // May this user read events of this room at all? Spec (Room History Visibility): "In all cases except
    // `world_readable`, a user needs to join a room to view events in that room"; a user who was joined keeps
    // the events they were allowed to see. Which events they then see is decided per event by
    // sync::HistoryVisibility (src/homeserver/AGENTS.md, "Read paths that return room events or state").
    [[nodiscard]] auto may_read_room_events(database::PersistentStore const& store, std::string_view room_id,
                                            std::string_view user_id) -> bool
    {
        return sync::room_read_access_for(store, room_id, user_id).kind != sync::RoomReadKind::none ||
               sync::room_is_world_readable(store, room_id);
    }

    // GET /relations?recurse=true (ADR-0475): the most levels of relationships walked, direct ones being the
    // first. The spec asks for at least 3 and sets no maximum.
    constexpr auto relations_max_depth = std::int64_t{3};
    // The most relation-bearing events offered to the walk beyond the first level, however the graph is
    // shaped, so a client that builds a wide tree cannot make one request do unbounded work under the lock.
    constexpr auto relations_max_indirect_examined = std::size_t{2048U};

    // An event whose content carries an `m.relates_to` naming an event.
    struct RelationEdge final
    {
        database::PersistentEvent const* event{nullptr};
        std::string target{};
        std::optional<std::string> rel_type{};
        std::optional<std::string> event_type{};
    };

    [[nodiscard]] auto parse_stream_ordering_token(std::optional<std::string> const& token)
        -> std::optional<std::uint64_t>
    {
        if (!token.has_value())
        {
            return std::nullopt;
        }
        auto value = std::uint64_t{0U};
        auto const [ptr, error] = std::from_chars(token->data(), token->data() + token->size(), value);
        if (error == std::errc{} && ptr == token->data() + token->size())
        {
            return value;
        }
        return std::nullopt;
    }

} // namespace

[[nodiscard]] auto fetch_relations(HomeserverRuntime const& runtime, std::string_view access_token,
                                   FetchRelationsRequest const& request) -> OperationResult
{
    // `authenticated_user` is non-const because the audit-routing helper writes
    // a row on token rejection; the const cast is safe for the read-only path.
    auto const user_id = authenticated_user(const_cast<HomeserverRuntime&>(runtime), access_token);
    if (!user_id.has_value())
    {
        return make_operation_result(false, {}, "unauthenticated", 401U);
    }

    // Spec (GET /relations, `dir`): "One of: [b, f]", default b. A value outside the enum is a bad
    // request, not a silent backward page.
    if (request.dir.has_value() && *request.dir != "b" && *request.dir != "f")
    {
        auto result = make_operation_result(false, {}, "dir must be one of: b, f", 400U);
        result.errcode = "M_INVALID_PARAM";
        return result;
    }

    // Spec: "404 The parent event was not found or the user does not have permission to read this event
    // (it might be contained in history that is not accessible to the user)". A user who left, or a peek of a
    // world_readable room, is not refused here: the per-event HistoryVisibility below decides.
    auto const* room = find_room(runtime.database, request.room_id);
    if (room == nullptr || !may_read_room_events(runtime.database.persistent_store, request.room_id, *user_id))
    {
        return make_operation_result(false, {}, "not joined or unknown room", 404U);
    }

    auto const& store = runtime.database.persistent_store;
    // Room History Visibility (CSAZ-3): one filter for the request. A parent the user may not
    // see is "not found", like GET /event, and children they may not see are not listed.
    auto visibility = sync::HistoryVisibility{store, *user_id};
    // Each child listed is itself an event served to the client, so it carries its own bundled
    // aggregations ("Aggregations of child events").
    auto const ignored_senders = trust_safety::resolve_ignored_users(store, *user_id);
    auto aggregations = make_bundled_aggregations(store, visibility, *user_id, ignored_senders);
    auto const parent = store.events.find_in_room(request.room_id, request.event_id);
    if (parent == store.events.end() || !visibility.can_see(*parent))
    {
        return make_operation_result(false, {}, "parent event not found", 404U);
    }

    // One pass over the room's events collects those that relate to an event; an event with no
    // `m.relates_to` costs a substring search, not a parse. The edges are then grouped by target.
    auto edges = std::vector<RelationEdge>{};
    for (auto const& event : store.events.room_in_stream_order(request.room_id))
    {
        if (event.json.find("\"m.relates_to\"") == std::string::npos)
        {
            continue;
        }
        auto const parsed = canonicaljson::parse_lossless(event.json);
        if (parsed.error != canonicaljson::ParseError::none)
        {
            continue;
        }
        auto const* event_obj = std::get_if<canonicaljson::Object>(&parsed.value.storage());
        auto const* content_value = event_obj == nullptr ? nullptr : object_member(*event_obj, "content");
        auto const* content_obj =
            content_value == nullptr ? nullptr : std::get_if<canonicaljson::Object>(&content_value->storage());
        auto const* relates_value = content_obj == nullptr ? nullptr : object_member(*content_obj, "m.relates_to");
        auto const* relates_obj =
            relates_value == nullptr ? nullptr : std::get_if<canonicaljson::Object>(&relates_value->storage());
        auto const* related_event_id = relates_obj == nullptr ? nullptr : string_member(*relates_obj, "event_id");
        if (related_event_id == nullptr)
        {
            continue;
        }
        auto edge = RelationEdge{&event, *related_event_id, std::nullopt, std::nullopt};
        if (auto const* rel_type = string_member(*relates_obj, "rel_type"); rel_type != nullptr)
        {
            edge.rel_type = *rel_type;
        }
        if (auto const* type = string_member(*event_obj, "type"); type != nullptr)
        {
            edge.event_type = *type;
        }
        edges.push_back(std::move(edge));
    }
    auto edges_by_target = std::unordered_map<std::string_view, std::vector<std::size_t>>{};
    for (auto index = std::size_t{0U}; index < edges.size(); ++index)
    {
        edges_by_target[edges[index].target].push_back(index);
    }

    // Level 1 is the direct relations of the parent. With `recurse=true` each level after it is the
    // relations of the events the level before returned (never of an event the filters or the viewer's
    // history visibility left out: "Events ... whose only relation to the original given event is through a
    // non-matching intermediate event, will not be included"). The walk stops after relations_max_depth
    // levels or when it has offered relations_max_indirect_examined events beyond the first level; the
    // response reports the levels it completed.
    auto const recurse = request.recurse.value_or(false);
    auto matches = std::vector<database::PersistentEvent const*>{};
    auto seen = std::unordered_set<std::string>{request.event_id};
    auto frontier = std::vector<std::string_view>{request.event_id};
    auto indirect_examined = std::size_t{0U};
    auto levels_completed = std::int64_t{0};
    auto const levels_wanted = recurse ? relations_max_depth : std::int64_t{1};
    for (auto level = std::int64_t{1}; level <= levels_wanted; ++level)
    {
        auto next_frontier = std::vector<std::string_view>{};
        auto stopped = false;
        for (auto const target : frontier)
        {
            auto const children = edges_by_target.find(target);
            if (children == edges_by_target.end())
            {
                continue;
            }
            for (auto const index : children->second)
            {
                if (level > 1)
                {
                    if (indirect_examined == relations_max_indirect_examined)
                    {
                        stopped = true;
                        break;
                    }
                    ++indirect_examined;
                }
                auto const& edge = edges[index];
                if (request.event_type.has_value() &&
                    (!edge.event_type.has_value() || *edge.event_type != *request.event_type))
                {
                    continue;
                }
                if (request.rel_type.has_value() && (!edge.rel_type.has_value() || *edge.rel_type != *request.rel_type))
                {
                    continue;
                }
                if (!visibility.can_see(*edge.event) || !seen.insert(edge.event->event_id).second)
                {
                    continue;
                }
                matches.push_back(edge.event);
                next_frontier.push_back(edge.event->event_id);
            }
            if (stopped)
            {
                break;
            }
        }
        if (stopped)
        {
            break;
        }
        // A level with nothing to walk from completes every level after it as well.
        levels_completed = next_frontier.empty() ? levels_wanted : level;
        if (next_frontier.empty())
        {
            break;
        }
        frontier = std::move(next_frontier);
    }

    auto const forward = request.dir.has_value() && *request.dir == "f";
    if (forward)
    {
        std::ranges::sort(matches, {}, [](database::PersistentEvent const* event) {
            return event->stream_ordering;
        });
    }
    else
    {
        std::ranges::sort(matches, std::ranges::greater{}, [](database::PersistentEvent const* event) {
            return event->stream_ordering;
        });
    }

    // `from` may be "a next_batch token from /sync". This endpoint's own tokens are
    // inclusive positions (forward keeps events at or after one, backward at or before one);
    // a /sync next_batch names the newest event that sync delivered, so forward starts
    // after it and backward includes it.
    auto const relations_position = [forward](std::optional<std::string> const& token, bool is_from) {
        if (auto const plain = parse_stream_ordering_token(token); plain.has_value())
        {
            return plain;
        }
        auto const decoded = token.has_value() ? sync::decode_stream_token(*token) : std::nullopt;
        if (!decoded.has_value())
        {
            return std::optional<std::uint64_t>{};
        }
        return std::optional<std::uint64_t>{is_from && forward ? decoded->event_ordering + 1U
                                                               : decoded->event_ordering};
    };
    auto const from_token = relations_position(request.from, true);
    auto const to_token = relations_position(request.to, false);
    auto constexpr default_limit = std::uint64_t{100U};
    auto const max_limit = static_cast<std::uint64_t>(runtime.config.server().client_api.max_relations_page_size);
    auto limit = request.limit.value_or(default_limit);
    if (limit == 0U || limit > max_limit)
    {
        limit = max_limit;
    }

    auto start = std::size_t{0U};
    if (from_token.has_value())
    {
        if (forward)
        {
            while (start < matches.size() && matches[start]->stream_ordering < *from_token)
            {
                ++start;
            }
        }
        else
        {
            while (start < matches.size() && matches[start]->stream_ordering > *from_token)
            {
                ++start;
            }
        }
    }

    auto end = matches.size();
    if (to_token.has_value())
    {
        if (forward)
        {
            while (end > start && matches[end - 1U]->stream_ordering > *to_token)
            {
                --end;
            }
        }
        else
        {
            while (end > start && matches[end - 1U]->stream_ordering < *to_token)
            {
                --end;
            }
        }
    }

    // `end` is now the end of the requested range. A page cut by `limit` ends before it and has a
    // next_batch; a range that `to` closed has no more results to offer.
    auto const range_end = end;
    if (end - start > static_cast<std::size_t>(limit))
    {
        end = start + static_cast<std::size_t>(limit);
    }

    auto chunk = canonicaljson::Array{};
    chunk.reserve(end - start);
    for (auto index = start; index < end; ++index)
    {
        chunk.push_back(aggregations.apply(*matches[index], client_event_with_id(store, *matches[index])));
    }

    auto response = canonicaljson::Object{};
    response.push_back(canonicaljson::make_member("chunk", canonicaljson::Value{std::move(chunk)}));

    if (start > 0U)
    {
        response.push_back(canonicaljson::make_member(
            "prev_batch", canonicaljson::Value{std::to_string(matches[start - 1U]->stream_ordering)}));
    }
    if (end < range_end)
    {
        response.push_back(canonicaljson::make_member(
            "next_batch", canonicaljson::Value{std::to_string(matches[end]->stream_ordering)}));
    }
    if (request.recurse.has_value())
    {
        // Spec: mandatory when `recurse` was supplied: "the actual depth to which the server recursed".
        response.push_back(canonicaljson::make_member("recursion_depth", canonicaljson::Value{levels_completed}));
    }

    auto serialized = canonicaljson::serialize_canonical(canonicaljson::Value{std::move(response)});
    if (serialized.error != canonicaljson::CanonicalJsonError::none)
    {
        return make_operation_result(false, {}, "relations serialization failed", 500U);
    }
    return make_operation_result(true, std::move(serialized.output));
}

[[nodiscard]] auto fetch_room_threads(HomeserverRuntime const& runtime, std::string_view access_token,
                                      FetchThreadsRequest const& request) -> OperationResult
{
    // `authenticated_user` is non-const because the audit-routing helper writes
    // a row on token rejection; the const cast is safe for the read-only path.
    auto const user_id = authenticated_user(const_cast<HomeserverRuntime&>(runtime), access_token);
    if (!user_id.has_value())
    {
        return make_operation_result(false, {}, "unauthenticated", 401U);
    }

    // Spec: "include ... One of: [all, participated]". A value outside the enum
    // is a bad request, not a silent fallback to "all" — a client asking for the
    // filtered view must never be handed the unfiltered one.
    auto const participated_only = request.include.has_value() && *request.include == "participated";
    if (request.include.has_value() && *request.include != "all" && !participated_only)
    {
        return make_operation_result(false, {}, "include must be one of: all, participated", 400U);
    }

    // Spec: "limit ... Must be an integer greater than zero."
    if (request.limit.has_value() && *request.limit == 0U)
    {
        return make_operation_result(false, {}, "limit must be greater than zero", 400U);
    }

    // Spec 403: "The user cannot view or peek on the room ... The room does not
    // exist."
    auto const* room = find_room(runtime.database, request.room_id);
    if (room == nullptr || !may_read_room_events(runtime.database.persistent_store, request.room_id, *user_id))
    {
        return make_operation_result(false, {}, "cannot view threads in this room", 403U);
    }

    auto const& store = runtime.database.persistent_store;
    // Resolved once for the whole request, never inside the per-event loop.
    auto const ignored_senders = trust_safety::resolve_ignored_users(store, *user_id);

    // Room History Visibility (CSAZ-3): a child the user may not see does not count towards
    // a thread, and a root they may not see is not listed.
    auto visibility = sync::HistoryVisibility{store, *user_id};

    // One walk over the room's newest events collects, for every thread root, the number of
    // m.thread children, the most recent child, and whether the caller participated. The walk
    // reads the room's own events through the per-room time index and offers at most
    // `max_events_examined` of them (F-33, ADR-0345); aggregation is keyed by root ID, so the cost
    // is linear in the rows offered.
    struct ThreadAggregate final
    {
        database::PersistentEvent const* root{nullptr};
        database::PersistentEvent const* latest_child{nullptr};
        std::int64_t count{0};
        bool participated{false};
    };
    auto aggregates = std::unordered_map<std::string, ThreadAggregate>{};
    auto const max_events_examined = request.max_events_examined.value_or(max_thread_events_examined);

    std::ignore = store.events.walk_room_newest_first(
        request.room_id,
        [&](database::PersistentEvent const& event) {
            // Spec: "Servers must additionally ensure they do not consider child events
            // from ignored users when preparing an aggregation for the client."
            if (trust_safety::is_delivery_suppressed(ignored_senders, event.sender_user_id, false))
            {
                return;
            }
            auto const parsed = canonicaljson::parse_lossless(event.json);
            if (parsed.error != canonicaljson::ParseError::none)
            {
                return;
            }
            auto const* event_obj = std::get_if<canonicaljson::Object>(&parsed.value.storage());
            if (event_obj == nullptr)
            {
                return;
            }
            auto const* content_value = object_member(*event_obj, "content");
            auto const* content_obj =
                content_value == nullptr ? nullptr : std::get_if<canonicaljson::Object>(&content_value->storage());
            if (content_obj == nullptr)
            {
                return;
            }
            auto const* relates_value = object_member(*content_obj, "m.relates_to");
            auto const* relates_obj =
                relates_value == nullptr ? nullptr : std::get_if<canonicaljson::Object>(&relates_value->storage());
            if (relates_obj == nullptr)
            {
                return;
            }
            auto const* rel_type = string_member(*relates_obj, "rel_type");
            auto const* root_id = string_member(*relates_obj, "event_id");
            if (rel_type == nullptr || *rel_type != "m.thread" || root_id == nullptr)
            {
                return;
            }
            // The relation's target is client-chosen text: one that is not a well-formed event ID
            // (appendices, "Event IDs": at most 255 bytes) names no event, and would only cost
            // memory as a key.
            if (root_id->size() > events::max_id_length_bytes || !events::event_id_is_valid(*root_id))
            {
                return;
            }

            if (!visibility.can_see(event))
            {
                return;
            }

            auto& aggregate = aggregates[*root_id];
            ++aggregate.count;
            if (aggregate.latest_child == nullptr || sync::is_later_in_thread(event, *aggregate.latest_child))
            {
                aggregate.latest_child = &event;
            }
            // Spec: participated when the caller is "the sender of an event which
            // references the thread root with a rel_type of m.thread".
            if (event.sender_user_id == *user_id)
            {
                aggregate.participated = true;
            }
        },
        max_events_examined);

    // Attach each root event. A relation naming an event this server does not
    // hold (or one in another room) is not a thread we can list.
    for (auto& [root_id, aggregate] : aggregates)
    {
        auto const root = store.events.find_in_room(request.room_id, root_id);
        if (root == store.events.end() || !visibility.can_see(*root))
        {
            continue;
        }
        aggregate.root = &*root;
        // Spec: participated is also true when the caller is "the sender of the
        // thread root event".
        if (root->sender_user_id == *user_id)
        {
            aggregate.participated = true;
        }
    }

    auto listed = std::vector<ThreadAggregate>{};
    listed.reserve(aggregates.size());
    for (auto const& aggregate : aggregates | std::views::values)
    {
        if (aggregate.root == nullptr || aggregate.latest_child == nullptr)
        {
            continue;
        }
        if (participated_only && !aggregate.participated)
        {
            continue;
        }
        listed.push_back(aggregate);
    }

    // Spec: "The thread roots, ordered by the latest_event in each event's
    // aggregated children" — most recent first, matching the default "start from
    // the most recent event" pagination direction.
    std::ranges::sort(listed, std::ranges::greater{}, [](ThreadAggregate const& aggregate) {
        return aggregate.latest_child->stream_ordering;
    });

    // `from` is the latest_event stream ordering of the next root to return, as
    // handed out in a previous response's next_batch. Spec 400: "The from token
    // is unknown to the server."
    auto start = std::size_t{0U};
    if (request.from.has_value())
    {
        auto const from_token = parse_stream_ordering_token(request.from);
        if (!from_token.has_value())
        {
            return make_operation_result(false, {}, "invalid from token", 400U);
        }
        while (start < listed.size() && listed[start].latest_child->stream_ordering > *from_token)
        {
            ++start;
        }
    }

    auto constexpr default_limit = std::uint64_t{50U};
    auto const max_limit = static_cast<std::uint64_t>(runtime.config.server().client_api.max_threads_page_size);
    auto const limit = std::min(request.limit.value_or(default_limit), max_limit);
    auto end = listed.size();
    if (end - start > static_cast<std::size_t>(limit))
    {
        end = start + static_cast<std::size_t>(limit);
    }

    auto const* version_policy =
        rooms::find_room_version_policy(room_version_for_room(runtime.database.persistent_store, request.room_id));

    auto aggregations = make_bundled_aggregations(store, visibility, *user_id, ignored_senders);
    auto chunk = canonicaljson::Array{};
    chunk.reserve(end - start);
    for (auto index = start; index < end; ++index)
    {
        auto const& aggregate = listed[index];
        auto root_event = client_event_with_id(store, *aggregate.root);
        // Spec: "If the thread root event was sent by an ignored user, the event is
        // returned redacted to the caller." The thread itself still exists, so the
        // root is listed — stripped rather than omitted.
        if (version_policy != nullptr &&
            trust_safety::is_delivery_suppressed(ignored_senders, aggregate.root->sender_user_id, false))
        {
            auto redacted = events::redact_event(root_event, *version_policy);
            if (redacted.error.empty())
            {
                root_event = std::move(redacted.event);
            }
        }
        // The root's m.thread (and any other) aggregation is built by the one aggregation code every
        // endpoint uses, from the relation index, not from this endpoint's walk.
        chunk.push_back(aggregations.apply(*aggregate.root, std::move(root_event)));
    }

    auto response = canonicaljson::Object{};
    response.push_back(canonicaljson::make_member("chunk", canonicaljson::Value{std::move(chunk)}));
    // Spec: next_batch is "Not present when there are no further results."
    if (end < listed.size())
    {
        response.push_back(canonicaljson::make_member(
            "next_batch", canonicaljson::Value{std::to_string(listed[end].latest_child->stream_ordering)}));
    }

    auto serialized = canonicaljson::serialize_canonical(canonicaljson::Value{std::move(response)});
    if (serialized.error != canonicaljson::CanonicalJsonError::none)
    {
        return make_operation_result(false, {}, "threads serialization failed", 500U);
    }
    return make_operation_result(true, std::move(serialized.output));
}

[[nodiscard]] auto audit_event_count(HomeserverRuntime const& runtime) noexcept -> std::size_t
{
    return runtime.database.audit_events.size();
}

auto validate_make_join_response(std::string_view requested_room_id, std::string_view requested_user_id,
                                 std::string_view body) -> ValidatedMakeJoinResponse
{
    auto const parsed = canonicaljson::parse_lossless(body);
    if (parsed.error != canonicaljson::ParseError::none)
    {
        return {false, "make_join response is not valid canonical JSON"};
    }
    auto const* response_object = std::get_if<canonicaljson::Object>(&parsed.value.storage());
    if (response_object == nullptr)
    {
        return {false, "make_join response must be a JSON object"};
    }
    return validate_make_join_event(requested_room_id, requested_user_id, *response_object);
}

auto claim_membership_event_template(canonicaljson::Object& event, std::string_view our_server_name,
                                     std::int64_t now_ms) -> void
{
    // The resident's template is signed and stored as this server's own event, so an `unsigned` it carries
    // (covered by no signature) is dropped with the `event_id` (ADR-0402).
    std::erase_if(event, [](canonicaljson::ObjectMember const& member) {
        return member.key == "event_id" || member.key == "unsigned";
    });
    replace_or_add_member(event, "origin", canonicaljson::Value{std::string{our_server_name}});
    replace_or_add_member(event, "origin_server_ts", canonicaljson::Value{now_ms});
}

auto restrict_membership_template_content(canonicaljson::Object& event, std::string_view our_server_name,
                                          bool allow_join_authoriser) -> std::string
{
    auto const* const template_content = object_member_as_object(event, "content");
    if (template_content == nullptr)
    {
        return {};
    }
    auto content = canonicaljson::Object{};
    if (auto const* const membership = string_member(*template_content, "membership"); membership != nullptr)
    {
        content.push_back(canonicaljson::make_member("membership", canonicaljson::Value{*membership}));
    }
    if (allow_join_authoriser)
    {
        if (auto const* const authoriser = string_member(*template_content, "join_authorised_via_users_server");
            authoriser != nullptr)
        {
            // The spec defines it as a user of the resident; one of ours would have this server vouch for itself.
            if (auth::user_id_server_name(*authoriser) == our_server_name)
            {
                return "the template names a user of this server as the authorising user";
            }
            content.push_back(
                canonicaljson::make_member("join_authorised_via_users_server", canonicaljson::Value{*authoriser}));
        }
    }
    replace_or_add_member(event, "content", canonicaljson::Value{std::move(content)});
    return {};
}

auto validate_make_leave_response(std::string_view requested_room_id, std::string_view requested_user_id,
                                  std::string_view body) -> ValidatedMakeLeaveResponse
{
    auto const parsed = canonicaljson::parse_lossless(body);
    if (parsed.error != canonicaljson::ParseError::none)
    {
        return {false, "make_leave response is not valid canonical JSON"};
    }
    auto const* response_object = std::get_if<canonicaljson::Object>(&parsed.value.storage());
    if (response_object == nullptr)
    {
        return {false, "make_leave response must be a JSON object"};
    }
    return validate_make_leave_event(requested_room_id, requested_user_id, *response_object);
}

} // namespace merovingian::homeserver
