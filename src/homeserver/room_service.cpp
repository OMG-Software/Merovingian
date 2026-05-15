// SPDX-License-Identifier: GPL-3.0-or-later

#include "local_services.hpp"
#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/serializer.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/crypto/ed25519.hpp"
#include "merovingian/crypto/signing_service.hpp"
#include "merovingian/events/authorization.hpp"
#include "merovingian/events/event.hpp"
#include "merovingian/events/event_id.hpp"
#include "merovingian/events/event_signer.hpp"
#include "merovingian/homeserver/vertical_slice.hpp"
#include "merovingian/rooms/room_version_policy.hpp"
#include "merovingian/trust_safety/policy_engine.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <variant>

#include <sodium.h>

namespace merovingian::homeserver
{
namespace
{

    struct ComposedEvent final
    {
        std::string event_id{};
        std::string json{};
        std::uint64_t depth{0U};
        std::vector<std::string> prev_event_ids{};
        std::vector<std::string> auth_event_ids{};
        std::vector<events::EventSignature> signatures{};
        std::string event_type{};
        std::optional<std::string> state_key{};
    };

    [[nodiscard]] auto sodium_is_ready() noexcept -> bool
    {
        static auto const ready = sodium_init() >= 0;
        return ready;
    }

    [[nodiscard]] auto find_room(LocalDatabase& database, std::string_view room_id) -> LocalRoom*
    {
        auto const iterator = std::ranges::find_if(database.rooms, [room_id](LocalRoom const& room) {
            return room.room_id == room_id;
        });
        return iterator == database.rooms.end() ? nullptr : &(*iterator);
    }

    [[nodiscard]] auto find_room(LocalDatabase const& database, std::string_view room_id) -> LocalRoom const*
    {
        auto const iterator = std::ranges::find_if(database.rooms, [room_id](LocalRoom const& room) {
            return room.room_id == room_id;
        });
        return iterator == database.rooms.end() ? nullptr : &(*iterator);
    }

    [[nodiscard]] auto room_has_member(LocalRoom const& room, std::string_view user_id) noexcept -> bool
    {
        return std::ranges::any_of(room.members, [user_id](std::string const& member) {
            return member == user_id;
        });
    }

    auto generate_random_signing_keypair(std::array<unsigned char, crypto_sign_PUBLICKEYBYTES>& public_key,
                                         std::array<unsigned char, crypto_sign_SECRETKEYBYTES>& secret_key) noexcept
        -> bool
    {
        if (!sodium_is_ready())
        {
            return false;
        }
        return crypto_sign_keypair(public_key.data(), secret_key.data()) == 0;
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

    [[nodiscard]] auto ensure_runtime_signing_key(HomeserverRuntime& runtime)
        -> std::optional<database::PersistentServerSigningKey>
    {
        auto constexpr key_id = std::string_view{"ed25519:auto"};
        auto const& server_name = runtime.config.server().server_name;

        if (!runtime.database.signing_secret_key.empty())
        {
            auto existing = database::find_server_signing_key(runtime.database.persistent_store, server_name, key_id);
            if (existing.has_value())
            {
                return existing;
            }
        }

        auto public_key = std::array<unsigned char, crypto_sign_PUBLICKEYBYTES>{};
        auto secret_key = std::array<unsigned char, crypto_sign_SECRETKEYBYTES>{};
        if (!generate_random_signing_keypair(public_key, secret_key))
        {
            return std::nullopt;
        }
        auto key = database::PersistentServerSigningKey{
            std::string{server_name},
            std::string{key_id},
            events::matrix_base64_from_bytes(
                std::string_view{reinterpret_cast<char const*>(public_key.data()), public_key.size()}),
            32503680000000ULL,
        };
        if (!database::store_server_signing_key(runtime.database.persistent_store, key))
        {
            return std::nullopt;
        }
        runtime.database.signing_secret_key = std::vector<unsigned char>(secret_key.begin(), secret_key.end());
        return key;
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

    [[nodiscard]] auto previous_events_for_room(database::PersistentStore const& store, std::string_view room_id)
        -> std::vector<std::string>
    {
        for (auto iterator = store.events.rbegin(); iterator != store.events.rend(); ++iterator)
        {
            if (iterator->room_id == room_id)
            {
                return {iterator->event_id};
            }
        }
        return {};
    }

    [[nodiscard]] auto auth_events_for_room(database::PersistentStore const& store, std::string_view room_id)
        -> std::vector<std::string>
    {
        auto event_ids = std::vector<std::string>{};
        for (auto const& state : store.state)
        {
            if (state.room_id == room_id)
            {
                event_ids.push_back(state.event_id);
            }
        }
        return event_ids;
    }

    [[nodiscard]] auto next_depth_for_room(database::PersistentStore const& store, std::string_view room_id) noexcept
        -> std::uint64_t
    {
        auto depth = std::uint64_t{0U};
        for (auto const& event : store.events)
        {
            if (event.room_id == room_id && event.depth > depth)
            {
                depth = event.depth;
            }
        }
        return depth + 1U;
    }

    [[nodiscard]] auto find_event_json(database::PersistentStore const& store, std::string_view event_id)
        -> canonicaljson::Value
    {
        for (auto const& event : store.events)
        {
            if (event.event_id == event_id)
            {
                auto const parsed = canonicaljson::parse_lossless(event.json);
                if (parsed.error == canonicaljson::ParseError::none)
                {
                    return parsed.value;
                }
            }
        }
        return {};
    }

    [[nodiscard]] auto build_auth_event_map(database::PersistentStore const& store, std::string_view room_id,
                                            std::string_view sender, std::string_view target_state_key,
                                            std::string_view event_type) -> events::AuthEventMap
    {
        auto result = events::AuthEventMap{};
        for (auto const& state : store.state)
        {
            if (state.room_id != room_id)
            {
                continue;
            }
            if (state.event_type == "m.room.create" && state.state_key.empty())
            {
                result.create = find_event_json(store, state.event_id);
            }
            if (state.event_type == "m.room.power_levels" && state.state_key.empty())
            {
                result.power_levels = find_event_json(store, state.event_id);
            }
            if (state.event_type == "m.room.join_rules" && state.state_key.empty())
            {
                result.join_rules = find_event_json(store, state.event_id);
            }
            if (state.event_type == "m.room.member" && state.state_key == sender)
            {
                result.sender_member = find_event_json(store, state.event_id);
            }
            if (state.event_type == "m.room.member" && event_type == "m.room.member" &&
                state.state_key == target_state_key)
            {
                result.target_member = find_event_json(store, state.event_id);
            }
        }
        return result;
    }

    [[nodiscard]] auto compose_signed_event(HomeserverRuntime& runtime, std::string_view room_id,
                                            std::string_view sender, std::string_view client_event_json)
        -> std::optional<ComposedEvent>
    {
        auto const parsed = canonicaljson::parse_lossless(client_event_json);
        auto const* input = std::get_if<canonicaljson::Object>(&parsed.value.storage());
        auto fallback = canonicaljson::Object{};
        if (parsed.error != canonicaljson::ParseError::none || input == nullptr)
        {
            fallback.push_back(canonicaljson::make_member("type", canonicaljson::Value{std::string{"m.room.message"}}));
            fallback.push_back(
                canonicaljson::make_member("content", canonicaljson::Value{std::string{client_event_json}}));
            input = &fallback;
        }

        auto const* type = string_member(*input, "type");
        auto const event_type = type == nullptr ? std::string{"m.room.message"} : *type;
        auto const prev_events = previous_events_for_room(runtime.database.persistent_store, room_id);
        auto const auth_events = auth_events_for_room(runtime.database.persistent_store, room_id);
        auto const depth = next_depth_for_room(runtime.database.persistent_store, room_id);
        auto const now_ms = static_cast<std::int64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
                .count());
        auto event = canonicaljson::Object{};
        event.push_back(canonicaljson::make_member("type", canonicaljson::Value{event_type}));
        event.push_back(canonicaljson::make_member("room_id", canonicaljson::Value{std::string{room_id}}));
        event.push_back(canonicaljson::make_member("sender", canonicaljson::Value{std::string{sender}}));
        event.push_back(canonicaljson::make_member("origin_server_ts", canonicaljson::Value{now_ms}));
        event.push_back(canonicaljson::make_member("depth", canonicaljson::Value{static_cast<std::int64_t>(depth)}));
        event.push_back(canonicaljson::make_member("prev_events", string_array(prev_events)));
        event.push_back(canonicaljson::make_member("auth_events", string_array(auth_events)));
        event.push_back(canonicaljson::make_member("content", copy_member_or_empty_object(*input, "content")));
        auto state_key = std::optional<std::string>{};
        if (auto const* found_state_key = string_member(*input, "state_key"); found_state_key != nullptr)
        {
            state_key = *found_state_key;
            event.push_back(canonicaljson::make_member("state_key", canonicaljson::Value{*state_key}));
        }

        auto unsigned_event = canonicaljson::Value{event};
        auto const content_hash = events::make_content_hash(unsigned_event);
        if (!content_hash.error.empty())
        {
            return std::nullopt;
        }
        auto hashes = canonicaljson::Object{};
        hashes.push_back(canonicaljson::make_member("sha256", canonicaljson::Value{content_hash.sha256}));
        event.push_back(canonicaljson::make_member("hashes", canonicaljson::Value{std::move(hashes)}));
        auto hash_event = canonicaljson::Value{event};
        auto const* policy = rooms::find_room_version_policy("12");
        if (policy == nullptr)
        {
            return std::nullopt;
        }
        auto const event_id = events::make_reference_hash_event_id(hash_event, *policy);
        if (!event_id.error.empty())
        {
            return std::nullopt;
        }

        auto key = ensure_runtime_signing_key(runtime);
        if (!key.has_value())
        {
            return std::nullopt;
        }
        auto key_store = RuntimeSigningKeyStore{runtime.config.server().server_name, *key};
        auto secret_key_array = std::array<unsigned char, crypto_sign_SECRETKEYBYTES>{};
        if (runtime.database.signing_secret_key.size() == crypto_sign_SECRETKEYBYTES)
        {
            std::copy(runtime.database.signing_secret_key.begin(), runtime.database.signing_secret_key.end(),
                      secret_key_array.begin());
        }
        auto provider = RuntimeEd25519Provider{std::move(secret_key_array)};
        auto const signed_event = events::sign_event_for_server(hash_event, *policy, key_store, provider,
                                                                runtime.config.server().server_name);
        if (!signed_event.error.empty())
        {
            return std::nullopt;
        }
        auto signed_event_value = canonicaljson::parse_lossless(signed_event.event_json);
        if (signed_event_value.error == canonicaljson::ParseError::none)
        {
            auto const* policy = rooms::find_room_version_policy("12");
            if (policy != nullptr)
            {
                auto auth_map = build_auth_event_map(runtime.database.persistent_store, room_id, sender,
                                                     state_key.value_or(""), event_type);
                auto const auth_decision =
                    events::authorize_event_against_auth_events(signed_event_value.value, *policy, auth_map);
                if (!auth_decision.allowed)
                {
                    return std::nullopt;
                }
            }
        }

        return ComposedEvent{
            event_id.event_id,
            signed_event.event_json,
            depth,
            prev_events,
            auth_events,
            {{signed_event.server_name, signed_event.key_id, signed_event.signature}},
            event_type,
            state_key,
        };
    }

} // namespace

[[nodiscard]] auto create_room(HomeserverRuntime& runtime, std::string_view access_token) -> OperationResult
{
    auto const user_id = authenticated_user(runtime, access_token);
    if (!user_id.has_value())
    {
        return make_operation_result(false, {}, "unauthenticated");
    }

    auto const room_id =
        "!room" + std::to_string(runtime.database.rooms.size() + 1U) + ":" + runtime.config.server().server_name;
    auto const room_decision = trust_safety::evaluate_room_policy({room_id, false, false, {}});
    if (!room_decision.allowed)
    {
        return make_operation_result(false, {}, room_decision.reason.code);
    }

    if (!database::store_room_with_membership(runtime.database.persistent_store, {room_id, *user_id},
                                              {room_id, *user_id}))
    {
        return make_operation_result(false, {}, "room persistence failed", 500U);
    }
    runtime.database.rooms.push_back({room_id, *user_id, {*user_id}, {}});
    append_local_audit(runtime.database, observability::AuditCategory::admin, "room.created", *user_id, room_id,
                       "created");
    return make_operation_result(true, room_id);
}

[[nodiscard]] auto join_room(HomeserverRuntime& runtime, std::string_view access_token, std::string_view room_id)
    -> OperationResult
{
    auto const user_id = authenticated_user(runtime, access_token);
    if (!user_id.has_value())
    {
        return make_operation_result(false, {}, "unauthenticated");
    }

    auto* room = find_room(runtime.database, room_id);
    if (room == nullptr)
    {
        return make_operation_result(false, {}, "unknown room");
    }
    if (!room_has_member(*room, *user_id))
    {
        if (!database::store_membership(runtime.database.persistent_store, {std::string{room_id}, *user_id}))
        {
            return make_operation_result(false, {}, "membership persistence failed", 500U);
        }
        room->members.push_back(*user_id);
    }

    append_local_audit(runtime.database, observability::AuditCategory::admin, "room.joined", *user_id, room_id,
                       "joined");
    return make_operation_result(true, std::string{room_id});
}

// NOLINTBEGIN(bugprone-easily-swappable-parameters)
[[nodiscard]] auto send_event(HomeserverRuntime& runtime, std::string_view access_token, std::string_view room_id,
                              std::string_view event_json) -> OperationResult
{
    auto const user_id = authenticated_user(runtime, access_token);
    if (!user_id.has_value())
    {
        return make_operation_result(false, {}, "unauthenticated");
    }

    auto* room = find_room(runtime.database, room_id);
    if (room == nullptr)
    {
        return make_operation_result(false, {}, "unknown room");
    }
    if (!room_has_member(*room, *user_id))
    {
        return make_operation_result(false, {}, "not joined");
    }
    if (event_json.empty())
    {
        return make_operation_result(false, {}, "empty event");
    }

    auto const composed = compose_signed_event(runtime, room_id, *user_id, event_json);
    if (!composed.has_value())
    {
        return make_operation_result(false, {}, "event authorization or signing failed", 403U);
    }
    auto state = std::optional<database::PersistentStateEvent>{};
    if (composed->state_key.has_value())
    {
        state = database::PersistentStateEvent{std::string{room_id}, composed->event_type, *composed->state_key,
                                               composed->event_id};
    }
    if (!database::store_event_with_state(runtime.database.persistent_store,
                                          {composed->event_id, std::string{room_id}, *user_id, composed->json,
                                           composed->depth, composed->prev_event_ids, composed->auth_event_ids,
                                           composed->signatures},
                                          std::move(state)))
    {
        return make_operation_result(false, {}, "event persistence failed", 500U);
    }
    room->events.push_back(composed->json);
    append_local_audit(runtime.database, observability::AuditCategory::admin, "room.event_sent", *user_id, room_id,
                       "stored");
    return make_operation_result(true, composed->event_id);
}
// NOLINTEND(bugprone-easily-swappable-parameters)

[[nodiscard]] auto fetch_room_state(HomeserverRuntime const& runtime, std::string_view access_token,
                                    std::string_view room_id) -> OperationResult
{
    auto const user_id = authenticated_user(runtime, access_token);
    if (!user_id.has_value())
    {
        return make_operation_result(false, {}, "unauthenticated");
    }

    auto const* room = find_room(runtime.database, room_id);
    if (room == nullptr)
    {
        return make_operation_result(false, {}, "unknown room");
    }
    if (!room_has_member(*room, *user_id))
    {
        return make_operation_result(false, {}, "not joined");
    }

    return make_operation_result(true, "room_id=" + room->room_id + " members=" + std::to_string(room->members.size()) +
                                           " events=" + std::to_string(room->events.size()));
}

[[nodiscard]] auto audit_event_count(HomeserverRuntime const& runtime) noexcept -> std::size_t
{
    return runtime.database.audit_events.size();
}

} // namespace merovingian::homeserver
