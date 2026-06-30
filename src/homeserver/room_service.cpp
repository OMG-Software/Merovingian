// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/room_service.hpp"

#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/serializer.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/core/query_params.hpp"
#include "merovingian/crypto/ed25519.hpp"
#include "merovingian/crypto/secret_box.hpp"
#include "merovingian/crypto/signing_service.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/events/authorization.hpp"
#include "merovingian/events/event.hpp"
#include "merovingian/events/event_id.hpp"
#include "merovingian/events/event_signer.hpp"
#include "merovingian/federation/membership_endpoints.hpp"
#include "merovingian/federation/outbound_membership.hpp"
#include "merovingian/federation/outbound_transaction.hpp"
#include "merovingian/federation/server_discovery.hpp"
#include "merovingian/homeserver/auth_service.hpp"
#include "merovingian/homeserver/federation_proxy.hpp"
#include "merovingian/homeserver/local_http_router.hpp"
#include "merovingian/homeserver/local_services.hpp"
#include "merovingian/homeserver/runtime.hpp"
#include "merovingian/observability/logger.hpp"
#include "merovingian/observability/observability.hpp"
#include "merovingian/rooms/room_version_policy.hpp"
#include "merovingian/trust_safety/policy_engine.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <fstream>
#include <optional>
#include <ranges>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <variant>
#include <vector>

#include <sodium.h>

namespace merovingian::homeserver
{
namespace
{

    auto log_diagnostic(std::string_view event, std::vector<observability::StructuredLogField> fields,
                        observability::LogEventSeverity severity = observability::LogEventSeverity::debug) -> void
    {
        observability::log_diagnostic("rooms", event, fields, severity);
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
    };

    [[nodiscard]] auto compose_signed_event(HomeserverRuntime& runtime, std::string_view room_id,
                                            std::string_view sender, std::string_view client_event_json)
        -> std::optional<ComposedEvent>;
    [[nodiscard]] auto persist_composed_event(HomeserverRuntime& runtime, std::string_view room_id,
                                              std::string_view sender, ComposedEvent const& composed) -> bool;
    [[nodiscard]] auto record_room_share_started_device_changes(HomeserverRuntime& runtime, std::string_view room_id,
                                                                std::string_view joining_user_id) -> bool;
    [[nodiscard]] auto record_room_share_ended_device_changes(HomeserverRuntime& runtime, std::string_view room_id,
                                                              std::string_view departing_user_id) -> bool;

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

    // Extract the server name from a Matrix room ID. Room IDs have the form
    // !opaque:server_name — the server name is everything after the last ':'.
    [[nodiscard]] auto server_name_from_room_id(std::string_view room_id) -> std::string_view
    {
        auto const pos = room_id.rfind(':');
        return pos == std::string_view::npos ? std::string_view{} : room_id.substr(pos + 1);
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

    // Load the operator-supplied master key material from the configured file.
    // The file is treated as opaque binary material; it is hashed with domain
    // separation before being used as an encryption key.
    [[nodiscard]] auto load_master_key_material(std::string_view path) -> std::optional<std::vector<std::uint8_t>>
    {
        if (path.empty())
        {
            return std::nullopt;
        }
        auto stream = std::ifstream{std::string{path}, std::ios::binary};
        if (!stream)
        {
            log_diagnostic(
                "signing_key.master_key_file_unreadable",
                {
                    {"path",   std::string{path},                false},
                    {"reason", "failed to open master key file", false}
            });
            return std::nullopt;
        }
        auto content = std::vector<std::uint8_t>{};
        auto const size_limit = std::size_t{4096U};
        auto buffer = std::array<char, 1024U>{};
        while (stream.good())
        {
            stream.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
            auto const count = static_cast<std::size_t>(stream.gcount());
            if (count == 0U)
            {
                break;
            }
            if (content.size() + count > size_limit)
            {
                log_diagnostic(
                    "signing_key.master_key_file_unreadable",
                    {
                        {"path",   std::string{path},                    false},
                        {"reason", "master key file exceeds size limit", false}
                });
                return std::nullopt;
            }
            content.insert(content.end(), reinterpret_cast<std::uint8_t*>(buffer.data()),
                           reinterpret_cast<std::uint8_t*>(buffer.data()) + count);
        }
        if (content.empty())
        {
            log_diagnostic("signing_key.master_key_file_unreadable",
                           {
                               {"path",   std::string{path},          false},
                               {"reason", "master key file is empty", false}
            });
            return std::nullopt;
        }
        return content;
    }

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
        auto const master_key_material = load_master_key_material(runtime.config.security().secrets.master_key_file);
        if (!master_key_material.has_value())
        {
            return std::nullopt;
        }
        auto const key = crypto::derive_secret_box_key(*master_key_material);
        if (!key.has_value())
        {
            return std::nullopt;
        }
        auto const ciphertext = crypto::secret_box_encrypt(secret, *key);
        if (!ciphertext.has_value())
        {
            return std::nullopt;
        }
        return encode_encrypted_secret_for_storage(*ciphertext);
    }

    // Decrypt a stored signing secret.  Returns nullopt if the value is encrypted
    // but cannot be decrypted (wrong master key / corrupted).  For legacy plaintext
    // rows, returns the decoded bytes directly.
    [[nodiscard]] auto decrypt_stored_signing_secret(HomeserverRuntime const& runtime, std::string_view stored)
        -> std::optional<std::vector<std::uint8_t>>
    {
        if (auto const ciphertext = decode_encrypted_secret_from_storage(stored); ciphertext.has_value())
        {
            auto const master_key_material =
                load_master_key_material(runtime.config.security().secrets.master_key_file);
            if (!master_key_material.has_value())
            {
                log_diagnostic(
                    "signing_key.decryption_failed",
                    {
                        {"reason", "encrypted signing secret requires security.secrets.master_key_file", false}
                });
                return std::nullopt;
            }
            auto const key = crypto::derive_secret_box_key(*master_key_material);
            if (!key.has_value())
            {
                return std::nullopt;
            }
            auto const plaintext = crypto::secret_box_decrypt(*ciphertext, *key);
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

        // Legacy plaintext base64 secret: decode and return as-is.  A diagnostic
        // is emitted so operators can rotate to an encrypted secret.
        auto const decoded = events::matrix_bytes_from_base64(stored);
        if (!decoded.empty())
        {
            log_diagnostic(
                "signing_key.legacy_plaintext",
                {
                    {"reason", "signing secret is stored plaintext; rotate to enable at-rest encryption", false}
            });
        }
        return std::vector<std::uint8_t>{decoded.begin(), decoded.end()};
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

    auto merge_object_into(canonicaljson::Object& destination, canonicaljson::Object const& source) -> void
    {
        for (auto const& member : source)
        {
            auto existing = std::ranges::find_if(destination, [&member](canonicaljson::ObjectMember const& current) {
                return current.key == member.key;
            });
            if (existing != destination.end())
            {
                auto const* destination_object = std::get_if<canonicaljson::Object>(&existing->value->storage());
                auto const* source_object = std::get_if<canonicaljson::Object>(&member.value->storage());
                if (destination_object != nullptr && source_object != nullptr)
                {
                    auto merged = *destination_object;
                    merge_object_into(merged, *source_object);
                    existing->value = std::make_unique<canonicaljson::Value>(std::move(merged));
                    continue;
                }
                existing->value = std::make_unique<canonicaljson::Value>(*member.value);
                continue;
            }
            destination.push_back(canonicaljson::make_member(member.key, *member.value));
        }
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

    [[nodiscard]] auto room_version_number(std::string_view room_version) -> int
    {
        auto parsed = int{0};
        auto const [ptr, error] =
            std::from_chars(room_version.data(), room_version.data() + room_version.size(), parsed);
        return error == std::errc{} && ptr == room_version.data() + room_version.size() ? parsed : 0;
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
        // The origin field was removed from events in room version 4 (hash-based
        // event IDs replaced server-name-based IDs). Do not require it on the
        // make_join event template — room versions 10/11/12 omit it.
        if (integer_member(*event_object, "origin_server_ts") == nullptr)
        {
            return {false, "make_join event origin_server_ts is required"};
        }
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
        if (integer_member(*event_object, "origin_server_ts") == nullptr)
        {
            return {false, "make_leave event origin_server_ts is required"};
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

    [[nodiscard]] auto event_json_for_id(database::PersistentStore const& store, std::string_view event_id)
        -> std::optional<std::string>
    {
        auto const event = std::ranges::find_if(store.events, [&](database::PersistentEvent const& current) {
            return current.event_id == event_id;
        });
        return event == store.events.end() ? std::nullopt : std::optional<std::string>{event->json};
    }

    [[nodiscard]] auto invite_state_events_for_room(database::PersistentStore const& store, std::string_view room_id,
                                                    std::string_view invitee) -> std::vector<std::string>
    {
        auto events = std::vector<std::string>{};
        for (auto const& state : store.state)
        {
            if (state.room_id != room_id)
            {
                continue;
            }
            if (state.event_type == "m.room.member" && state.state_key == invitee)
            {
                continue;
            }
            auto const event_json = event_json_for_id(store, state.event_id);
            if (event_json.has_value())
            {
                events.push_back(*event_json);
            }
        }
        return events;
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
        auto const state = std::ranges::find_if(store.state, [&](database::PersistentStateEvent const& current) {
            return current.room_id == room_id && current.event_type == "m.room.member" && current.state_key == user_id;
        });
        return state == store.state.end() ? std::nullopt : std::optional<database::PersistentStateEvent>{*state};
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
               database::update_membership(store, room_id, user_id, membership);
    }

    [[nodiscard]] auto upsert_local_invite_metadata(database::PersistentStore& store, std::string_view room_id,
                                                    std::string_view sender_user_id, std::string_view target_user_id,
                                                    std::uint64_t stream_ordering) -> bool
    {
        auto const invite_state = membership_state_entry(store, room_id, target_user_id);
        if (!invite_state.has_value())
        {
            return false;
        }
        auto const invite_json = event_json_for_id(store, invite_state->event_id);
        return invite_json.has_value() &&
               database::upsert_invite(store,
                                       {std::string{room_id}, std::string{target_user_id}, std::string{sender_user_id},
                                        invite_state->event_id, *invite_json,
                                        invite_state_events_for_room(store, room_id, target_user_id), stream_ordering});
    }

    [[nodiscard]] auto persist_membership_transition(HomeserverRuntime& runtime, std::string_view room_id,
                                                     std::string_view sender_user_id, std::string_view target_user_id,
                                                     std::string_view membership, std::string_view reason = {})
        -> OperationResult
    {
        auto const event_json = serialize_membership_event_json(target_user_id, membership, reason);
        if (!event_json.has_value())
        {
            return make_operation_result(false, {}, "membership event serialization failed", 500U);
        }

        auto const composed = compose_signed_event(runtime, room_id, sender_user_id, *event_json);
        if (!composed.has_value())
        {
            return make_operation_result(false, {}, "membership event rejected", 403U);
        }
        if (!persist_composed_event(runtime, room_id, sender_user_id, *composed))
        {
            return make_operation_result(false, {}, "membership event persistence failed", 500U);
        }

        if (auto* room = find_room(runtime.database, room_id); room != nullptr)
        {
            room->events.push_back(composed->json);
        }

        auto const membership_stream = runtime.database.next_stream_ordering++;
        if (!store_or_update_membership(runtime.database.persistent_store, room_id, target_user_id, membership,
                                        membership_stream))
        {
            return make_operation_result(false, {}, "membership persistence failed", 500U);
        }

        if ((membership == "leave" || membership == "ban") &&
            !record_room_share_ended_device_changes(runtime, room_id, target_user_id))
        {
            return make_operation_result(false, {}, "device list change persistence failed", 500U);
        }

        apply_runtime_membership(runtime.database, room_id, target_user_id, membership);
        if (membership == "invite")
        {
            if (!upsert_local_invite_metadata(runtime.database.persistent_store, room_id, sender_user_id,
                                              target_user_id, membership_stream))
            {
                return make_operation_result(false, {}, "invite metadata persistence failed", 500U);
            }
        }
        else if ((membership == "join" || membership == "leave" || membership == "ban") &&
                 !database::delete_invite(runtime.database.persistent_store, room_id, target_user_id))
        {
            return make_operation_result(false, {}, "invite metadata cleanup failed", 500U);
        }

        auto const sync_stream_id = database::allocate_sync_stream_id(runtime.database.persistent_store);
        if (runtime.sync_notifier != nullptr)
        {
            runtime.sync_notifier->publish(runtime.database.next_stream_ordering - 1U, sync_stream_id);
        }
        return make_operation_result(true, std::string{room_id});
    }

    // Per the Matrix spec v1.18 Sec. 4.4 auth_events, only specific event types
    // belong in auth_events depending on the event being composed:
    //   m.room.create:  none
    //   m.room.member:  {create, power_levels, join_rules, sender_member, target_member}
    //   all others:      {create, power_levels, sender_member}
    // Room v12 (MSC4291) excludes create from auth_events (implied by room ID).
    // Synapse rejects events that include unrelated auth_events (e.g. join_rules
    // in a history_visibility event) with "unexpected auth_event".
    [[nodiscard]] auto auth_events_for_room(database::PersistentStore const& store, std::string_view room_id,
                                            std::string_view event_type, std::string_view target_state_key,
                                            std::string_view sender, bool exclude_create) -> std::vector<std::string>
    {
        if (event_type == "m.room.create")
        {
            return {};
        }
        auto event_ids = std::vector<std::string>{};
        for (auto const& state : store.state)
        {
            if (state.room_id != room_id)
            {
                continue;
            }
            if (state.event_type == "m.room.create" && state.state_key.empty())
            {
                if (!exclude_create)
                {
                    event_ids.push_back(state.event_id);
                }
                continue;
            }
            if (state.event_type == "m.room.power_levels" && state.state_key.empty())
            {
                event_ids.push_back(state.event_id);
                continue;
            }
            if (state.event_type == "m.room.join_rules" && state.state_key.empty())
            {
                if (event_type == "m.room.member")
                {
                    event_ids.push_back(state.event_id);
                }
                continue;
            }
            if (state.event_type == "m.room.member")
            {
                if (event_type == "m.room.member" && state.state_key == target_state_key)
                {
                    event_ids.push_back(state.event_id);
                    continue;
                }
                if (state.state_key == sender)
                {
                    // Avoid duplicate when sender == target (self-join).
                    if (event_type != "m.room.member" || target_state_key != sender)
                    {
                        event_ids.push_back(state.event_id);
                    }
                    continue;
                }
                continue;
            }
            // All other state event types (history_visibility, guest_access,
            // encryption, canonical_alias, etc.) are NOT valid auth_events
            // for any event type per the Matrix spec.
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

    [[nodiscard]] auto users_share_joined_room(LocalDatabase const& database, std::string_view left_user_id,
                                               std::string_view right_user_id,
                                               std::string_view excluding_room_id = {}) noexcept -> bool
    {
        return std::ranges::any_of(database.rooms, [&](LocalRoom const& room) {
            return room.room_id != excluding_room_id && room_has_member(room, left_user_id) &&
                   room_has_member(room, right_user_id);
        });
    }

    [[nodiscard]] auto record_local_device_list_change(LocalDatabase& database, std::string_view observer_user_id,
                                                       std::string_view subject_user_id, std::string_view change_type)
        -> bool
    {
        if (observer_user_id == subject_user_id || !is_local_user(database, observer_user_id))
        {
            return true;
        }
        return database::record_device_list_change(
            database.persistent_store,
            {0U, std::string{observer_user_id}, std::string{subject_user_id}, std::string{change_type}});
    }

    [[nodiscard]] auto record_room_share_started_device_changes(HomeserverRuntime& runtime, std::string_view room_id,
                                                                std::string_view joining_user_id) -> bool
    {
        auto const* room = find_room(runtime.database, room_id);
        if (room == nullptr)
        {
            return true;
        }
        for (auto const& member : room->members)
        {
            if (member == joining_user_id)
            {
                continue;
            }
            if (!record_local_device_list_change(runtime.database, member, joining_user_id, "changed") ||
                !record_local_device_list_change(runtime.database, joining_user_id, member, "changed"))
            {
                return false;
            }
        }
        return true;
    }

    [[nodiscard]] auto record_room_share_ended_device_changes(HomeserverRuntime& runtime, std::string_view room_id,
                                                              std::string_view departing_user_id) -> bool
    {
        auto const* room = find_room(runtime.database, room_id);
        if (room == nullptr)
        {
            return true;
        }
        for (auto const& member : room->members)
        {
            if (member == departing_user_id ||
                users_share_joined_room(runtime.database, departing_user_id, member, room_id))
            {
                continue;
            }
            if (!record_local_device_list_change(runtime.database, member, departing_user_id, "left") ||
                !record_local_device_list_change(runtime.database, departing_user_id, member, "left"))
            {
                return false;
            }
        }
        return true;
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

    // Returns the room_version string from the room's m.room.create event, or "10"
    // as a safe fallback for rooms that pre-date initial-state generation.
    [[nodiscard]] auto room_version_for_room(database::PersistentStore const& store, std::string_view room_id)
        -> std::string
    {
        for (auto const& state : store.state)
        {
            if (state.room_id != room_id || state.event_type != "m.room.create" || !state.state_key.empty())
            {
                continue;
            }
            auto const evt = find_event_json(store, state.event_id);
            auto const* obj = std::get_if<canonicaljson::Object>(&evt.storage());
            if (obj == nullptr)
            {
                break;
            }
            auto const* content_val = object_member(*obj, "content");
            if (content_val == nullptr)
            {
                break;
            }
            auto const* content_obj = std::get_if<canonicaljson::Object>(&content_val->storage());
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
        return "12"; // Latest stable version — matches the createRoom and capabilities defaults.
    }

    [[nodiscard]] auto compose_signed_event(HomeserverRuntime& runtime, std::string_view room_id,
                                            std::string_view sender, std::string_view client_event_json)
        -> std::optional<ComposedEvent>
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
            return std::nullopt;
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
        // Derive the room version so the correct signing policy (event-id format, auth
        // rules, MSC4291/MSC4289 behaviour) is used for every event in the room. The
        // m.room.create event carries its own room_version in content — and while it is
        // being composed the store holds no create row yet — so read it from the event
        // itself; every other event reads the version from the room's persisted create.
        auto room_version = std::string{};
        if (event_type == "m.room.create")
        {
            auto const* content_value = object_member(*input, "content");
            auto const* content_obj =
                content_value == nullptr ? nullptr : std::get_if<canonicaljson::Object>(&content_value->storage());
            auto const* rv = content_obj == nullptr ? nullptr : string_member(*content_obj, "room_version");
            room_version = rv != nullptr && !rv->empty() ? *rv : std::string{"12"};
        }
        else
        {
            room_version = room_version_for_room(runtime.database.persistent_store, room_id);
        }
        auto const* policy = rooms::find_room_version_policy(room_version);
        if (policy == nullptr)
        {
            return std::nullopt;
        }
        // MSC4291 (room v12): the create event omits room_id (the room ID is its reference
        // hash) and no event lists the create event in its auth_events.
        auto const create_defines_room_id = policy->create_event_is_room_id;
        auto const omit_room_id = event_type == "m.room.create" && create_defines_room_id;
        auto const prev_events = previous_events_for_room(runtime.database.persistent_store, room_id);
        auto const auth_events = auth_events_for_room(runtime.database.persistent_store, room_id, event_type,
                                                      event_state_key.value_or(""), sender, create_defines_room_id);
        auto const depth = next_depth_for_room(runtime.database.persistent_store, room_id);
        auto const now_ms = static_cast<std::int64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
                .count());
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
        event.push_back(canonicaljson::make_member("content", copy_member_or_empty_object(*input, "content")));
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
            return std::nullopt;
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
            return std::nullopt;
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
            return std::nullopt;
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
            return std::nullopt;
        }
        auto signed_event_value = canonicaljson::parse_lossless(signed_event.event_json);
        if (signed_event_value.error == canonicaljson::ParseError::none)
        {
            auto const* auth_policy = rooms::find_room_version_policy(room_version);
            if (auth_policy != nullptr)
            {
                auto auth_map = build_auth_event_map(runtime.database.persistent_store, room_id, sender,
                                                     state_key.value_or(""), event_type);
                auto const has_create_event = !std::holds_alternative<std::nullptr_t>(auth_map.create.storage());
                if (has_create_event)
                {
                    auto const auth_decision =
                        events::authorize_event_against_auth_events(signed_event_value.value, *auth_policy, auth_map);
                    if (!auth_decision.allowed)
                    {
                        log_diagnostic("event.auth.rejected", {
                                                                  {"room_id",    std::string{room_id},    false},
                                                                  {"sender",     std::string{sender},     false},
                                                                  {"event_type", event_type,              false},
                                                                  {"rule_hook",  auth_decision.rule_hook, false},
                                                                  {"rule_step",  auth_decision.rule_step, false},
                                                                  {"reason",     auth_decision.reason,    false}
                        });
                        return std::nullopt;
                    }
                }
            }
        }

        return ComposedEvent{
            event_id.event_id,
            signed_event.event_json,
            depth,
            0U,
            prev_events,
            auth_events,
            {{signed_event.server_name, signed_event.key_id, signed_event.signature}},
            event_type,
            state_key,
        };
    }

    // Composes, signs, and persists a single room state event.  Used by create_room to
    // emit the initial chain (create → member → power_levels → join_rules) so the room's
    // current_state is populated before any federation peer calls send_join.
    // Each event must be stored before the next is generated: auth_events_for_room and
    // previous_events_for_room both read the persistent state to build the correct chain.
    // Persists an already-composed event (and its state row, if any) under room_id.
    // Split out from emit_initial_state_event so create_room can compose the room v12
    // m.room.create event first — deriving the room ID from its reference hash
    // (MSC4291) — and persist it once that room ID is known.
    [[nodiscard]] auto persist_composed_event(HomeserverRuntime& runtime, std::string_view room_id,
                                              std::string_view sender, ComposedEvent const& composed) -> bool
    {
        auto const stream_ordering = runtime.database.next_stream_ordering++;
        auto state = std::optional<database::PersistentStateEvent>{};
        if (composed.state_key.has_value())
        {
            state = database::PersistentStateEvent{std::string{room_id}, composed.event_type, *composed.state_key,
                                                   composed.event_id};
        }
        return database::store_event_with_state(runtime.database.persistent_store,
                                                {composed.event_id, std::string{room_id}, std::string{sender},
                                                 composed.json, composed.depth, stream_ordering,
                                                 composed.prev_event_ids, composed.auth_event_ids, composed.signatures},
                                                std::move(state));
    }

    [[nodiscard]] auto emit_initial_state_event(HomeserverRuntime& runtime, std::string_view room_id,
                                                std::string_view sender, std::string const& event_json) -> bool
    {
        auto const composed = compose_signed_event(runtime, room_id, sender, event_json);
        if (!composed.has_value())
        {
            // compose_signed_event already emitted a diagnostic.
            return false;
        }
        return persist_composed_event(runtime, room_id, sender, *composed);
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
        auto const& account_data = runtime.database.persistent_store.account_data;
        auto const existing =
            std::ranges::find_if(account_data, [user_id](database::PersistentAccountData const& entry) {
                return entry.user_id == user_id && entry.room_id.empty() && entry.event_type == "m.direct";
            });
        if (existing != account_data.end())
        {
            auto const parsed = canonicaljson::parse_lossless(existing->content_json);
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

} // namespace

// Perform a single synchronous outbound federation call. Returns the raw
// response body on success (HTTP 2xx), or an error description on failure.
// The request is signed in-process; if a federation proxy is wired the actual
// HTTP call runs in the worker's thread pool, freeing this handler thread.
[[nodiscard]] auto perform_sync_outbound_call(HomeserverRuntime& runtime, std::string_view room_id,
                                              federation::OutboundTransaction const& transaction,
                                              std::string_view key_id, std::span<std::uint8_t const> secret_key,
                                              std::string_view diagnostic_event, std::uint32_t timeout_seconds)
    -> std::pair<bool, std::string>
{
    auto* discovery_network = runtime.discovery_network.get();
    if (discovery_network == nullptr)
    {
        log_diagnostic(diagnostic_event, {
                                             {"reason", "federation infrastructure not available", false}
        });
        return {false, "federation not available"};
    }
    auto const resolution = federation::discover_server(transaction.destination, *discovery_network, timeout_seconds);
    if (!resolution.discovery_allowed)
    {
        log_diagnostic(diagnostic_event, {
                                             {"destination", transaction.destination,   false},
                                             {"reason",      "server discovery failed", false}
        });
        return {false, "server discovery failed"};
    }
    if (secret_key.size() != crypto_sign_SECRETKEYBYTES)
    {
        log_diagnostic(diagnostic_event, {
                                             {"reason", "server signing key not initialized", false}
        });
        return {false, "server signing key not initialized"};
    }
    auto call = federation::OutboundCall{};
    call.transaction = transaction;
    call.resolved_host = resolution.resolved_host;
    call.resolved_port = resolution.resolved_port;
    call.pinned_addresses = resolution.pinned_addresses;
    call.key_id = std::string{key_id};
    // Borrow the caller's span (backed by the runtime's SecretBuffer) for the
    // synchronous build+send below. No std::string materialisation of the key.
    call.secret_key = secret_key;
    call.connect_timeout_seconds = std::min(timeout_seconds, 30U);
    call.total_timeout_seconds = timeout_seconds;

    // Sign the request in-process — the Ed25519 secret never crosses the IPC boundary.
    auto const request = federation::build_outbound_request(call);

    // Route via worker if available; fall back to direct outbound client.
    auto outcome = http::OutboundResult{};
    if (runtime.federation_proxy)
    {
        outcome = runtime.federation_proxy->send_outbound_request(request, room_id);
    }
    else if (runtime.outbound_client)
    {
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
        return {false, outcome.error_detail.empty()
                           ? "remote server returned " + std::to_string(outcome.response.status)
                           : outcome.error_detail};
    }
    return {true, outcome.response.body};
}

namespace
{
    // Derives an "ed25519:<hex>" key_id from the first four bytes of a public key.
    // Tying the id to the key material gives every generated key a unique id, so a
    // stale federation notary cache for a previous id becomes irrelevant after a
    // rotation. Shared by key generation and key rotation.
    [[nodiscard]] auto derive_ed25519_key_id(std::array<unsigned char, crypto_sign_PUBLICKEYBYTES> const& public_key)
        -> std::string
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
} // namespace

[[nodiscard]] auto ensure_runtime_server_signing_key(HomeserverRuntime& runtime)
    -> std::optional<database::PersistentServerSigningKey>
{
    auto const& server_name = runtime.config.server().server_name;
    auto const& all_keys = runtime.database.persistent_store.server_signing_keys;

    // Find any signing key for this server that uses a derived key_id (not the legacy
    // "ed25519:auto" sentinel). The sentinel was used before key-ids were derived from
    // the public key bytes; federation notary servers (e.g. matrix.org) that cached it
    // with a far-future valid_until_ts will never re-fetch it, causing BadSignatureError
    // on every outbound request. Ignoring "ed25519:auto" forces generation of a new
    // key whose key_id is unknown to any stale notary cache.
    // Select the usable key with the greatest valid_until_ts. After a rotation the
    // store holds both the retired key (valid_until_ts == "now") and the freshly
    // activated key (valid_until_ts == now + 7 days); choosing the furthest expiry
    // guarantees the new key is loaded as active and the retired one is left for
    // publication under old_verify_keys.
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
        // Decrypt (or decode legacy plaintext) the stored secret and validate its
        // size before trusting it.  Fail closed if the secret cannot hydrate into a
        // full Ed25519 secret key — attempting to sign with wrong-length material
        // produces corrupt signatures.
        auto const raw_secret = decrypt_stored_signing_secret(runtime, it->secret_key);
        if (!raw_secret.has_value() || raw_secret->size() != crypto_sign_SECRETKEYBYTES)
        {
            log_diagnostic(
                "signing_key.rejected",
                {
                    {"server_name", std::string{server_name},                                                false},
                    {"key_id",      it->key_id,                                                              false},
                    {"reason",      "secret_size_invalid",                                                   false},
                    {"secret_size", std::to_string(raw_secret.value_or(std::vector<std::uint8_t>{}).size()), false},
                    {"expected",    std::to_string(crypto_sign_SECRETKEYBYTES),                              false}
            });
            return std::nullopt;
        }
        runtime.database.signing_secret_key = core::SecretBuffer{raw_secret->size()};
        std::copy(raw_secret->begin(), raw_secret->end(), runtime.database.signing_secret_key.bytes().begin());
        log_diagnostic("signing_key.loaded",
                       {
                           {"server_name", std::string{server_name},           false},
                           {"key_id",      it->key_id,                         false},
                           {"public_key",  it->public_key,                     false},
                           {"secret_size", std::to_string(raw_secret->size()), false}
        },
                       observability::LogEventSeverity::info);
        return *it;
    }

    // No usable derived-format key found. Log whether a legacy entry exists (for ops
    // visibility) then generate a fresh Ed25519 keypair with a derived key_id.
    auto const has_legacy =
        std::ranges::any_of(all_keys, [&server_name](database::PersistentServerSigningKey const& k) {
            return k.server_name == server_name && k.key_id == "ed25519:auto";
        });
    log_diagnostic("signing_key.generating", {
                                                 {"server_name",    std::string{server_name},      false},
                                                 {"has_legacy_key", has_legacy ? "true" : "false", false}
    });

    auto public_key = std::array<unsigned char, crypto_sign_PUBLICKEYBYTES>{};
    auto secret_key = std::array<unsigned char, crypto_sign_SECRETKEYBYTES>{};
    if (!generate_random_signing_keypair(public_key, secret_key))
    {
        return std::nullopt;
    }

    // Derive the key_id from the public key material so each new key gets a unique
    // id; stale notary-cache entries for old ids become irrelevant after rotation.
    auto const key_id = derive_ed25519_key_id(public_key);

    // Publish now + 7 days as valid_until_ts so federation peers periodically
    // re-fetch the key rather than caching it indefinitely.
    auto constexpr seven_days_ms = std::uint64_t{7U * 24U * 60U * 60U * 1000U};
    auto const now_ms = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
            .count());

    // Encrypt the secret at rest when a master key is configured.  For backwards
    // compatibility a server without a configured master key falls back to the
    // legacy plaintext base64 format, but a diagnostic is emitted so operators know
    // the secret is not protected at rest.
    auto secret_span = std::span<std::uint8_t const>{secret_key.data(), secret_key.size()};
    auto stored_secret = encrypt_signing_secret(runtime, secret_span);
    auto encrypted = std::string{"true"};
    if (!stored_secret.has_value())
    {
        if (runtime.config.security().secrets.master_key_file.empty())
        {
            log_diagnostic(
                "signing_key.plaintext_fallback",
                {
                    {"server_name", std::string{server_name},                                                               false},
                    {"reason",      "security.secrets.master_key_file not configured; storing signing secret in plaintext",
                     false                                                                                                       }
            });
            stored_secret = events::matrix_base64_from_bytes(
                std::string_view{reinterpret_cast<char const*>(secret_key.data()), secret_key.size()});
            encrypted = "false";
        }
        else
        {
            log_diagnostic("signing_key.generation_failed", {
                                                                {"server_name", std::string{server_name},           false},
                                                                {"reason",      "signing secret encryption failed", false}
            });
            return std::nullopt;
        }
    }

    auto key = database::PersistentServerSigningKey{
        std::string{server_name},
        key_id,
        events::matrix_base64_from_bytes(
            std::string_view{reinterpret_cast<char const*>(public_key.data()), public_key.size()}),
        now_ms + seven_days_ms,
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
    runtime.database.signing_secret_key = core::SecretBuffer{secret_key.size()};
    std::copy(secret_key.begin(), secret_key.end(), runtime.database.signing_secret_key.bytes().begin());
    return key;
}

[[nodiscard]] auto find_active_server_signing_key(HomeserverRuntime const& runtime)
    -> std::optional<database::PersistentServerSigningKey>
{
    auto const& server_name = runtime.config.server().server_name;
    auto const& all_keys = runtime.database.persistent_store.server_signing_keys;

    // Select the usable non-legacy key with the greatest valid_until_ts, mirroring
    // the choice made by ensure_runtime_server_signing_key but without touching the
    // encrypted secret. This lets federation handlers that delegate signing to an
    // external provider obtain the key_id and public_key they need.
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
    auto key = ensure_runtime_server_signing_key(runtime);
    if (!key.has_value())
    {
        return make_operation_result(false, {}, "server signing key unavailable", 500U);
    }
    if (runtime.crypto_provider == nullptr)
    {
        return make_operation_result(false, {}, "server signing provider unavailable", 500U);
    }

    // Publish a rolling valid_until_ts of now + 7 days. A far-future sentinel (year 2999) is
    // problematic because federation peers cache the key permanently and will never re-fetch if
    // the key changes — for example after a migration bug that rotated the key on every restart.
    // Seven days gives peers a window to notice the new key without hammering our endpoint.
    auto constexpr seven_days_ms = std::uint64_t{7U * 24U * 60U * 60U * 1000U};
    auto const now_ms = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
            .count());
    auto const rolling_valid_until_ts = now_ms + seven_days_ms;

    auto verify_key = canonicaljson::Object{};
    verify_key.push_back(canonicaljson::make_member("key", canonicaljson::Value{key->public_key}));
    auto verify_keys = canonicaljson::Object{};
    verify_keys.push_back(canonicaljson::make_member(key->key_id, canonicaljson::Value{std::move(verify_key)}));

    // Build old_verify_keys from every stored signing key for this server that is not
    // the currently active key. Per the Matrix spec each entry is:
    //   "<key_id>": { "expired_ts": <ms>, "key": "<base64 public key>" }
    // expired_ts is capped at now_ms so that superseded keys with a far-future
    // valid_until_ts (e.g. the legacy year-2999 sentinel) are never published with
    // a future expiry, which would cause peers to treat them as still valid.
    auto old_verify_keys_obj = canonicaljson::Object{};
    for (auto const& old_key : runtime.database.persistent_store.server_signing_keys)
    {
        if (old_key.server_name != key->server_name || old_key.key_id == key->key_id || old_key.public_key.empty())
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
    response.push_back(canonicaljson::make_member("server_name", canonicaljson::Value{key->server_name}));
    response.push_back(canonicaljson::make_member(
        "valid_until_ts", canonicaljson::Value{static_cast<std::int64_t>(rolling_valid_until_ts)}));
    response.push_back(canonicaljson::make_member("verify_keys", canonicaljson::Value{std::move(verify_keys)}));

    auto payload = canonicaljson::serialize_canonical(canonicaljson::Value{response});
    if (payload.error != canonicaljson::CanonicalJsonError::none)
    {
        return make_operation_result(false, {}, canonicaljson::canonical_json_error_name(payload.error), 500U);
    }

    auto const sign_result = runtime.crypto_provider->sign(crypto::Ed25519SecretKeyHandle{key->key_id}, payload.output);
    if (!sign_result.error.empty())
    {
        return make_operation_result(false, {}, "server key response signing failed: " + sign_result.error, 500U);
    }

    auto server_signatures = canonicaljson::Object{};
    server_signatures.push_back(canonicaljson::make_member(
        key->key_id, canonicaljson::Value{events::matrix_base64_from_bytes(sign_result.signature.bytes)}));
    auto signatures = canonicaljson::Object{};
    signatures.push_back(
        canonicaljson::make_member(key->server_name, canonicaljson::Value{std::move(server_signatures)}));
    response.push_back(canonicaljson::make_member("signatures", canonicaljson::Value{std::move(signatures)}));

    auto signed_response = canonicaljson::serialize_canonical(canonicaljson::Value{std::move(response)});
    if (signed_response.error != canonicaljson::CanonicalJsonError::none)
    {
        return make_operation_result(false, {}, canonicaljson::canonical_json_error_name(signed_response.error), 500U);
    }

    // Atomically update the lock-free cache so dispatch_local_http_request can
    // serve subsequent key server requests without acquiring the runtime mutex.
    if (runtime.database.key_server_cache)
    {
        runtime.database.key_server_cache->store(signed_response.output);
    }

    return make_operation_result(true, std::move(signed_response.output));
}

[[nodiscard]] auto rotate_server_signing_key(HomeserverRuntime& runtime) -> OperationResult
{
    auto guard = std::unique_lock<std::recursive_mutex>{runtime.mutex};

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
    auto public_key = std::array<unsigned char, crypto_sign_PUBLICKEYBYTES>{};
    auto secret_key = std::array<unsigned char, crypto_sign_SECRETKEYBYTES>{};
    if (!generate_random_signing_keypair(public_key, secret_key))
    {
        return make_operation_result(false, {}, "signing key generation failed", 500U);
    }
    auto const key_id = derive_ed25519_key_id(public_key);
    auto constexpr seven_days_ms = std::uint64_t{7U * 24U * 60U * 60U * 1000U};

    auto stored_secret =
        encrypt_signing_secret(runtime, std::span<std::uint8_t const>{secret_key.data(), secret_key.size()});
    auto encrypted = std::string{"true"};
    if (!stored_secret.has_value())
    {
        if (runtime.config.security().secrets.master_key_file.empty())
        {
            stored_secret = events::matrix_base64_from_bytes(
                std::string_view{reinterpret_cast<char const*>(secret_key.data()), secret_key.size()});
            encrypted = "false";
        }
        else
        {
            return make_operation_result(false, {}, "failed to encrypt rotated signing secret", 500U);
        }
    }

    auto new_key = database::PersistentServerSigningKey{
        current->server_name,
        key_id,
        events::matrix_base64_from_bytes(
            std::string_view{reinterpret_cast<char const*>(public_key.data()), public_key.size()}),
        now_ms + seven_days_ms,
        *stored_secret,
    };
    if (!database::store_server_signing_key(runtime.database.persistent_store, new_key))
    {
        return make_operation_result(false, {}, "failed to store rotated signing key", 500U);
    }
    runtime.database.signing_secret_key = core::SecretBuffer{secret_key.size()};
    std::copy(secret_key.begin(), secret_key.end(), runtime.database.signing_secret_key.bytes().begin());
    reset_runtime_crypto_provider(runtime);
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
    auto guard = std::unique_lock<std::recursive_mutex>{runtime.mutex};
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

    // Build the m.room.create content first. In room version 12 the room ID is the
    // reference hash of the create event (MSC4291), so the create event must be
    // composed before a room ID exists; earlier versions use a server-scoped ID.
    auto create_content = options.creation_content;
    upsert_object_member(create_content, canonicaljson::make_member("creator", canonicaljson::Value{*user_id}));
    upsert_object_member(create_content,
                         canonicaljson::make_member("room_version", canonicaljson::Value{options.room_version}));

    auto const* version_policy = rooms::find_room_version_policy(options.room_version);
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
    auto precomposed_create = std::optional<ComposedEvent>{};
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
            return make_operation_result(false, {}, "initial room state event generation failed", 500U);
        }
        precomposed_create = compose_signed_event(runtime, std::string_view{}, *user_id, *create_event_json);
        if (!precomposed_create.has_value())
        {
            return make_operation_result(false, {}, "initial room state event generation failed", 500U);
        }
        room_id = "!" + precomposed_create->event_id.substr(1U);
    }
    else
    {
        room_id =
            "!room" + std::to_string(runtime.database.rooms.size() + 1U) + ":" + runtime.config.server().server_name;
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

    if (!database::store_room_with_membership(runtime.database.persistent_store, {room_id, *user_id},
                                              {room_id, *user_id}))
    {
        log_diagnostic("room.create.rejected", {
                                                   {"actor",   *user_id,                  false},
                                                   {"room_id", room_id,                   false},
                                                   {"status",  "500",                     false},
                                                   {"reason",  "room persistence failed", false}
        });
        return make_operation_result(false, {}, "room persistence failed", 500U);
    }
    runtime.database.rooms.push_back({room_id, *user_id, {*user_id}, {}});

    auto emit_state = [&](std::string_view event_type, canonicaljson::Object content,
                          std::string_view state_key = std::string_view{}) -> bool {
        auto event = canonicaljson::Object{};
        event.push_back(canonicaljson::make_member("type", canonicaljson::Value{std::string{event_type}}));
        event.push_back(canonicaljson::make_member("state_key", canonicaljson::Value{std::string{state_key}}));
        event.push_back(canonicaljson::make_member("content", canonicaljson::Value{std::move(content)}));
        auto const serialized = serialize_canonical_string(canonicaljson::Value{std::move(event)});
        return serialized.has_value() && emit_initial_state_event(runtime, room_id, *user_id, *serialized);
    };

    auto power_levels = canonicaljson::Object{};
    power_levels.push_back(canonicaljson::make_member("ban", canonicaljson::Value{std::int64_t{50}}));
    power_levels.push_back(canonicaljson::make_member("events", canonicaljson::Value{canonicaljson::Object{}}));
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
    merge_object_into(power_levels, options.power_level_content_override);
    if (creator_has_implicit_power_level)
    {
        // A client may still send creators in power_level_content_override; strip them so the
        // emitted event is always valid for v12 regardless of the override's contents.
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
    if (options.preset == "trusted_private_chat" && room_version_number(options.room_version) >= 12)
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

    // In room v12 the create event was composed up-front to derive the room ID, so
    // persist that exact event; earlier versions compose and persist it here.
    auto const create_persisted = create_defines_room_id
                                      ? persist_composed_event(runtime, room_id, *user_id, *precomposed_create)
                                      : emit_state("m.room.create", std::move(create_content));
    if (!create_persisted || !emit_state("m.room.member", std::move(creator_member), *user_id) ||
        !emit_state("m.room.power_levels", std::move(power_levels)))
    {
        log_diagnostic("room.create.rejected", {
                                                   {"actor",   *user_id,                                     false},
                                                   {"room_id", room_id,                                      false},
                                                   {"status",  "500",                                        false},
                                                   {"reason",  "initial room state event generation failed", false}
        });
        return make_operation_result(false, {}, "initial room state event generation failed", 500U);
    }

    if (!alias.empty())
    {
        auto canonical_alias = canonicaljson::Object{};
        canonical_alias.push_back(canonicaljson::make_member("alias", canonicaljson::Value{alias}));
        if (!emit_state("m.room.canonical_alias", std::move(canonical_alias)) ||
            !database::store_room_alias(runtime.database.persistent_store, {alias, room_id}))
        {
            log_diagnostic("room.create.rejected", {
                                                       {"actor",      *user_id,                        false},
                                                       {"room_id",    room_id,                         false},
                                                       {"room_alias", alias,                           false},
                                                       {"status",     "500",                           false},
                                                       {"reason",     "room alias persistence failed", false}
            });
            return make_operation_result(false, {}, "room alias persistence failed", 500U);
        }
    }

    // Scan initial_state once for all client-provided event types that overlap
    // with preset-derived state, so presets are not emitted as duplicates.
    auto client_provided_join_rules = false;
    auto client_provided_history_visibility = false;
    auto client_provided_guest_access = false;
    auto client_provided_encryption = false;
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
        else if (*type_str == "m.room.encryption")
        {
            client_provided_encryption = true;
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
        return make_operation_result(false, {}, "preset room state event generation failed", 500U);
    }
    if (!client_provided_history_visibility && !emit_state("m.room.history_visibility", std::move(history_visibility)))
    {
        log_diagnostic("room.create.rejected", {
                                                   {"actor",   *user_id,                                    false},
                                                   {"room_id", room_id,                                     false},
                                                   {"status",  "500",                                       false},
                                                   {"reason",  "preset room state event generation failed", false}
        });
        return make_operation_result(false, {}, "preset room state event generation failed", 500U);
    }
    if (!client_provided_guest_access && !emit_state("m.room.guest_access", std::move(guest_access)))
    {
        log_diagnostic("room.create.rejected", {
                                                   {"actor",   *user_id,                                    false},
                                                   {"room_id", room_id,                                     false},
                                                   {"status",  "500",                                       false},
                                                   {"reason",  "preset room state event generation failed", false}
        });
        return make_operation_result(false, {}, "preset room state event generation failed", 500U);
    }

    // Emit m.room.encryption for private room presets. Per the Matrix spec,
    // private_chat and trusted_private_chat rooms SHOULD enable encryption by
    // default. Skip if the client already included m.room.encryption in
    // initial_state to avoid emitting a duplicate state event.
    auto const encryption_preset = options.preset == "private_chat" || options.preset == "trusted_private_chat";
    if (encryption_preset && !client_provided_encryption)
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
            return make_operation_result(false, {}, "encryption room state event generation failed", 500U);
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
            return make_operation_result(false, {}, "initial room state event generation failed", 500U);
        }
    }

    if (!options.name.empty())
    {
        auto name_content = canonicaljson::Object{};
        name_content.push_back(canonicaljson::make_member("name", canonicaljson::Value{options.name}));
        if (!emit_state("m.room.name", std::move(name_content)))
        {
            return make_operation_result(false, {}, "initial room state event generation failed", 500U);
        }
    }
    if (!options.topic.empty())
    {
        auto topic_content = canonicaljson::Object{};
        topic_content.push_back(canonicaljson::make_member("topic", canonicaljson::Value{options.topic}));
        if (!emit_state("m.room.topic", std::move(topic_content)))
        {
            return make_operation_result(false, {}, "initial room state event generation failed", 500U);
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
        if (!emit_state("m.room.member", std::move(invite_content), invitee))
        {
            return make_operation_result(false, {}, "initial room state event generation failed", 500U);
        }
        auto const membership_stream = runtime.database.next_stream_ordering++;
        auto const membership_result = database::store_membership(runtime.database.persistent_store,
                                                                  {room_id, invitee, "invite", membership_stream});
        if (membership_result == database::MembershipStoreResult::error ||
            (membership_result == database::MembershipStoreResult::already_exists &&
             !database::update_membership(runtime.database.persistent_store, room_id, invitee, "invite")))
        {
            return make_operation_result(false, {}, "invite membership persistence failed", 500U);
        }
        auto const invite_state = std::ranges::find_if(
            runtime.database.persistent_store.state, [&](database::PersistentStateEvent const& state) {
                return state.room_id == room_id && state.event_type == "m.room.member" && state.state_key == invitee;
            });
        if (invite_state == runtime.database.persistent_store.state.end())
        {
            return make_operation_result(false, {}, "invite state event missing", 500U);
        }
        auto const invite_json = event_json_for_id(runtime.database.persistent_store, invite_state->event_id);
        if (!invite_json.has_value() ||
            !database::upsert_invite(runtime.database.persistent_store,
                                     {room_id, invitee, *user_id, invite_state->event_id, *invite_json,
                                      invite_state_events_for_room(runtime.database.persistent_store, room_id, invitee),
                                      membership_stream}))
        {
            return make_operation_result(false, {}, "invite metadata persistence failed", 500U);
        }
        apply_runtime_membership(runtime.database, room_id, invitee, "invite");
        invited_anyone = true;
    }

    if (options.is_direct && !options.invitees.empty())
    {
        if (!upsert_m_direct(runtime, *user_id, room_id, options.invitees))
        {
            return make_operation_result(false, {}, "m.direct account data update failed", 500U);
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
        runtime.sync_notifier->publish(runtime.database.next_stream_ordering - 1U, sync_stream_id);
    }
    return make_operation_result(true, room_id);
}

auto parse_join_via_servers(std::string_view query) -> std::vector<std::string>
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
        auto decoded = core::percent_decode_path_component(pair.substr(eq + 1U));
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
    // Room versions < 12 embed the resident server in the room ID; room version 12
    // IDs are bare reference hashes (MSC4291), so server_name_from_room_id returns
    // empty and the via servers are the only route.
    add(server_name_from_room_id(room_id));
    return candidates;
}

// Persists the `state` array from a send_join response. Each event is stored to
// the persistent event graph. Events that carry a "state_key" field in their raw
// JSON (even when that value is "") are also written to the state table. That is
// the correct discriminant per the Matrix spec: any event with a "state_key"
// field is a state event, regardless of whether the value is empty.
//
// Returns the user IDs with membership="join" found within the ingested events.
//
// IMPORTANT: this function is also called directly from unit tests to verify
// that state events with empty state_key (m.room.encryption, m.room.create, etc.)
// are correctly persisted. Do NOT change the state-key check without updating the
// corresponding test in tests/unit/test_federation_invite_join.cpp.
[[nodiscard]] auto ingest_send_join_state(HomeserverRuntime& runtime, canonicaljson::Array const& state_arr,
                                          rooms::RoomVersionPolicy const& policy) -> std::vector<std::string>
{
    auto joined_members = std::vector<std::string>{};
    for (auto const& state_entry : state_arr)
    {
        auto const serialized = canonicaljson::serialize_canonical(state_entry);
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
                auto const stream_ordering = runtime.database.next_stream_ordering++;
                // A state event is identified by the PRESENCE of the "state_key" field
                // in the raw JSON, even when its value is "". EventEnvelope::state_key
                // defaults to "" both for state events with state_key="" AND for
                // non-state events (where the field is absent), so .empty() cannot
                // distinguish the two. Check the raw JSON field instead.
                // v12 (MSC4291): m.room.create carries no room_id field — the room ID
                // IS the create event's reference hash. Derive it from event_id so the
                // PersistentStateEvent is stored with the correct room_id and can be
                // found later by build_pdu_auth_event_map.
                auto const effective_room_id = [&]() -> std::string {
                    if (!parsed.event.room_id.empty())
                    {
                        return parsed.event.room_id;
                    }
                    if (policy.create_event_is_room_id && !event_id.empty())
                    {
                        return "!" + event_id.substr(1);
                    }
                    return {};
                }();
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
                std::ignore = database::store_event_with_state(runtime.database.persistent_store, std::move(pe), state);
                // Track joined members for the in-memory LocalRoom population step.
                // state_key is non-empty for membership events (it holds the user ID).
                if (parsed.event.event_type == "m.room.member" && !parsed.event.state_key.empty() &&
                    events::extract_content_membership(state_entry) == "join")
                {
                    append_unique_member(joined_members, parsed.event.state_key);
                }
            }
        }
    }
    return joined_members;
}

[[nodiscard]] auto join_room(HomeserverRuntime& runtime, std::string_view access_token, std::string_view room_id,
                             std::vector<std::string> const& via_servers) -> OperationResult
{
    auto guard = std::unique_lock<std::recursive_mutex>{runtime.mutex};
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
    if (room == nullptr)
    {
        // Remote room: attempt make_join → sign → send_join. The candidate resident
        // servers come from the join endpoint's via/server_name parameters, plus the
        // room ID's domain for room versions < 12 (v12 IDs are domain-less, MSC4291).
        auto const our_server = runtime.config.server().server_name;
        auto const candidates = join_candidate_servers(via_servers, room_id, our_server);
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
        wire_federation_callbacks(runtime);
        auto const supported_versions = std::vector<std::string>{"10", "11", "12"};
        // Best-effort: load the key_id from the persistent store. If no usable key
        // record exists, perform_sync_outbound_call fails with "server signing key not
        // initialized", which join_room surfaces as 502 — the correct status for an
        // upstream federation failure. The signing secret stays in the runtime's
        // mlocked SecretBuffer; we borrow a span of it for the X-Matrix header,
        // never copying the key into an unpinned std::string.
        auto const signing_key = find_active_server_signing_key(runtime);
        auto const key_id = signing_key.has_value() ? signing_key->key_id : std::string{};
        auto const secret_key = runtime.database.signing_secret_key.bytes();
        guard.unlock();
        // Try each candidate resident server's make_join until one responds successfully.
        auto remote_server = std::string{};
        auto make_body = std::string{};
        auto make_ok = false;
        for (auto const& candidate : candidates)
        {
            auto make_join_tx =
                federation::make_outbound_make_membership(federation::FederationEndpoint::make_join, candidate,
                                                          our_server, room_id, *user_id, supported_versions);
            log_diagnostic("room.join.remote.make_join", {
                                                             {"actor",         *user_id,             false},
                                                             {"room_id",       std::string{room_id}, false},
                                                             {"remote_server", candidate,            false}
            });
            auto [ok, body] = perform_sync_outbound_call(runtime, room_id, make_join_tx, key_id, secret_key,
                                                         "room.join.remote.make_join_failed",
                                                         runtime.federation.config.remote_timeout_seconds);
            // Keep the latest body: on success it is the make_join response; on failure it
            // is the reason, surfaced below if every candidate server fails.
            make_body = std::move(body);
            if (ok)
            {
                remote_server = candidate;
                make_ok = true;
                break;
            }
        }
        if (!make_ok)
        {
            log_diagnostic("room.join.rejected", {
                                                     {"actor",   *user_id,                              false},
                                                     {"room_id", std::string{room_id},                  false},
                                                     {"status",  "502",                                 false},
                                                     {"reason",  "make_join failed via all candidates", false}
            });
            return make_operation_result(false, {}, "make_join failed: " + make_body, 502U);
        }
        // Parse the make_join response and validate the template before we sign it.
        auto const make_response = canonicaljson::parse_lossless(make_body);
        auto const* make_obj = std::get_if<canonicaljson::Object>(&make_response.value.storage());
        if (make_obj == nullptr)
        {
            log_diagnostic("room.join.rejected", {
                                                     {"actor",   *user_id,                   false},
                                                     {"room_id", std::string{room_id},       false},
                                                     {"status",  "502",                      false},
                                                     {"reason",  "malformed make_join body", false}
            });
            return make_operation_result(false, {}, "malformed make_join response", 502U);
        }
        auto const validated = validate_make_join_event(room_id, *user_id, *make_obj);
        if (!validated.ok)
        {
            log_diagnostic("room.join.rejected", {
                                                     {"actor",   *user_id,             false},
                                                     {"room_id", std::string{room_id}, false},
                                                     {"status",  "502",                false},
                                                     {"reason",  validated.reason,     false}
            });
            return make_operation_result(false, {}, validated.reason, 502U);
        }
        auto const room_version = validated.room_version;
        auto event_object = validated.event;
        // Compute and attach the content hash (hashes.sha256) before signing.
        // The Matrix spec requires every PDU to carry this field (room versions >= 2).
        // Without it, Synapse rejects send_join with:
        //   SynapseError: 400 - Malformed 'hashes': <class 'NoneType'>
        auto const content_hash = events::make_content_hash(canonicaljson::Value{event_object});
        if (!content_hash.error.empty())
        {
            log_diagnostic("room.join.rejected", {
                                                     {"actor",   *user_id,             false},
                                                     {"room_id", std::string{room_id}, false},
                                                     {"status",  "500",                false},
                                                     {"reason",  content_hash.error,   false}
            });
            return make_operation_result(false, {}, "join event content hash failed", 500U);
        }
        auto hashes_obj = canonicaljson::Object{};
        hashes_obj.push_back(canonicaljson::make_member("sha256", canonicaljson::Value{content_hash.sha256}));
        event_object.push_back(canonicaljson::make_member("hashes", canonicaljson::Value{std::move(hashes_obj)}));

        auto event_to_sign = canonicaljson::Value{event_object};
        // Sign the event with our server's signing key.
        // signing_key is guaranteed non-empty here: perform_sync_outbound_call
        // validates secret_key size before executing make_join, so a failed key
        // means make_ok was false and we returned 502 above.
        if (runtime.crypto_provider == nullptr)
        {
            log_diagnostic("room.join.rejected", {
                                                     {"actor",   *user_id,                                false},
                                                     {"room_id", std::string{room_id},                    false},
                                                     {"status",  "500",                                   false},
                                                     {"reason",  "server signing provider not available", false}
            });
            return make_operation_result(false, {}, "server signing provider not available", 500U);
        }
        auto key_store = RuntimeSigningKeyStore{our_server, signing_key.value()};
        auto const* policy = rooms::find_room_version_policy(room_version);
        if (policy == nullptr)
        {
            log_diagnostic("room.join.rejected", {
                                                     {"actor",   *user_id,                      false},
                                                     {"room_id", std::string{room_id},          false},
                                                     {"status",  "500",                         false},
                                                     {"reason",  "room version policy missing", false}
            });
            return make_operation_result(false, {}, "room version policy missing", 500U);
        }
        auto const signed_event =
            events::sign_event_for_server(event_to_sign, *policy, key_store, *runtime.crypto_provider, our_server);
        if (!signed_event.error.empty())
        {
            log_diagnostic("room.join.rejected", {
                                                     {"actor",   *user_id,             false},
                                                     {"room_id", std::string{room_id}, false},
                                                     {"status",  "500",                false},
                                                     {"reason",  signed_event.error,   false}
            });
            return make_operation_result(false, {}, "event signing failed", 500U);
        }
        // Compute the event_id from the signed event (room v10+ uses
        // reference hash-based event IDs).
        auto const signed_value = canonicaljson::parse_lossless(signed_event.event_json);
        auto const event_id_result = events::make_reference_hash_event_id(signed_value.value, *policy);
        if (event_id_result.error.empty() && event_id_result.event_id.empty())
        {
            log_diagnostic("room.join.rejected", {
                                                     {"actor",   *user_id,                      false},
                                                     {"room_id", std::string{room_id},          false},
                                                     {"status",  "500",                         false},
                                                     {"reason",  "event_id computation failed", false}
            });
            return make_operation_result(false, {}, "event_id computation failed", 500U);
        }
        // Send the signed join event via send_join.
        auto send_join_tx = federation::make_outbound_send_membership(
            federation::FederationEndpoint::send_join, remote_server, our_server, room_id, event_id_result.event_id,
            signed_event.event_json);
        log_diagnostic("room.join.remote.send_join", {
                                                         {"actor",         *user_id,                   false},
                                                         {"room_id",       std::string{room_id},       false},
                                                         {"remote_server", std::string{remote_server}, false},
                                                         {"event_id",      event_id_result.event_id,   false}
        });
        auto const [send_ok, send_body] = perform_sync_outbound_call(runtime, room_id, send_join_tx, key_id, secret_key,
                                                                     "room.join.remote.send_join_failed",
                                                                     runtime.federation.config.remote_timeout_seconds);
        if (!send_ok)
        {
            log_diagnostic("room.join.rejected",
                           {
                               {"actor",   *user_id,             false},
                               {"room_id", std::string{room_id}, false},
                               {"status",  "502",                false},
                               {"reason",  "send_join failed",   false}
            },
                           observability::LogEventSeverity::warning);
            return make_operation_result(false, {}, "send_join failed: " + send_body, 502U);
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
                                                     {"actor",   *user_id,                       false},
                                                     {"room_id", std::string{room_id},           false},
                                                     {"status",  "502",                          false},
                                                     {"reason",  "malformed send_join response", false}
            });
            return make_operation_result(false, {}, "malformed send_join response", 502U);
        }
        guard.lock();
        // Persist the room locally with the joined user as a member.
        // State events from the remote response are persisted to the
        // database so the room has enough state for auth checks.
        auto joined_members = std::vector<std::string>{*user_id};
        auto const state_arr_member = std::ranges::find_if(*send_obj, [](canonicaljson::ObjectMember const& m) {
            return m.key == "state";
        });
        if (state_arr_member != send_obj->end())
        {
            auto const* state_arr = std::get_if<canonicaljson::Array>(&state_arr_member->value->storage());
            if (state_arr != nullptr)
            {
                // Persist every state event in the send_join response. ingest_send_join_state
                // correctly handles events with empty state_key (m.room.encryption,
                // m.room.create, m.room.power_levels, etc.) by checking the raw JSON for
                // the presence of the "state_key" field rather than its emptiness.
                auto const state_members = ingest_send_join_state(runtime, *state_arr, *policy);
                for (auto const& m : state_members)
                {
                    append_unique_member(joined_members, m);
                }
            }
        }
        // Persist auth chain events for auth-rule resolution.
        auto const auth_arr_member = std::ranges::find_if(*send_obj, [](canonicaljson::ObjectMember const& m) {
            return m.key == "auth_chain";
        });
        if (auth_arr_member != send_obj->end())
        {
            auto const* auth_arr = std::get_if<canonicaljson::Array>(&auth_arr_member->value->storage());
            if (auth_arr != nullptr)
            {
                for (auto const& auth_entry : *auth_arr)
                {
                    auto const serialized = canonicaljson::serialize_canonical(auth_entry);
                    if (serialized.error == canonicaljson::CanonicalJsonError::none)
                    {
                        auto const parsed = events::parse_event_envelope(auth_entry);
                        if (parsed.error.empty())
                        {
                            auto const* entry_obj = std::get_if<canonicaljson::Object>(&auth_entry.storage());
                            auto event_id = std::string{};
                            if (entry_obj != nullptr)
                            {
                                if (policy->event_id_format == rooms::EventIdFormat::reference_hash)
                                {
                                    auto const eid = events::make_reference_hash_event_id(auth_entry, *policy);
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
                            auto const stream_ordering = runtime.database.next_stream_ordering++;
                            // Detect state events by JSON field presence, not .empty(): the
                            // state_key field exists even when "" (e.g. m.room.create).
                            // v12 (MSC4291): m.room.create has no room_id field; derive it.
                            auto const auth_effective_room_id = [&]() -> std::string {
                                if (!parsed.event.room_id.empty())
                                {
                                    return parsed.event.room_id;
                                }
                                if (policy != nullptr && policy->create_event_is_room_id && !event_id.empty())
                                {
                                    return "!" + event_id.substr(1);
                                }
                                return {};
                            }();
                            auto state = std::optional<database::PersistentStateEvent>{};
                            if (entry_obj != nullptr)
                            {
                                if (auto const* raw_sk = json_string_member(*entry_obj, "state_key"); raw_sk != nullptr)
                                {
                                    state = database::PersistentStateEvent{auth_effective_room_id,
                                                                           parsed.event.event_type, *raw_sk, event_id};
                                }
                            }
                            auto pe = database::PersistentEvent{};
                            pe.event_id = event_id;
                            pe.room_id = auth_effective_room_id;
                            pe.sender_user_id = parsed.event.sender;
                            pe.json = serialized.output;
                            pe.depth = depth;
                            pe.stream_ordering = stream_ordering;
                            pe.prev_event_ids = std::move(prev_ids);
                            pe.auth_event_ids = std::move(auth_ids);
                            pe.signatures = parsed.event.signatures;
                            std::ignore = database::store_event_with_state(runtime.database.persistent_store,
                                                                           std::move(pe), state);
                        }
                    }
                }
            }
        }
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
        auto const membership_stream = runtime.database.next_stream_ordering++;

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
            if (auto const* obj = std::get_if<canonicaljson::Object>(&signed_value.value.storage()))
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
            // store_event_with_state either inserts a new state row or UPDATEs the
            // existing one (invite → join).  Either path leaves current_state pointing
            // at the join event at membership_stream, which joined_membership_changed_since
            // then detects correctly.
            std::ignore =
                database::store_event_with_state(runtime.database.persistent_store, std::move(join_pe), join_state);
        }
        // GCOVR_EXCL_STOP

        auto const membership_result = database::store_membership(
            runtime.database.persistent_store, {std::string{room_id}, *user_id, "join", membership_stream});
        if (membership_result == database::MembershipStoreResult::error)
        {
            log_diagnostic("room.join.rejected", {
                                                     {"actor",   *user_id,                        false},
                                                     {"room_id", std::string{room_id},            false},
                                                     {"status",  "500",                           false},
                                                     {"reason",  "membership persistence failed", false}
            });
            return make_operation_result(false, {}, "membership persistence failed", 500U);
        }
        if (membership_result == database::MembershipStoreResult::already_exists &&
            !database::update_membership(runtime.database.persistent_store, room_id, *user_id, "join"))
        {
            log_diagnostic("room.join.rejected", {
                                                     {"actor",   *user_id,                   false},
                                                     {"room_id", std::string{room_id},       false},
                                                     {"status",  "500",                      false},
                                                     {"reason",  "membership update failed", false}
            });
            return make_operation_result(false, {}, "membership update failed", 500U);
        }
        for (auto const& joined_member : joined_members)
        {
            if (joined_member == *user_id)
            {
                continue;
            }
            auto const result = database::store_membership(
                runtime.database.persistent_store,
                {std::string{room_id}, joined_member, "join", runtime.database.next_stream_ordering++});
            if (result == database::MembershipStoreResult::already_exists)
            {
                std::ignore =
                    database::update_membership(runtime.database.persistent_store, room_id, joined_member, "join");
            }
        }
        if (!database::delete_invite(runtime.database.persistent_store, room_id, *user_id))
        {
            log_diagnostic("room.join.rejected", {
                                                     {"actor",   *user_id,                         false},
                                                     {"room_id", std::string{room_id},             false},
                                                     {"status",  "500",                            false},
                                                     {"reason",  "invite metadata cleanup failed", false}
            });
            return make_operation_result(false, {}, "invite metadata cleanup failed", 500U);
        }
        runtime.database.rooms.push_back({std::string{room_id}, *user_id, std::move(joined_members), {}});
        if (!record_room_share_started_device_changes(runtime, room_id, *user_id))
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
            runtime.sync_notifier->publish(runtime.database.next_stream_ordering - 1U, sync_stream_id);
        }
        return make_operation_result(true, std::string{room_id});
    }
    if (!room_has_member(*room, *user_id))
    {
        auto const join_event_json = serialize_membership_event_json(*user_id, "join");
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
        auto const composed = compose_signed_event(runtime, room_id, *user_id, *join_event_json);
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
        if (!persist_composed_event(runtime, room_id, *user_id, *composed))
        {
            log_diagnostic("room.join.rejected", {
                                                     {"actor",   *user_id,                              false},
                                                     {"room_id", std::string{room_id},                  false},
                                                     {"status",  "500",                                 false},
                                                     {"reason",  "membership event persistence failed", false}
            });
            return make_operation_result(false, {}, "membership event persistence failed", 500U);
        }
        room->events.push_back(composed->json);

        auto const membership_stream = runtime.database.next_stream_ordering++;
        auto const result = database::store_membership(runtime.database.persistent_store,
                                                       {std::string{room_id}, *user_id, "join", membership_stream});
        if (result == database::MembershipStoreResult::error)
        {
            log_diagnostic("room.join.rejected", {
                                                     {"actor",   *user_id,                        false},
                                                     {"room_id", std::string{room_id},            false},
                                                     {"status",  "500",                           false},
                                                     {"reason",  "membership persistence failed", false}
            });
            return make_operation_result(false, {}, "membership persistence failed", 500U);
        }
        // Both stored and already_exists: membership is valid — sync the in-memory state.
        if (result == database::MembershipStoreResult::already_exists &&
            !database::update_membership(runtime.database.persistent_store, room_id, *user_id, "join"))
        {
            log_diagnostic("room.join.rejected", {
                                                     {"actor",   *user_id,                   false},
                                                     {"room_id", std::string{room_id},       false},
                                                     {"status",  "500",                      false},
                                                     {"reason",  "membership update failed", false}
            });
            return make_operation_result(false, {}, "membership update failed", 500U);
        }
        append_unique_member(room->members, *user_id);
        if (!record_room_share_started_device_changes(runtime, room_id, *user_id))
        {
            log_diagnostic("room.join.rejected", {
                                                     {"actor",   *user_id,                                false},
                                                     {"room_id", std::string{room_id},                    false},
                                                     {"status",  "500",                                   false},
                                                     {"reason",  "device list change persistence failed", false}
            });
            return make_operation_result(false, {}, "device list change persistence failed", 500U);
        }
        if (result == database::MembershipStoreResult::stored)
        {
            log_diagnostic("room.join.membership_persisted",
                           {
                               {"actor",        *user_id,                             false},
                               {"room_id",      std::string{room_id},                 false},
                               {"member_count", std::to_string(room->members.size()), false}
            });
        }
        else
        {
            log_diagnostic("room.join.membership_updated",
                           {
                               {"actor",        *user_id,                             false},
                               {"room_id",      std::string{room_id},                 false},
                               {"member_count", std::to_string(room->members.size()), false}
            });
        }
        if (!database::delete_invite(runtime.database.persistent_store, room_id, *user_id))
        {
            log_diagnostic("room.join.rejected", {
                                                     {"actor",   *user_id,                         false},
                                                     {"room_id", std::string{room_id},             false},
                                                     {"status",  "500",                            false},
                                                     {"reason",  "invite metadata cleanup failed", false}
            });
            return make_operation_result(false, {}, "invite metadata cleanup failed", 500U);
        }
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
        runtime.sync_notifier->publish(runtime.database.next_stream_ordering - 1U, sync_stream_id);
    }
    return make_operation_result(true, std::string{room_id});
}

[[nodiscard]] auto leave_room(HomeserverRuntime& runtime, std::string_view access_token, std::string_view room_id)
    -> OperationResult
{
    auto guard = std::unique_lock<std::recursive_mutex>{runtime.mutex};
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
        auto const state_it =
            std::ranges::find_if(runtime.database.persistent_store.state, [&](database::PersistentStateEvent const& s) {
                return s.room_id == room_id && s.event_type == "m.room.member" && s.state_key == *user_id;
            });
        if (state_it != runtime.database.persistent_store.state.end())
        {
            auto const event_it =
                std::ranges::find_if(runtime.database.persistent_store.events, [&](database::PersistentEvent const& e) {
                    return e.event_id == state_it->event_id;
                });
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
                    auto const recovered_stream = runtime.database.next_stream_ordering++;
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
    if (membership_it->membership != "join" && membership_it->membership != "invite")
    {
        log_diagnostic("room.leave.accepted",
                       {
                           {"actor",   *user_id,             false},
                           {"room_id", std::string{room_id}, false}
        },
                       observability::LogEventSeverity::info);
        return make_operation_result(true, std::string{room_id});
    }

    // For rooms hosted on a remote server, perform a federated leave:
    // make_leave (get a signed template) → sign → send_leave.
    auto const our_server = runtime.config.server().server_name;
    auto const room_domain = server_name_from_room_id(room_id);
    auto const is_remote = !room_domain.empty() && room_domain != our_server;

    if (is_remote)
    {
        wire_federation_callbacks(runtime);
        auto const remote_server = std::string{room_domain};
        auto const signing_key = find_active_server_signing_key(runtime);
        auto const key_id = signing_key.has_value() ? signing_key->key_id : std::string{};
        auto const secret_key = runtime.database.signing_secret_key.bytes();

        guard.unlock();

        // Step 1: make_leave — fetch a leave event template from the remote server.
        auto make_leave_tx = federation::make_outbound_make_membership(
            federation::FederationEndpoint::make_leave, remote_server, our_server, room_id, *user_id, {});
        log_diagnostic("room.leave.remote.make_leave", {
                                                           {"actor",         *user_id,             false},
                                                           {"room_id",       std::string{room_id}, false},
                                                           {"remote_server", remote_server,        false}
        });
        auto const [make_ok, make_body] = perform_sync_outbound_call(runtime, room_id, make_leave_tx, key_id,
                                                                     secret_key, "room.leave.remote.make_leave_failed",
                                                                     runtime.federation.config.remote_timeout_seconds);
        if (!make_ok)
        {
            guard.lock();
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

        // Step 2: validate the leave event template.
        auto const make_response = canonicaljson::parse_lossless(make_body);
        auto const* make_obj = std::get_if<canonicaljson::Object>(&make_response.value.storage());
        if (make_obj == nullptr)
        {
            guard.lock();
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
            guard.lock();
            log_diagnostic("room.leave.rejected", {
                                                      {"actor",   *user_id,             false},
                                                      {"room_id", std::string{room_id}, false},
                                                      {"status",  "502",                false},
                                                      {"reason",  validated.reason,     false}
            });
            return make_operation_result(false, {}, validated.reason, 502U);
        }
        auto const room_version = validated.room_version;
        auto event_object = validated.event;

        // Step 3: add content hash and sign the leave event.
        auto const content_hash = events::make_content_hash(canonicaljson::Value{event_object});
        if (!content_hash.error.empty())
        {
            guard.lock();
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
        event_object.push_back(canonicaljson::make_member("hashes", canonicaljson::Value{std::move(hashes_obj)}));

        auto event_to_sign = canonicaljson::Value{event_object};
        auto const* policy = rooms::find_room_version_policy(room_version);
        if (policy == nullptr)
        {
            guard.lock();
            log_diagnostic("room.leave.rejected", {
                                                      {"actor",   *user_id,                      false},
                                                      {"room_id", std::string{room_id},          false},
                                                      {"status",  "500",                         false},
                                                      {"reason",  "room version policy missing", false}
            });
            return make_operation_result(false, {}, "room version policy missing", 500U);
        }
        if (runtime.crypto_provider == nullptr)
        {
            guard.lock();
            log_diagnostic("room.leave.rejected", {
                                                      {"actor",   *user_id,                                false},
                                                      {"room_id", std::string{room_id},                    false},
                                                      {"status",  "500",                                   false},
                                                      {"reason",  "server signing provider not available", false}
            });
            return make_operation_result(false, {}, "server signing provider not available", 500U);
        }
        auto key_store = RuntimeSigningKeyStore{our_server, signing_key.value()};
        auto const signed_event =
            events::sign_event_for_server(event_to_sign, *policy, key_store, *runtime.crypto_provider, our_server);
        if (!signed_event.error.empty())
        {
            guard.lock();
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
            guard.lock();
            log_diagnostic("room.leave.rejected", {
                                                      {"actor",   *user_id,                      false},
                                                      {"room_id", std::string{room_id},          false},
                                                      {"status",  "500",                         false},
                                                      {"reason",  "event_id computation failed", false}
            });
            return make_operation_result(false, {}, "event_id computation failed", 500U);
        }

        // Step 4: send_leave — deliver the signed leave event to the remote server.
        auto send_leave_tx = federation::make_outbound_send_membership(
            federation::FederationEndpoint::send_leave, remote_server, our_server, room_id, event_id_result.event_id,
            signed_event.event_json);
        log_diagnostic("room.leave.remote.send_leave", {
                                                           {"actor",         *user_id,                 false},
                                                           {"room_id",       std::string{room_id},     false},
                                                           {"remote_server", remote_server,            false},
                                                           {"event_id",      event_id_result.event_id, false}
        });
        auto const [send_ok, send_body] = perform_sync_outbound_call(runtime, room_id, send_leave_tx, key_id,
                                                                     secret_key, "room.leave.remote.send_leave_failed",
                                                                     runtime.federation.config.remote_timeout_seconds);

        guard.lock();

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

        // Step 5: update local membership, device lists and in-memory state.
        auto const membership_stream = runtime.database.next_stream_ordering++;
        if (!store_or_update_membership(runtime.database.persistent_store, room_id, *user_id, "leave",
                                        membership_stream))
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
        std::ignore = database::delete_invite(runtime.database.persistent_store, room_id, *user_id);
        auto const sync_stream_id = database::allocate_sync_stream_id(runtime.database.persistent_store);
        if (runtime.sync_notifier != nullptr)
        {
            runtime.sync_notifier->publish(runtime.database.next_stream_ordering - 1U, sync_stream_id);
        }
        append_local_audit(runtime.database, observability::AuditCategory::admin, "room.left_remote", *user_id, room_id,
                           "left via federation");
        log_diagnostic("room.leave.accepted",
                       {
                           {"actor",   *user_id,             false},
                           {"room_id", std::string{room_id}, false}
        },
                       observability::LogEventSeverity::info);
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
    return make_operation_result(true, std::string{room_id});
}

[[nodiscard]] auto invite_user(HomeserverRuntime& runtime, std::string_view access_token, std::string_view room_id,
                               std::string_view target_user_id, std::string_view reason) -> OperationResult
{
    auto guard = std::unique_lock<std::recursive_mutex>{runtime.mutex};
    auto const user_id = authenticated_user(runtime, access_token);
    if (!user_id.has_value())
    {
        return make_operation_result(false, {}, "unauthenticated", 401U);
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

    auto const result = persist_membership_transition(runtime, room_id, *user_id, target_user_id, "invite", reason);
    if (!result.ok)
    {
        return result;
    }
    append_local_audit(runtime.database, observability::AuditCategory::admin, "room.invited", *user_id, target_user_id,
                       std::string{room_id});
    return make_operation_result(true, std::string{room_id});
}

[[nodiscard]] auto ban_user(HomeserverRuntime& runtime, std::string_view access_token, std::string_view room_id,
                            std::string_view target_user_id, std::string_view reason) -> OperationResult
{
    auto guard = std::unique_lock<std::recursive_mutex>{runtime.mutex};
    auto const user_id = authenticated_user(runtime, access_token);
    if (!user_id.has_value())
    {
        return make_operation_result(false, {}, "unauthenticated", 401U);
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
    return make_operation_result(true, std::string{room_id});
}

[[nodiscard]] auto kick_user(HomeserverRuntime& runtime, std::string_view access_token, std::string_view room_id,
                             std::string_view target_user_id, std::string_view reason) -> OperationResult
{
    auto guard = std::unique_lock<std::recursive_mutex>{runtime.mutex};
    auto const user_id = authenticated_user(runtime, access_token);
    if (!user_id.has_value())
    {
        return make_operation_result(false, {}, "unauthenticated", 401U);
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

    auto const result = persist_membership_transition(runtime, room_id, *user_id, target_user_id, "leave", reason);
    if (!result.ok)
    {
        return result;
    }
    append_local_audit(runtime.database, observability::AuditCategory::admin, "room.kicked", *user_id, target_user_id,
                       std::string{room_id});
    return make_operation_result(true, std::string{room_id});
}

[[nodiscard]] auto unban_user(HomeserverRuntime& runtime, std::string_view access_token, std::string_view room_id,
                              std::string_view target_user_id) -> OperationResult
{
    auto guard = std::unique_lock<std::recursive_mutex>{runtime.mutex};
    auto const user_id = authenticated_user(runtime, access_token);
    if (!user_id.has_value())
    {
        return make_operation_result(false, {}, "unauthenticated", 401U);
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
    return make_operation_result(true, std::string{room_id});
}

[[nodiscard]] auto forget_room(HomeserverRuntime& runtime, std::string_view access_token, std::string_view room_id)
    -> OperationResult
{
    auto guard = std::unique_lock<std::recursive_mutex>{runtime.mutex};
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
    if (!database::delete_membership(runtime.database.persistent_store, room_id, *user_id))
    {
        return make_operation_result(false, {}, "membership delete failed", 500U);
    }
    if (!database::delete_invite(runtime.database.persistent_store, room_id, *user_id))
    {
        return make_operation_result(false, {}, "invite metadata cleanup failed", 500U);
    }

    auto const sync_stream_id = database::allocate_sync_stream_id(runtime.database.persistent_store);
    if (runtime.sync_notifier != nullptr)
    {
        runtime.sync_notifier->publish(runtime.database.next_stream_ordering - 1U, sync_stream_id);
    }
    append_local_audit(runtime.database, observability::AuditCategory::admin, "room.forgotten", *user_id, room_id,
                       "forgotten");
    return make_operation_result(true, std::string{room_id});
}

[[nodiscard]] auto knock_room(HomeserverRuntime& runtime, std::string_view access_token, std::string_view room_id)
    -> OperationResult
{
    auto guard = std::unique_lock<std::recursive_mutex>{runtime.mutex};
    auto const user_id = authenticated_user(runtime, access_token);
    if (!user_id.has_value())
    {
        return make_operation_result(false, {}, "unauthenticated", 401U);
    }
    if (!room_exists(runtime, room_id))
    {
        return make_operation_result(false, {}, "room not found", 404U);
    }

    auto const result = persist_membership_transition(runtime, room_id, *user_id, *user_id, "knock");
    if (!result.ok)
    {
        return result;
    }
    append_local_audit(runtime.database, observability::AuditCategory::admin, "room.knocked", *user_id, room_id,
                       "knocked");
    return make_operation_result(true, std::string{room_id});
}

// NOLINTBEGIN(bugprone-easily-swappable-parameters)
[[nodiscard]] auto send_event(HomeserverRuntime& runtime, std::string_view access_token, std::string_view room_id,
                              std::string_view event_json) -> OperationResult
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

    auto* room = find_room(runtime.database, room_id);
    if (room == nullptr)
    {
        log_diagnostic("room.event.rejected", {
                                                  {"actor",   *user_id,             false},
                                                  {"room_id", std::string{room_id}, false},
                                                  {"reason",  "unknown room",       false}
        });
        return make_operation_result(false, {}, "unknown room");
    }
    if (!room_has_member(*room, *user_id))
    {
        log_diagnostic(
            "room.event.rejected",
            {
                {"actor",   *user_id,             false},
                {"room_id", std::string{room_id}, false},
                {"reason",  "not joined",         false}
        });
        return make_operation_result(false, {}, "not joined");
    }
    if (event_json.empty())
    {
        log_diagnostic("room.event.rejected", {
                                                  {"actor",   *user_id,             false},
                                                  {"room_id", std::string{room_id}, false},
                                                  {"reason",  "empty event",        false}
        });
        return make_operation_result(false, {}, "empty event");
    }

    auto const composed = compose_signed_event(runtime, room_id, *user_id, event_json);
    if (!composed.has_value())
    {
        log_diagnostic("room.event.rejected", {
                                                  {"actor",   *user_id,                                false},
                                                  {"room_id", std::string{room_id},                    false},
                                                  {"status",  "403",                                   false},
                                                  {"reason",  "event authorization or signing failed", false}
        });
        return make_operation_result(false, {}, "event authorization or signing failed", 403U);
    }
    auto const stream_ordering = runtime.database.next_stream_ordering++;
    auto state = std::optional<database::PersistentStateEvent>{};
    if (composed->state_key.has_value())
    {
        state = database::PersistentStateEvent{std::string{room_id}, composed->event_type, *composed->state_key,
                                               composed->event_id};
    }
    if (!database::store_event_with_state(runtime.database.persistent_store,
                                          {composed->event_id, std::string{room_id}, *user_id, composed->json,
                                           composed->depth, stream_ordering, composed->prev_event_ids,
                                           composed->auth_event_ids, composed->signatures},
                                          std::move(state)))
    {
        log_diagnostic("room.event.rejected", {
                                                  {"actor",      *user_id,                   false},
                                                  {"room_id",    std::string{room_id},       false},
                                                  {"event_id",   composed->event_id,         false},
                                                  {"event_type", composed->event_type,       false},
                                                  {"status",     "500",                      false},
                                                  {"reason",     "event persistence failed", false}
        });
        return make_operation_result(false, {}, "event persistence failed", 500U);
    }
    room->events.push_back(composed->json);
    append_local_audit(runtime.database, observability::AuditCategory::admin, "room.event_sent", *user_id, room_id,
                       "stored");
    log_diagnostic("room.event.accepted", {
                                              {"actor",       *user_id,                                        false},
                                              {"room_id",     std::string{room_id},                            false},
                                              {"event_id",    composed->event_id,                              false},
                                              {"event_type",  composed->event_type,                            false},
                                              {"depth",       std::to_string(composed->depth),                 false},
                                              {"prev_events", std::to_string(composed->prev_event_ids.size()), false},
                                              {"auth_events", std::to_string(composed->auth_event_ids.size()), false}
    });
    if (runtime.sync_notifier != nullptr)
    {
        runtime.sync_notifier->publish(runtime.database.next_stream_ordering - 1U,
                                       runtime.database.persistent_store.next_sync_stream_id);
    }
    wire_federation_callbacks(runtime);
    if (runtime.dispatch_worker != nullptr)
    {
        auto const& server_name = runtime.config.server().server_name;
        auto remote_servers = std::vector<std::string>{};
        for (auto const& member : room->members)
        {
            auto const colon = member.rfind(':');
            if (colon == std::string::npos)
            {
                continue;
            }
            auto const member_server = member.substr(colon + 1);
            if (member_server != server_name &&
                std::ranges::find(remote_servers, member_server) == remote_servers.end())
            {
                remote_servers.emplace_back(member_server);
            }
        }
        if (!remote_servers.empty())
        {
            auto pdu_array = canonicaljson::Array{};
            auto pdu_parsed = canonicaljson::parse_lossless(composed->json);
            if (pdu_parsed.error == canonicaljson::ParseError::none)
            {
                pdu_array.push_back(std::move(pdu_parsed.value));
            }
            auto tx_root = canonicaljson::Object{};
            tx_root.push_back(canonicaljson::make_member("pdus", canonicaljson::Value{std::move(pdu_array)}));
            tx_root.push_back(canonicaljson::make_member("edus", canonicaljson::Value{canonicaljson::Array{}}));
            auto const tx_body_result = canonicaljson::serialize_canonical(canonicaljson::Value{std::move(tx_root)});
            auto const& tx_body = tx_body_result.output;
            auto const tx_id = federation::make_federation_transaction_id();
            for (auto const& destination : remote_servers)
            {
                auto target = "/_matrix/federation/v1/send/" + tx_id;
                auto transaction =
                    federation::make_outbound_transaction(destination, "PUT", target, server_name, tx_body);
                transaction.transaction_id = tx_id;
                std::ignore = runtime.dispatch_worker->enqueue(std::move(transaction));
            }
            log_diagnostic("room.event.dispatched",
                           {
                               {"room_id",      std::string{room_id},                  false},
                               {"event_id",     composed->event_id,                    false},
                               {"destinations", std::to_string(remote_servers.size()), false}
            });
        }
    }
    return make_operation_result(true, composed->event_id);
}
// NOLINTEND(bugprone-easily-swappable-parameters)

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
    if (!room_has_member(*room, *user_id))
    {
        return make_operation_result(false, {}, "not joined", 403U);
    }

    // Build a JSON array of the current state events for this room.
    auto state_array = canonicaljson::Array{};
    for (auto const& state : runtime.database.persistent_store.state)
    {
        if (state.room_id != room_id)
        {
            continue;
        }
        auto event_value = find_event_json(runtime.database.persistent_store, state.event_id);
        if (!std::holds_alternative<std::nullptr_t>(event_value.storage()))
        {
            state_array.push_back(std::move(event_value));
        }
    }
    auto serialized = canonicaljson::serialize_canonical(canonicaljson::Value{std::move(state_array)});
    if (serialized.error != canonicaljson::CanonicalJsonError::none)
    {
        return make_operation_result(false, {}, "state serialization failed", 500U);
    }
    return make_operation_result(true, std::move(serialized.output));
}

namespace
{
    [[nodiscard]] auto client_event_with_id(database::PersistentEvent const& event) -> canonicaljson::Value
    {
        auto const parsed = canonicaljson::parse_lossless(event.json);
        if (parsed.error == canonicaljson::ParseError::none)
        {
            if (auto const* obj = std::get_if<canonicaljson::Object>(&parsed.value.storage()))
            {
                auto client_obj = *obj;
                client_obj.push_back(canonicaljson::make_member("event_id", canonicaljson::Value{event.event_id}));
                return canonicaljson::Value{std::move(client_obj)};
            }
        }
        return canonicaljson::Value{canonicaljson::Object{}};
    }

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

    auto const* room = find_room(runtime.database, request.room_id);
    if (room == nullptr || !room_has_member(*room, *user_id))
    {
        return make_operation_result(false, {}, "not joined or unknown room", 404U);
    }

    auto const& store = runtime.database.persistent_store;
    auto const parent_exists = std::ranges::any_of(store.events, [&request](database::PersistentEvent const& event) {
        return event.room_id == request.room_id && event.event_id == request.event_id;
    });
    if (!parent_exists)
    {
        return make_operation_result(false, {}, "parent event not found", 404U);
    }

    auto matches = std::vector<database::PersistentEvent const*>{};
    for (auto const& event : store.events)
    {
        if (event.room_id != request.room_id)
        {
            continue;
        }

        if (request.event_type.has_value())
        {
            auto const parsed_type = canonicaljson::parse_lossless(event.json);
            if (parsed_type.error != canonicaljson::ParseError::none)
            {
                continue;
            }
            auto const* event_obj = std::get_if<canonicaljson::Object>(&parsed_type.value.storage());
            if (event_obj == nullptr)
            {
                continue;
            }
            auto const* type = string_member(*event_obj, "type");
            if (type == nullptr || *type != *request.event_type)
            {
                continue;
            }
        }

        auto const parsed = canonicaljson::parse_lossless(event.json);
        if (parsed.error != canonicaljson::ParseError::none)
        {
            continue;
        }
        auto const* event_obj = std::get_if<canonicaljson::Object>(&parsed.value.storage());
        if (event_obj == nullptr)
        {
            continue;
        }
        auto const* content_value = object_member(*event_obj, "content");
        if (content_value == nullptr)
        {
            continue;
        }
        auto const* content_obj = std::get_if<canonicaljson::Object>(&content_value->storage());
        if (content_obj == nullptr)
        {
            continue;
        }
        auto const* relates_value = object_member(*content_obj, "m.relates_to");
        if (relates_value == nullptr)
        {
            continue;
        }
        auto const* relates_obj = std::get_if<canonicaljson::Object>(&relates_value->storage());
        if (relates_obj == nullptr)
        {
            continue;
        }
        auto const* related_event_id = string_member(*relates_obj, "event_id");
        if (related_event_id == nullptr || *related_event_id != request.event_id)
        {
            continue;
        }
        auto const* rel_type = string_member(*relates_obj, "rel_type");
        if (request.rel_type.has_value() && (rel_type == nullptr || *rel_type != *request.rel_type))
        {
            continue;
        }

        matches.push_back(&event);
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

    auto const from_token = parse_stream_ordering_token(request.from);
    auto const to_token = parse_stream_ordering_token(request.to);
    auto constexpr default_limit = std::uint64_t{100U};
    auto constexpr max_limit = std::uint64_t{1000U};
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

    if (end - start > static_cast<std::size_t>(limit))
    {
        end = start + static_cast<std::size_t>(limit);
    }

    auto chunk = canonicaljson::Array{};
    chunk.reserve(end - start);
    for (auto index = start; index < end; ++index)
    {
        chunk.push_back(client_event_with_id(*matches[index]));
    }

    auto response = canonicaljson::Object{};
    response.push_back(canonicaljson::make_member("chunk", canonicaljson::Value{std::move(chunk)}));

    if (start > 0U)
    {
        response.push_back(canonicaljson::make_member(
            "prev_batch", canonicaljson::Value{std::to_string(matches[start - 1U]->stream_ordering)}));
    }
    if (end < matches.size())
    {
        response.push_back(canonicaljson::make_member(
            "next_batch", canonicaljson::Value{std::to_string(matches[end]->stream_ordering)}));
    }
    if (request.recurse.has_value())
    {
        // Direct relations only for now; still report the depth the client asked for.
        response.push_back(
            canonicaljson::make_member("recursion_depth", canonicaljson::Value{static_cast<std::int64_t>(0)}));
    }

    auto serialized = canonicaljson::serialize_canonical(canonicaljson::Value{std::move(response)});
    if (serialized.error != canonicaljson::CanonicalJsonError::none)
    {
        return make_operation_result(false, {}, "relations serialization failed", 500U);
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
