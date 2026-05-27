// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/room_service.hpp"

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
#include "merovingian/federation/membership_endpoints.hpp"
#include "merovingian/federation/outbound_membership.hpp"
#include "merovingian/federation/outbound_transaction.hpp"
#include "merovingian/federation/server_discovery.hpp"
#include "merovingian/homeserver/auth_service.hpp"
#include "merovingian/homeserver/local_http_router.hpp"
#include "merovingian/observability/logger.hpp"
#include "merovingian/observability/observability.hpp"
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
#include <vector>

#include <sodium.h>

namespace merovingian::homeserver
{
namespace
{

    auto log_diagnostic(std::string_view event, std::vector<observability::StructuredLogField> fields) -> void
    {
        LOG_DEBUG(observability::diagnostic_log_summary("rooms", event, std::move(fields)));
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

    // Perform a single synchronous outbound federation call. Returns the raw
    // response body on success (HTTP 2xx), or an error description on failure.
    [[nodiscard]] auto perform_sync_outbound_call(http::OutboundClient* outbound_client,
                                                  federation::ServerDiscoveryNetwork* discovery_network,
                                                  federation::OutboundTransaction const& transaction,
                                                  std::string_view key_id, std::string_view secret_key,
                                                  std::string_view diagnostic_event) -> std::pair<bool, std::string>
    {
        if (outbound_client == nullptr || discovery_network == nullptr)
        {
            log_diagnostic(diagnostic_event, {
                                                 {"reason", "federation infrastructure not available", false}
            });
            return {false, "federation not available"};
        }
        auto const discovery_timeout = std::uint32_t{30U};
        auto const resolution =
            federation::discover_server(transaction.destination, *discovery_network, discovery_timeout);
        if (!resolution.discovery_allowed)
        {
            log_diagnostic(diagnostic_event, {
                                                 {"destination", transaction.destination,   false},
                                                 {"reason",      "server discovery failed", false}
            });
            return {false, "server discovery failed"};
        }
        // Load (or generate) the server signing key so we can read its actual key_id.
        // Outbound federation requests must reference the exact key_id that was published
        // to key servers — never a hardcoded sentinel like "ed25519:auto".
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
        call.secret_key = std::string{secret_key};
        auto destination = federation::FederationDestination{};
        destination.server_name = transaction.destination;
        auto const now_ts = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
                .count());
        auto const result = federation::perform_outbound_transaction(*outbound_client, call, destination, now_ts);
        if (!result.sent || result.http_status < 200U || result.http_status >= 300U)
        {
            log_diagnostic(diagnostic_event, {
                                                 {"destination", transaction.destination,                         false},
                                                 {"http_status", std::to_string(result.http_status),              false},
                                                 {"reason",      result.error.empty() ? "non-2xx" : result.error, false}
            });
            return {false, result.error.empty() ? "remote server returned " + std::to_string(result.http_status)
                                                : result.error};
        }
        return {true, result.response_body};
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

    auto append_unique_member(std::vector<std::string>& members, std::string_view user_id) -> void
    {
        if (!std::ranges::any_of(members, [&](std::string const& member) {
                return member == user_id;
            }))
        {
            members.emplace_back(user_id);
        }
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
            log_diagnostic("event.compose.body_fallback",
                           {
                               {"room_id",    std::string{room_id},                     false},
                               {"sender",     std::string{sender},                      false},
                               {"body_bytes", std::to_string(client_event_json.size()), false}
            });
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
        auto const* policy = rooms::find_room_version_policy("12");
        if (policy == nullptr)
        {
            return std::nullopt;
        }
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

        auto key = ensure_runtime_server_signing_key(runtime);
        if (!key.has_value())
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
            auto const* auth_policy = rooms::find_room_version_policy("12");
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
    auto const it = std::ranges::find_if(all_keys, [&server_name](database::PersistentServerSigningKey const& k) {
        return k.server_name == server_name && k.key_id != "ed25519:auto" && !k.secret_key.empty();
    });

    if (it != all_keys.end())
    {
        // Decode the stored base64 secret and validate its size before trusting it.
        // Fail closed if the secret cannot hydrate into a full Ed25519 secret key —
        // attempting to sign with wrong-length material produces corrupt signatures.
        auto const raw_secret = events::matrix_bytes_from_base64(it->secret_key);
        if (raw_secret.size() != crypto_sign_SECRETKEYBYTES)
        {
            log_diagnostic("signing_key.rejected",
                           {
                               {"server_name", std::string{server_name},                   false},
                               {"key_id",      it->key_id,                                 false},
                               {"reason",      "secret_size_invalid",                      false},
                               {"secret_size", std::to_string(raw_secret.size()),          false},
                               {"expected",    std::to_string(crypto_sign_SECRETKEYBYTES), false}
            });
            return std::nullopt;
        }
        runtime.database.signing_secret_key = std::vector<unsigned char>(raw_secret.begin(), raw_secret.end());
        log_diagnostic("signing_key.loaded", {
                                                 {"server_name", std::string{server_name},          false},
                                                 {"key_id",      it->key_id,                        false},
                                                 {"public_key",  it->public_key,                    false},
                                                 {"secret_size", std::to_string(raw_secret.size()), false}
        });
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

    // Derive the key_id from the first four bytes of the public key as lowercase hex.
    // This ties the ID to the key material so that each new key gets a unique ID;
    // stale notary-cache entries for old IDs become irrelevant after key rotation.
    static constexpr auto hex_digits = std::string_view{"0123456789abcdef"};
    auto key_version = std::string{};
    key_version.reserve(8U);
    for (auto i = 0U; i < 4U; ++i)
    {
        key_version += hex_digits[(public_key[i] >> 4U) & 0x0fU];
        key_version += hex_digits[public_key[i] & 0x0fU];
    }
    auto const key_id = "ed25519:" + key_version;

    // Publish now + 7 days as valid_until_ts so federation peers periodically
    // re-fetch the key rather than caching it indefinitely.
    auto constexpr seven_days_ms = std::uint64_t{7U * 24U * 60U * 60U * 1000U};
    auto const now_ms = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
            .count());

    auto key = database::PersistentServerSigningKey{
        std::string{server_name},
        key_id,
        events::matrix_base64_from_bytes(
            std::string_view{reinterpret_cast<char const*>(public_key.data()), public_key.size()}),
        now_ms + seven_days_ms,
        // Base64-encode the secret so it can be stored as printable text — raw Ed25519
        // secret bytes frequently contain null bytes, which would truncate the value when
        // read back via C string APIs.
        events::matrix_base64_from_bytes(
            std::string_view{reinterpret_cast<char const*>(secret_key.data()), secret_key.size()}),
    };
    log_diagnostic("signing_key.generated", {
                                                {"server_name", std::string{server_name}, false},
                                                {"key_id",      key_id,                   false},
                                                {"public_key",  key.public_key,           false}
    });
    if (!database::store_server_signing_key(runtime.database.persistent_store, key))
    {
        return std::nullopt;
    }
    runtime.database.signing_secret_key = std::vector<unsigned char>(secret_key.begin(), secret_key.end());
    return key;
}

[[nodiscard]] auto publish_server_signing_keys(HomeserverRuntime& runtime) -> OperationResult
{
    auto key = ensure_runtime_server_signing_key(runtime);
    if (!key.has_value())
    {
        return make_operation_result(false, {}, "server signing key unavailable", 500U);
    }
    if (runtime.database.signing_secret_key.size() != crypto_sign_SECRETKEYBYTES)
    {
        return make_operation_result(false, {}, "server signing secret unavailable", 500U);
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

    auto signature = std::string(crypto_sign_BYTES, '\0');
    if (crypto_sign_detached(reinterpret_cast<unsigned char*>(signature.data()), nullptr,
                             reinterpret_cast<unsigned char const*>(payload.output.data()), payload.output.size(),
                             runtime.database.signing_secret_key.data()) != 0)
    {
        return make_operation_result(false, {}, "server key response signing failed", 500U);
    }

    auto server_signatures = canonicaljson::Object{};
    server_signatures.push_back(
        canonicaljson::make_member(key->key_id, canonicaljson::Value{events::matrix_base64_from_bytes(signature)}));
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
        runtime.database.key_server_cache->store(std::make_shared<std::string>(signed_response.output));
    }

    return make_operation_result(true, std::move(signed_response.output));
}

[[nodiscard]] auto create_room(HomeserverRuntime& runtime, std::string_view access_token) -> OperationResult
{
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

    auto const room_id =
        "!room" + std::to_string(runtime.database.rooms.size() + 1U) + ":" + runtime.config.server().server_name;
    auto const room_decision = trust_safety::evaluate_room_policy({room_id, false, false, {}});
    if (!room_decision.allowed)
    {
        log_diagnostic(
            "room.create.rejected",
            {
                {"actor",   *user_id,                  false},
                {"room_id", room_id,                   false},
                {"reason",  room_decision.reason.code, false}
        });
        return make_operation_result(false, {}, room_decision.reason.code);
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
    append_local_audit(runtime.database, observability::AuditCategory::admin, "room.created", *user_id, room_id,
                       "created");
    log_diagnostic("room.create.accepted", {
                                               {"actor",   *user_id, false},
                                               {"room_id", room_id,  false}
    });
    // Room creation changes membership which is visible in /sync;
    // advance the sync stream counter so the publish wakes clients.
    runtime.database.persistent_store.next_sync_stream_id += 1U;
    if (runtime.sync_notifier != nullptr)
    {
        runtime.sync_notifier->publish(runtime.database.next_stream_ordering - 1U,
                                       runtime.database.persistent_store.next_sync_stream_id);
    }
    return make_operation_result(true, room_id);
}

[[nodiscard]] auto join_room(HomeserverRuntime& runtime, std::string_view access_token, std::string_view room_id)
    -> OperationResult
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
    if (room == nullptr)
    {
        auto const remote_server = server_name_from_room_id(room_id);
        if (remote_server.empty() || remote_server == runtime.config.server().server_name)
        {
            log_diagnostic("room.join.rejected", {
                                                     {"actor",   *user_id,             false},
                                                     {"room_id", std::string{room_id}, false},
                                                     {"status",  "403",                false},
                                                     {"reason",  "unknown room",       false}
            });
            return make_operation_result(false, {}, "unknown room", 403U);
        }
        // Remote room: attempt make_join → sign → send_join via the
        // remote homeserver that originated the room.
        wire_federation_callbacks(runtime);
        auto* outbound_client = runtime.outbound_client.get();
        auto* discovery_network = runtime.discovery_network.get();
        auto const our_server = runtime.config.server().server_name;
        auto const supported_versions = std::vector<std::string>{"12"};
        auto const signing_key = ensure_runtime_server_signing_key(runtime);
        if (!signing_key.has_value())
        {
            log_diagnostic("room.join.rejected", {
                                                     {"actor",   *user_id,                         false},
                                                     {"room_id", std::string{room_id},             false},
                                                     {"status",  "500",                            false},
                                                     {"reason",  "server signing key unavailable", false}
            });
            return make_operation_result(false, {}, "server signing key unavailable", 500U);
        }
        auto const signing_key_copy = *signing_key;
        auto const secret_key = std::string{reinterpret_cast<char const*>(runtime.database.signing_secret_key.data()),
                                            runtime.database.signing_secret_key.size()};
        if (secret_key.size() != crypto_sign_SECRETKEYBYTES)
        {
            log_diagnostic("room.join.rejected", {
                                                     {"actor",   *user_id,                         false},
                                                     {"room_id", std::string{room_id},             false},
                                                     {"status",  "500",                            false},
                                                     {"reason",  "server signing key unavailable", false}
            });
            return make_operation_result(false, {}, "server signing key unavailable", 500U);
        }
        auto make_join_tx =
            federation::make_outbound_make_membership(federation::FederationEndpoint::make_join, remote_server,
                                                      our_server, room_id, *user_id, supported_versions);
        log_diagnostic("room.join.remote.make_join", {
                                                         {"actor",         *user_id,                   false},
                                                         {"room_id",       std::string{room_id},       false},
                                                         {"remote_server", std::string{remote_server}, false}
        });
        guard.unlock();
        auto const [make_ok, make_body] =
            perform_sync_outbound_call(outbound_client, discovery_network, make_join_tx, signing_key_copy.key_id,
                                       secret_key, "room.join.remote.make_join_failed");
        if (!make_ok)
        {
            log_diagnostic("room.join.rejected", {
                                                     {"actor",   *user_id,             false},
                                                     {"room_id", std::string{room_id}, false},
                                                     {"status",  "502",                false},
                                                     {"reason",  "make_join failed",   false}
            });
            return make_operation_result(false, {}, "make_join failed: " + make_body, 502U);
        }
        // Parse the make_join response: { "room_version": "12", "event": {...} }
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
        // Extract the "event" member (an object, not a string) from the
        // make_join response.
        auto const* event_member_value = object_member(*make_obj, "event");
        auto const* event_inner = event_member_value == nullptr
                                      ? nullptr
                                      : std::get_if<canonicaljson::Object>(&event_member_value->storage());
        if (event_inner == nullptr)
        {
            log_diagnostic("room.join.rejected", {
                                                     {"actor",   *user_id,                        false},
                                                     {"room_id", std::string{room_id},            false},
                                                     {"status",  "502",                           false},
                                                     {"reason",  "make_join missing event field", false}
            });
            return make_operation_result(false, {}, "make_join missing event field", 502U);
        }
        // The template event arrives without origin_server_ts; inject it.
        auto const now_ms = static_cast<std::int64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
                .count());
        auto event_object = canonicaljson::Object{};
        for (auto const& member : *event_inner)
        {
            if (member.key == "origin_server_ts")
            {
                event_object.push_back(canonicaljson::make_member("origin_server_ts", canonicaljson::Value{now_ms}));
            }
            else
            {
                event_object.push_back(member);
            }
        }
        // Ensure origin_server_ts is present even if the remote omitted it.
        auto const has_ost = std::ranges::any_of(*event_inner, [](canonicaljson::ObjectMember const& m) {
            return m.key == "origin_server_ts";
        });
        if (!has_ost)
        {
            event_object.push_back(canonicaljson::make_member("origin_server_ts", canonicaljson::Value{now_ms}));
        }
        auto event_to_sign = canonicaljson::Value{event_object};
        // Sign the event with our server's signing key.
        auto key_store = RuntimeSigningKeyStore{our_server, signing_key_copy};
        auto secret_key_array = std::array<unsigned char, crypto_sign_SECRETKEYBYTES>{};
        if (secret_key.size() == crypto_sign_SECRETKEYBYTES)
        {
            std::copy(secret_key.begin(), secret_key.end(), secret_key_array.begin());
        }
        auto provider = RuntimeEd25519Provider{std::move(secret_key_array)};
        auto const* policy = rooms::find_room_version_policy("12");
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
            events::sign_event_for_server(event_to_sign, *policy, key_store, provider, our_server);
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
        auto const [send_ok, send_body] =
            perform_sync_outbound_call(outbound_client, discovery_network, send_join_tx, signing_key_copy.key_id,
                                       secret_key, "room.join.remote.send_join_failed");
        if (!send_ok)
        {
            log_diagnostic("room.join.rejected", {
                                                     {"actor",   *user_id,             false},
                                                     {"room_id", std::string{room_id}, false},
                                                     {"status",  "502",                false},
                                                     {"reason",  "send_join failed",   false}
            });
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
                for (auto const& state_entry : *state_arr)
                {
                    auto const serialized = canonicaljson::serialize_canonical(state_entry);
                    if (serialized.error == canonicaljson::CanonicalJsonError::none)
                    {
                        auto const parsed = events::parse_event_envelope(state_entry);
                        if (parsed.error.empty())
                        {
                            auto pe = database::PersistentEvent{};
                            pe.event_id = ""; // hash-based IDs computed elsewhere
                            pe.room_id = parsed.event.room_id;
                            pe.sender_user_id = parsed.event.sender;
                            pe.json = serialized.output;
                            pe.signatures = parsed.event.signatures;
                            std::ignore = database::store_event(runtime.database.persistent_store, std::move(pe));
                            if (parsed.event.event_type == "m.room.member" && !parsed.event.state_key.empty() &&
                                events::extract_content_membership(state_entry) == "join")
                            {
                                append_unique_member(joined_members, parsed.event.state_key);
                            }
                        }
                    }
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
                            auto pe = database::PersistentEvent{};
                            pe.event_id = "";
                            pe.room_id = parsed.event.room_id;
                            pe.sender_user_id = parsed.event.sender;
                            pe.json = serialized.output;
                            pe.signatures = parsed.event.signatures;
                            std::ignore = database::store_event(runtime.database.persistent_store, std::move(pe));
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
        auto const membership_result =
            database::store_membership(runtime.database.persistent_store, {std::string{room_id}, *user_id});
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
        runtime.database.rooms.push_back({std::string{room_id}, *user_id, std::move(joined_members), {}});
        append_local_audit(runtime.database, observability::AuditCategory::admin, "room.joined_remote", *user_id,
                           room_id, "joined via federation");
        log_diagnostic("room.join.accepted_remote",
                       {
                           {"actor",         *user_id,                                                     false},
                           {"room_id",       std::string{room_id},                                         false},
                           {"remote_server", std::string{remote_server},                                   false},
                           {"event_id",      event_id_result.event_id,                                     false},
                           {"member_count",  std::to_string(runtime.database.rooms.back().members.size()), false}
        });
        // Membership change from remote join is visible in /sync; advance
        // the sync stream counter so the publish wakes clients.
        runtime.database.persistent_store.next_sync_stream_id += 1U;
        if (runtime.sync_notifier != nullptr)
        {
            runtime.sync_notifier->publish(runtime.database.next_stream_ordering - 1U,
                                           runtime.database.persistent_store.next_sync_stream_id);
        }
        return make_operation_result(true, std::string{room_id});
    }
    if (!room_has_member(*room, *user_id))
    {
        auto const result =
            database::store_membership(runtime.database.persistent_store, {std::string{room_id}, *user_id});
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
        room->members.push_back(*user_id);
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
            log_diagnostic("room.join.already_member",
                           {
                               {"actor",        *user_id,                             false},
                               {"room_id",      std::string{room_id},                 false},
                               {"member_count", std::to_string(room->members.size()), false}
            });
        }
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
    log_diagnostic("room.join.accepted", {
                                             {"actor",        *user_id,                             false},
                                             {"room_id",      std::string{room_id},                 false},
                                             {"member_count", std::to_string(room->members.size()), false}
    });
    // Membership change from local join is visible in /sync; advance
    // the sync stream counter so the publish wakes clients.
    runtime.database.persistent_store.next_sync_stream_id += 1U;
    if (runtime.sync_notifier != nullptr)
    {
        runtime.sync_notifier->publish(runtime.database.next_stream_ordering - 1U,
                                       runtime.database.persistent_store.next_sync_stream_id);
    }
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
            auto tx_id = std::to_string(runtime.database.next_session_id++);
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
    auto const user_id = authenticated_user(runtime, access_token);
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

[[nodiscard]] auto audit_event_count(HomeserverRuntime const& runtime) noexcept -> std::size_t
{
    return runtime.database.audit_events.size();
}

} // namespace merovingian::homeserver
