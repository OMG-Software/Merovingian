// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/federation/remote_key_cache.hpp"

#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/serializer.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/crypto/ed25519.hpp"
#include "merovingian/events/event_signer.hpp"
#include "merovingian/federation/security.hpp"
#include "merovingian/observability/logger.hpp"
#include "merovingian/observability/observability.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <tuple>
#include <utility>
#include <variant>
#include <vector>

#include <sodium.h>

namespace merovingian::federation
{
namespace
{

    auto constexpr key_endpoint = std::string_view{"/_matrix/key/v2/server"};
    // Refresh slack: re-fetch when within this window of expiry so verifications
    // don't race the cutoff. Five minutes matches the federation clock-skew bound.
    auto constexpr refresh_slack_ms = std::uint64_t{5U * 60U * 1000U};

    [[nodiscard]] auto find_member(canonicaljson::Object const& object, std::string_view key) noexcept
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

    [[nodiscard]] auto extract_string(canonicaljson::Value const& value) -> std::optional<std::string>
    {
        auto const* text = std::get_if<std::string>(&value.storage());
        return text == nullptr ? std::nullopt : std::optional<std::string>{*text};
    }

    [[nodiscard]] auto extract_integer(canonicaljson::Value const& value) -> std::optional<std::uint64_t>
    {
        auto const* number = std::get_if<std::int64_t>(&value.storage());
        if (number == nullptr || *number < 0)
        {
            return std::nullopt;
        }
        return static_cast<std::uint64_t>(*number);
    }

    struct RemoteKeyParsed final
    {
        std::string server_name{};
        std::uint64_t valid_until_ts{0U};
        std::vector<RemoteVerifyKey> verify_keys{};
        // signatures[server_name][key_id] = base64 signature
        std::vector<std::pair<std::string, std::string>> server_signatures{};
        canonicaljson::Value canonical_payload{};
    };

    [[nodiscard]] auto strip_signatures(canonicaljson::Object const& original) -> canonicaljson::Object
    {
        auto stripped = canonicaljson::Object{};
        stripped.reserve(original.size());
        for (auto const& member : original)
        {
            if (member.key == "signatures")
            {
                continue;
            }
            stripped.push_back(canonicaljson::make_member(member.key, *member.value));
        }
        return stripped;
    }

    [[nodiscard]] auto parse_response(std::string_view body) -> std::optional<RemoteKeyParsed>
    {
        auto const parsed = canonicaljson::parse_lossless(body);
        if (parsed.error != canonicaljson::ParseError::none)
        {
            return std::nullopt;
        }
        auto const* root = std::get_if<canonicaljson::Object>(&parsed.value.storage());
        if (root == nullptr)
        {
            return std::nullopt;
        }

        auto const* server_name_value = find_member(*root, "server_name");
        auto const* valid_until_value = find_member(*root, "valid_until_ts");
        auto const* verify_keys_value = find_member(*root, "verify_keys");
        auto const* signatures_value = find_member(*root, "signatures");
        if (server_name_value == nullptr || valid_until_value == nullptr || verify_keys_value == nullptr ||
            signatures_value == nullptr)
        {
            return std::nullopt;
        }

        auto record = RemoteKeyParsed{};
        auto server_name = extract_string(*server_name_value);
        auto valid_until_ts = extract_integer(*valid_until_value);
        auto const* verify_keys_object = std::get_if<canonicaljson::Object>(&verify_keys_value->storage());
        auto const* signatures_object = std::get_if<canonicaljson::Object>(&signatures_value->storage());
        if (!server_name.has_value() || !valid_until_ts.has_value() || verify_keys_object == nullptr ||
            signatures_object == nullptr)
        {
            return std::nullopt;
        }
        record.server_name = std::move(*server_name);
        record.valid_until_ts = *valid_until_ts;

        for (auto const& key_member : *verify_keys_object)
        {
            auto const* key_object = std::get_if<canonicaljson::Object>(&key_member.value->storage());
            if (key_object == nullptr)
            {
                return std::nullopt;
            }
            auto const* key_value = find_member(*key_object, "key");
            if (key_value == nullptr)
            {
                return std::nullopt;
            }
            auto encoded = extract_string(*key_value);
            if (!encoded.has_value() || encoded->empty())
            {
                return std::nullopt;
            }
            record.verify_keys.push_back({key_member.key, std::move(*encoded)});
        }
        if (record.verify_keys.empty())
        {
            return std::nullopt;
        }

        auto const* server_signatures_value = find_member(*signatures_object, record.server_name);
        if (server_signatures_value == nullptr)
        {
            return std::nullopt;
        }
        auto const* server_signatures_object = std::get_if<canonicaljson::Object>(&server_signatures_value->storage());
        if (server_signatures_object == nullptr)
        {
            return std::nullopt;
        }
        for (auto const& signature_member : *server_signatures_object)
        {
            auto signature_text = extract_string(*signature_member.value);
            if (!signature_text.has_value())
            {
                continue;
            }
            record.server_signatures.emplace_back(signature_member.key, std::move(*signature_text));
        }
        if (record.server_signatures.empty())
        {
            return std::nullopt;
        }

        record.canonical_payload = canonicaljson::Value{strip_signatures(*root)};
        return record;
    }

    [[nodiscard]] auto verify_one_signature(std::string_view payload, std::string_view signature_base64,
                                            std::string_view public_key_base64) -> bool
    {
        if (sodium_init() < 0)
        {
            return false;
        }
        auto const signature_bytes = events::matrix_bytes_from_base64(signature_base64);
        auto const public_key_bytes = events::matrix_bytes_from_base64(public_key_base64);
        if (signature_bytes.size() != crypto_sign_BYTES || public_key_bytes.size() != crypto_sign_PUBLICKEYBYTES)
        {
            return false;
        }
        return crypto_sign_verify_detached(reinterpret_cast<unsigned char const*>(signature_bytes.data()),
                                           reinterpret_cast<unsigned char const*>(payload.data()), payload.size(),
                                           reinterpret_cast<unsigned char const*>(public_key_bytes.data())) == 0;
    }

} // namespace

auto parse_and_verify_remote_key_response(std::string_view body, std::string_view expected_server_name)
    -> RemoteKeyFetchResult
{
    auto parsed = parse_response(body);
    if (!parsed.has_value())
    {
        return {false, {}, "response is not a canonical Matrix server-key object"};
    }
    if (parsed->server_name != expected_server_name)
    {
        return {false, {}, "response server_name does not match expected server"};
    }
    if (!server_name_is_valid(parsed->server_name))
    {
        return {false, {}, "response server_name is malformed"};
    }
    if (parsed->valid_until_ts == 0U)
    {
        return {false, {}, "response valid_until_ts is zero"};
    }

    auto const canonical = canonicaljson::serialize_canonical(parsed->canonical_payload);
    if (canonical.error != canonicaljson::CanonicalJsonError::none)
    {
        return {false, {}, "response cannot be re-serialized canonically"};
    }

    // Every verify_keys entry must have its own valid self-signature. A single
    // valid signature proves the payload shape, but not provenance for an
    // additional key listed without a matching signature.
    for (auto const& verify_key : parsed->verify_keys)
    {
        auto const signature_iterator =
            std::ranges::find_if(parsed->server_signatures, [&verify_key](auto const& signature) {
                return signature.first == verify_key.key_id;
            });
        if (signature_iterator == parsed->server_signatures.end())
        {
            return {false, {}, "response included unsigned verify key " + verify_key.key_id};
        }
        if (!verify_one_signature(canonical.output, signature_iterator->second, verify_key.public_key_base64))
        {
            return {false, {}, "response signature failed verification for key " + verify_key.key_id};
        }
    }

    auto response = RemoteKeyResponse{};
    response.server_name = std::move(parsed->server_name);
    response.valid_until_ts = parsed->valid_until_ts;
    response.verify_keys = std::move(parsed->verify_keys);
    return {true, std::move(response), {}};
}

auto fetch_remote_server_keys(http::OutboundClient& client, ServerDiscoveryNetwork& network,
                              std::string_view server_name, std::uint32_t timeout_seconds) -> RemoteKeyFetchResult
{
    auto const discovery = discover_server(server_name, network, timeout_seconds);
    if (!discovery.discovery_allowed)
    {
        return {false, {}, discovery.reason.empty() ? "discovery failed" : discovery.reason};
    }
    auto url = std::string{"https://"};
    auto const needs_brackets =
        discovery.resolved_host.find(':') != std::string::npos && discovery.resolved_host.front() != '[';
    if (needs_brackets)
    {
        url += '[';
    }
    url += discovery.resolved_host;
    if (needs_brackets)
    {
        url += ']';
    }
    url += ':';
    url += std::to_string(discovery.resolved_port);
    url += key_endpoint;

    auto request = http::OutboundRequest{};
    request.method = "GET";
    request.url = std::move(url);
    request.pinned_addresses = discovery.pinned_addresses;
    request.connect_timeout_seconds = timeout_seconds;
    request.total_timeout_seconds = timeout_seconds;
    request.max_response_body_bytes = 64U * 1024U;

    auto const result = client.perform(request);
    if (!result.ok)
    {
        return {false, {}, result.error_detail.empty() ? "outbound key fetch failed" : result.error_detail};
    }
    if (result.response.status != 200U)
    {
        return {false, {}, "remote key endpoint returned status " + std::to_string(result.response.status)};
    }
    return parse_and_verify_remote_key_response(result.response.body, server_name);
}

auto remote_key_needs_refresh(std::uint64_t valid_until_ts, std::uint64_t now_ts) noexcept -> bool
{
    if (valid_until_ts == 0U)
    {
        return true;
    }
    if (now_ts >= valid_until_ts)
    {
        return true;
    }
    return (valid_until_ts - now_ts) <= refresh_slack_ms;
}

auto cache_remote_server_keys(database::PersistentStore& store, RemoteKeyResponse const& response) -> bool
{
    if (response.server_name.empty() || response.valid_until_ts == 0U)
    {
        return false;
    }
    auto all_ok = true;
    for (auto const& verify_key : response.verify_keys)
    {
        auto persistent = database::PersistentServerSigningKey{
            response.server_name,
            verify_key.key_id,
            verify_key.public_key_base64,
            response.valid_until_ts,
        };
        if (!database::store_server_signing_key(store, std::move(persistent)))
        {
            all_ok = false;
        }
    }
    return all_ok;
}

auto find_cached_remote_key(database::PersistentStore const& store, std::string_view server_name,
                            std::string_view key_id) -> std::optional<FederationKeyRecord>
{
    auto const persistent = database::find_server_signing_key(store, server_name, key_id);
    if (!persistent.has_value())
    {
        return std::nullopt;
    }
    auto record = FederationKeyRecord{};
    record.server_name = persistent->server_name;
    record.key_id = persistent->key_id;
    record.public_key_bytes = events::matrix_bytes_from_base64(persistent->public_key);
    record.valid_until_ts = persistent->valid_until_ts;
    if (record.public_key_bytes.size() != crypto_sign_PUBLICKEYBYTES)
    {
        return std::nullopt;
    }
    return record;
}

auto find_any_cached_remote_key(database::PersistentStore const& store, std::string_view server_name)
    -> std::optional<FederationKeyRecord>
{
    for (auto const& persistent : store.server_signing_keys)
    {
        if (persistent.server_name != server_name)
        {
            continue;
        }
        auto record = FederationKeyRecord{};
        record.server_name = persistent.server_name;
        record.key_id = persistent.key_id;
        record.public_key_bytes = events::matrix_bytes_from_base64(persistent.public_key);
        record.valid_until_ts = persistent.valid_until_ts;
        if (record.public_key_bytes.size() == crypto_sign_PUBLICKEYBYTES)
        {
            return record;
        }
    }
    return std::nullopt;
}

namespace
{

    // Emits a redaction-aware debug line so operators can see why a remote
    // failed to resolve. Resolution failures are otherwise invisible: the
    // resolver only ever returns std::nullopt, which the inbound handler
    // surfaces as a flat "remote is unknown" 403.
    auto log_resolver(std::string_view event, std::vector<observability::StructuredLogField> fields,
                      observability::LogEventSeverity severity = observability::LogEventSeverity::debug) -> void
    {
        observability::log_diagnostic("remote_key_resolver", event, fields, severity);
    }

    [[nodiscard]] auto default_wall_clock_ms() -> std::uint64_t
    {
        return static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
                .count());
    }

    [[nodiscard]] auto build_remote_runtime(std::string_view server_name, FederationKeyRecord signing_key,
                                            ServerDiscoveryResult discovery) -> FederationRemoteRuntime
    {
        auto runtime = FederationRemoteRuntime{};
        runtime.server_name = std::string{server_name};
        runtime.signing_key = std::move(signing_key);
        runtime.discovery.server_name = std::string{server_name};
        runtime.discovery.resolved_host = std::move(discovery.resolved_host);
        runtime.discovery.well_known_host =
            discovery.well_known_host.empty() ? runtime.discovery.resolved_host : std::move(discovery.well_known_host);
        runtime.discovery.resolved_addresses = std::move(discovery.pinned_addresses);
        runtime.discovery.tls_required = discovery.tls_required;
        runtime.trust.reputation_score = 100U;
        return runtime;
    }

} // namespace

auto make_persistent_remote_key_resolver(database::PersistentStore& store, http::OutboundClient& client,
                                         ServerDiscoveryNetwork& network, std::uint32_t timeout_seconds,
                                         RemoteKeyClock now_ms) -> RemoteKeyResolver
{
    // Fall back to the real wall clock when the caller passes an empty
    // callback. Returning 0 from a missing clock made every cached key look
    // fresh and prevented refresh-on-expiry from ever firing.
    auto clock = now_ms ? std::move(now_ms) : RemoteKeyClock{default_wall_clock_ms};
    return [&store, &client, &network, timeout_seconds, clock = std::move(clock)](
               std::string_view server_name, std::string_view key_id) -> std::optional<FederationRemoteRuntime> {
        auto const now = clock();
        auto cached_key = find_cached_remote_key(store, server_name, key_id);
        auto const discovery = discover_server(server_name, network, timeout_seconds);
        if (!discovery.discovery_allowed)
        {
            log_resolver("discovery_failed", {
                                                 {"server_name", std::string{server_name}, false},
                                                 {"reason",      discovery.reason,         false},
            });
        }
        if (cached_key.has_value() && !remote_key_needs_refresh(cached_key->valid_until_ts, now) &&
            discovery.discovery_allowed)
        {
            log_resolver("cache.hit", {
                                          {"server_name", std::string{server_name},                   false},
                                          {"key_id",      std::string{key_id},                        false},
                                          {"valid_until", std::to_string(cached_key->valid_until_ts), false}
            });
            return build_remote_runtime(server_name, std::move(*cached_key), discovery);
        }
        auto const fetched = fetch_remote_server_keys(client, network, server_name, timeout_seconds);
        if (!fetched.ok)
        {
            log_resolver("key_fetch_failed", {
                                                 {"server_name", std::string{server_name}, false},
                                                 {"reason",      fetched.reason,           false},
            });
        }
        if (fetched.ok)
        {
            log_resolver("key_fetch_accepted",
                         {
                             {"server_name", std::string{server_name},                            false},
                             {"key_count",   std::to_string(fetched.response.verify_keys.size()), false},
                             {"valid_until", std::to_string(fetched.response.valid_until_ts),     false}
            });
            std::ignore = cache_remote_server_keys(store, fetched.response);
            auto refreshed = find_cached_remote_key(store, server_name, key_id);
            if (refreshed.has_value() && discovery.discovery_allowed)
            {
                return build_remote_runtime(server_name, std::move(*refreshed), discovery);
            }
            if (!refreshed.has_value())
            {
                // The fetch and self-verification succeeded, but the key_id the
                // request was signed with is absent from the published set.
                log_resolver("request_key_id_not_published", {
                                                                 {"server_name", std::string{server_name}, false},
                                                                 {"key_id",      std::string{key_id},      false},
                });
            }
        }
        // Fall back to the (possibly expired) cached entry — a stale key still
        // lets the caller distinguish "we have history with this server" from
        // "we have never heard of it". Discovery must still succeed: a remote
        // we cannot reach SSRF-safely should not be admitted.
        if (cached_key.has_value() && discovery.discovery_allowed)
        {
            log_resolver("cache.stale_fallback",
                         {
                             {"server_name", std::string{server_name},                   false},
                             {"key_id",      std::string{key_id},                        false},
                             {"valid_until", std::to_string(cached_key->valid_until_ts), false}
            });
            return build_remote_runtime(server_name, std::move(*cached_key), discovery);
        }
        log_resolver("unresolved", {
                                       {"server_name", std::string{server_name}, false},
                                       {"key_id",      std::string{key_id},      false},
        });
        return std::nullopt;
    };
}

} // namespace merovingian::federation
