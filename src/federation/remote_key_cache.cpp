// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/federation/remote_key_cache.hpp"

#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/serializer.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/crypto/ed25519.hpp"
#include "merovingian/events/event_signer.hpp"
#include "merovingian/federation/security.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <optional>
#include <string>
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
        auto const* server_signatures_object =
            std::get_if<canonicaljson::Object>(&server_signatures_value->storage());
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

    // At least one signature under signatures.<server_name>.<key_id> must
    // verify against the corresponding verify_keys.<key_id> public key. The
    // Matrix spec requires the response to be signed by *every* listed key.
    auto verified_at_least_one = false;
    for (auto const& [signature_key_id, signature_base64] : parsed->server_signatures)
    {
        auto const verify_key_iterator =
            std::ranges::find_if(parsed->verify_keys, [&signature_key_id](RemoteVerifyKey const& verify_key) {
                return verify_key.key_id == signature_key_id;
            });
        if (verify_key_iterator == parsed->verify_keys.end())
        {
            continue;
        }
        if (!verify_one_signature(canonical.output, signature_base64, verify_key_iterator->public_key_base64))
        {
            return {false, {}, "response signature failed verification for key " + signature_key_id};
        }
        verified_at_least_one = true;
    }
    if (!verified_at_least_one)
    {
        return {false, {}, "response did not include a verifiable self-signature"};
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

auto make_persistent_remote_key_resolver(database::PersistentStore& store, http::OutboundClient& client,
                                         ServerDiscoveryNetwork& network, std::uint32_t timeout_seconds,
                                         RemoteKeyClock now_ms) -> RemoteKeyResolver
{
    return [&store, &client, &network, timeout_seconds, now_ms = std::move(now_ms)](
               std::string_view server_name, std::string_view key_id) -> std::optional<FederationKeyRecord> {
        auto const now = now_ms ? now_ms() : std::uint64_t{0U};
        auto cached = find_cached_remote_key(store, server_name, key_id);
        if (cached.has_value() && !remote_key_needs_refresh(cached->valid_until_ts, now))
        {
            return cached;
        }
        auto const fetched = fetch_remote_server_keys(client, network, server_name, timeout_seconds);
        if (fetched.ok)
        {
            (void)cache_remote_server_keys(store, fetched.response);
            auto refreshed = find_cached_remote_key(store, server_name, key_id);
            if (refreshed.has_value())
            {
                return refreshed;
            }
        }
        // Fall back to the (possibly expired) cached entry rather than failing
        // outright — a stale key still lets the caller distinguish "we have
        // history with this server" from "we have never heard of it".
        return cached;
    };
}

} // namespace merovingian::federation
