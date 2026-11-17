// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#include "merovingian/crypto/LiveKitToken.hpp"

#include "merovingian/crypto/ConstantTime.hpp"
#include "merovingian/crypto/Encoding.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <string>
#include <string_view>
#include <utility>

#include <sodium.h>

namespace merovingian::crypto
{
namespace
{

constexpr auto mac_bytes = std::size_t{crypto_auth_hmacsha256_BYTES};
constexpr auto livekit_name_bytes = std::size_t{43U};
// The header every token signed here carries. It is never read back from a token: `verify_hs256_token` returns the
// header it received for the caller to judge, and checks HMAC-SHA256 whatever the header says.
constexpr auto hs256_header_json = std::string_view{R"({"alg":"HS256","typ":"JWT"})"};

[[nodiscard]] auto is_ascii_alnum(char const character) noexcept -> bool
{
    return (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
           (character >= '0' && character <= '9');
}

// HMAC-SHA256 of `message` under `key`. The init/update/final form takes a key of any length, as JWT HS256 requires
// (RFC 7518 3.2); `crypto_auth_hmacsha256` alone takes exactly 32 bytes.
[[nodiscard]] auto hmac_sha256(std::span<std::uint8_t const> key, std::string_view message)
    -> std::optional<std::array<unsigned char, mac_bytes>>
{
    if (sodium_init() < 0)
    {
        return std::nullopt;
    }
    auto state = crypto_auth_hmacsha256_state{};
    auto mac = std::array<unsigned char, mac_bytes>{};
    auto const ok = crypto_auth_hmacsha256_init(&state, key.data(), key.size()) == 0 &&
                    crypto_auth_hmacsha256_update(&state, reinterpret_cast<unsigned char const*>(message.data()),
                                                  message.size()) == 0 &&
                    crypto_auth_hmacsha256_final(&state, mac.data()) == 0;
    // The state holds the key's inner and outer pads.
    sodium_memzero(&state, sizeof(state));
    if (!ok)
    {
        sodium_memzero(mac.data(), mac.size());
        return std::nullopt;
    }
    return mac;
}

[[nodiscard]] auto as_string_view(std::array<unsigned char, mac_bytes> const& mac) noexcept -> std::string_view
{
    return {reinterpret_cast<char const*>(mac.data()), mac.size()};
}

// `header.payload.signature` for `payload_json`, whose every value the caller validated so that it needs no escaping.
[[nodiscard]] auto sign_payload(std::span<std::uint8_t const> api_secret, std::string_view payload_json)
    -> std::optional<std::string>
{
    if (api_secret.size() < livekit_api_secret_min_bytes)
    {
        return std::nullopt;
    }
    auto header = base64_urlsafe_encode(hs256_header_json);
    auto payload = base64_urlsafe_encode(payload_json);
    if (!header || !payload)
    {
        return std::nullopt;
    }
    // Element Call reads the payload with `atob`, which knows only the standard alphabet. The claims hold only ASCII
    // letters, digits and `{}":,+/._-`, none of which can put a 62 or 63 in a base64 group, so this never fires; it is
    // the guarantee stated where it is relied on.
    if (payload->find_first_of("-_") != std::string::npos)
    {
        return std::nullopt;
    }
    auto signing_input = std::move(*header);
    signing_input += '.';
    signing_input += *payload;
    auto const mac = hmac_sha256(api_secret, signing_input);
    if (!mac)
    {
        return std::nullopt;
    }
    auto signature = base64_urlsafe_encode(as_string_view(*mac));
    if (!signature)
    {
        return std::nullopt;
    }
    signing_input += '.';
    signing_input += *signature;
    return signing_input;
}

[[nodiscard]] auto times_are_valid(std::int64_t const not_before, std::int64_t const expires) noexcept -> bool
{
    return not_before >= 0 && expires > not_before;
}

} // namespace

auto livekit_api_key_is_valid(std::string_view const api_key) noexcept -> bool
{
    return !api_key.empty() && api_key.size() <= livekit_api_key_max_bytes &&
           std::ranges::all_of(api_key, [](char const character) {
               return is_ascii_alnum(character) || character == '_' || character == '-' || character == '.';
           });
}

auto livekit_name_is_valid(std::string_view const value) noexcept -> bool
{
    return value.size() == livekit_name_bytes && std::ranges::all_of(value, [](char const character) {
               return is_ascii_alnum(character) || character == '+' || character == '/';
           });
}

auto sign_livekit_participant_token(std::string_view const api_key, std::span<std::uint8_t const> const api_secret,
                                    LiveKitParticipantGrant const& grant) -> std::optional<std::string>
{
    if (!livekit_api_key_is_valid(api_key) || !livekit_name_is_valid(grant.identity) ||
        !livekit_name_is_valid(grant.room) || !times_are_valid(grant.not_before, grant.expires))
    {
        return std::nullopt;
    }
    auto const publish = std::string_view{grant.can_publish ? "true" : "false"};
    // Keys in lexical order, as canonical JSON would put them; LiveKit does not care, a reader of a token might.
    auto payload = std::string{R"({"exp":)"};
    payload += std::to_string(grant.expires);
    payload += R"(,"iss":")";
    payload += api_key;
    payload += R"(","nbf":)";
    payload += std::to_string(grant.not_before);
    payload += R"(,"sub":")";
    payload += grant.identity;
    payload += R"(","video":{"canPublish":)";
    payload += publish;
    payload += R"(,"canPublishData":)";
    payload += publish;
    payload += R"(,"canSubscribe":true,"room":")";
    payload += grant.room;
    payload += R"(","roomJoin":true}})";
    return sign_payload(api_secret, payload);
}

auto sign_livekit_room_create_token(std::string_view const api_key, std::span<std::uint8_t const> const api_secret,
                                    std::int64_t const not_before, std::int64_t const expires)
    -> std::optional<std::string>
{
    if (!livekit_api_key_is_valid(api_key) || !times_are_valid(not_before, expires))
    {
        return std::nullopt;
    }
    auto payload = std::string{R"({"exp":)"};
    payload += std::to_string(expires);
    payload += R"(,"iss":")";
    payload += api_key;
    payload += R"(","nbf":)";
    payload += std::to_string(not_before);
    payload += R"(,"video":{"roomCreate":true}})";
    return sign_payload(api_secret, payload);
}

auto verify_hs256_token(std::string_view const token, std::span<std::uint8_t const> const secret)
    -> std::optional<VerifiedHs256Token>
{
    if (secret.size() < livekit_api_secret_min_bytes || token.size() > hs256_token_max_bytes)
    {
        return std::nullopt;
    }
    auto const first_dot = token.find('.');
    if (first_dot == std::string_view::npos)
    {
        return std::nullopt;
    }
    auto const second_dot = token.find('.', first_dot + 1U);
    if (second_dot == std::string_view::npos || token.find('.', second_dot + 1U) != std::string_view::npos)
    {
        return std::nullopt;
    }
    auto const header_segment = token.substr(0U, first_dot);
    auto const payload_segment = token.substr(first_dot + 1U, second_dot - first_dot - 1U);
    auto const signature_segment = token.substr(second_dot + 1U);
    if (header_segment.empty() || payload_segment.empty() || signature_segment.empty())
    {
        return std::nullopt;
    }
    auto const signature = base64_urlsafe_decode(signature_segment);
    if (!signature || signature->size() != mac_bytes)
    {
        return std::nullopt;
    }
    // The MAC covers the segments as received, so nothing is decoded before it is checked.
    auto const mac = hmac_sha256(secret, token.substr(0U, second_dot));
    if (!mac || !constant_time_equal(as_string_view(*mac), *signature))
    {
        return std::nullopt;
    }
    auto header = base64_urlsafe_decode(header_segment);
    auto payload = base64_urlsafe_decode(payload_segment);
    if (!header || !payload)
    {
        return std::nullopt;
    }
    return VerifiedHs256Token{.header_json = std::move(*header), .payload_json = std::move(*payload)};
}

} // namespace merovingian::crypto
