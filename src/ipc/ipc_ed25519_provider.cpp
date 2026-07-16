// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/ipc/ipc_ed25519_provider.hpp"

#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/events/event_signer.hpp"
#include "merovingian/ipc/channel.hpp"
#include "merovingian/observability/logger.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

namespace merovingian::ipc
{

namespace
{

    // Minimal JSON string escaping used for the sign_request payload.
    auto json_str(std::string_view s) -> std::string
    {
        auto result = std::string{};
        result.reserve(s.size() + 2U);
        result += '"';
        for (auto const raw_ch : s)
        {
            auto const ch = static_cast<unsigned char>(raw_ch);
            switch (ch)
            {
            case '"':
                result += "\\\"";
                break;
            case '\\':
                result += "\\\\";
                break;
            case '\b':
                result += "\\b";
                break;
            case '\f':
                result += "\\f";
                break;
            case '\n':
                result += "\\n";
                break;
            case '\r':
                result += "\\r";
                break;
            case '\t':
                result += "\\t";
                break;
            default:
                if (ch < 0x20U)
                {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", static_cast<unsigned>(ch));
                    result += buf;
                }
                else
                {
                    result += static_cast<char>(ch);
                }
                break;
            }
        }
        result += '"';
        return result;
    }

    // Typed JSON accessors used to read sign_response fields.  These replace the
    // previous hand-rolled substring scanner so Unicode escapes and nested content
    // cannot confuse the extractor.
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
        if (value == nullptr)
        {
            return nullptr;
        }
        return std::get_if<std::string>(&value->storage());
    }

} // namespace

IpcEd25519Provider::IpcEd25519Provider(IpcChannel* channel)
    : channel_{channel}
{
}

auto IpcEd25519Provider::sign(crypto::Ed25519SecretKeyHandle const& key, std::string_view message)
    -> crypto::SignatureResult
{
    if (channel_ == nullptr)
    {
        return {{}, "IpcEd25519Provider: no IPC channel"};
    }

    auto body = std::string{};
    body.reserve(64U + message.size() + key.key_id.size());
    body += R"({"type":"sign_request","key_id":)";
    body += json_str(key.key_id);
    body += R"(,"canonical_json":)";
    body += json_str(message);
    body += '}';

    auto const reply = channel_->send_request(body, std::chrono::seconds{30});
    if (!reply.has_value())
    {
        return {{}, "IpcEd25519Provider: sign_request IPC timeout or failure"};
    }

    auto const parsed = canonicaljson::parse_json(*reply);
    if (parsed.error != canonicaljson::ParseError::none)
    {
        return {{}, "IpcEd25519Provider: malformed sign_response JSON"};
    }
    auto const* root = std::get_if<canonicaljson::Object>(&parsed.value.storage());
    if (root == nullptr)
    {
        return {{}, "IpcEd25519Provider: sign_response body is not a JSON object"};
    }

    auto const* type = string_member(*root, "type");
    if (type == nullptr || *type != "sign_response")
    {
        auto const type_str = type == nullptr ? std::string{} : *type;
        return {{}, "IpcEd25519Provider: unexpected response type: " + type_str};
    }

    auto const* error = string_member(*root, "error");
    if (error != nullptr && !error->empty())
    {
        return {{}, "IpcEd25519Provider: main returned error: " + *error};
    }

    auto const* signature_b64 = string_member(*root, "signature");
    if (signature_b64 == nullptr || signature_b64->empty())
    {
        return {{}, "IpcEd25519Provider: empty signature in response"};
    }

    auto const signature_bytes = events::matrix_bytes_from_base64(*signature_b64);
    if (signature_bytes.size() != crypto_sign_BYTES)
    {
        return {{}, "IpcEd25519Provider: invalid signature shape from main"};
    }

    return {crypto::Ed25519Signature{std::move(signature_bytes)}, {}};
}

auto IpcEd25519Provider::verify(crypto::Ed25519PublicKey const& /*public_key*/, std::string_view /*message*/,
                                crypto::Ed25519Signature const& /*signature*/) -> crypto::VerificationResult
{
    // The federation worker never verifies Ed25519 signatures; all verification
    // happens in the main process. Reaching this path is a programming error.
    LOG_CRITICAL("IpcEd25519Provider::verify is unsupported in the federation worker");
    std::terminate();
}

} // namespace merovingian::ipc
