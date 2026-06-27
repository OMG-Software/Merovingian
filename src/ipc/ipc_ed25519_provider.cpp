// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/ipc/ipc_ed25519_provider.hpp"

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

    // Extract a JSON-escaped string value for `key`. Returns empty string on failure.
    auto json_get_str(std::string_view json, std::string_view key) -> std::string
    {
        auto const needle = std::string{"\""} + std::string{key} + "\":\"";
        auto const pos = json.find(needle);
        if (pos == std::string_view::npos)
        {
            return {};
        }
        auto i = pos + needle.size();
        auto result = std::string{};
        while (i < json.size())
        {
            auto const ch = json[i];
            if (ch == '"')
            {
                break;
            }
            if (ch == '\\' && i + 1 < json.size())
            {
                ++i;
                switch (json[i])
                {
                case '"':
                    result += '"';
                    break;
                case '\\':
                    result += '\\';
                    break;
                case 'b':
                    result += '\b';
                    break;
                case 'f':
                    result += '\f';
                    break;
                case 'n':
                    result += '\n';
                    break;
                case 'r':
                    result += '\r';
                    break;
                case 't':
                    result += '\t';
                    break;
                default:
                    result += json[i];
                    break;
                }
            }
            else
            {
                result += ch;
            }
            ++i;
        }
        return result;
    }

} // namespace

IpcEd25519Provider::IpcEd25519Provider(IpcChannel* channel)
    : channel_{channel}
{
}

auto IpcEd25519Provider::sign(crypto::Ed25519SecretKeyHandle const& key,
                              std::string_view message) -> crypto::SignatureResult
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

    auto const type = json_get_str(*reply, "type");
    if (type != "sign_response")
    {
        return {{}, "IpcEd25519Provider: unexpected response type: " + type};
    }

    auto const error = json_get_str(*reply, "error");
    if (!error.empty())
    {
        return {{}, "IpcEd25519Provider: main returned error: " + error};
    }

    auto const signature_b64 = json_get_str(*reply, "signature");
    if (signature_b64.empty())
    {
        return {{}, "IpcEd25519Provider: empty signature in response"};
    }

    auto const signature_bytes = events::matrix_bytes_from_base64(signature_b64);
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
