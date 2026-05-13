// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/canonicaljson/serializer.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/events/event.hpp"

#include <string>
#include <string_view>

namespace merovingian::events
{

struct SigningKeyId final
{
    std::string server_name{};
    std::string key_id{};
};

struct SignatureVerificationResult final
{
    bool valid{false};
    std::string error{};
};

[[nodiscard]] auto signing_key_id_is_valid(SigningKeyId const& key_id) noexcept -> bool;
[[nodiscard]] auto make_event_signing_payload(canonicaljson::Value const& event) -> canonicaljson::SerializeResult;
[[nodiscard]] auto attach_event_signature(
    canonicaljson::Value const& event,
    SigningKeyId const& key_id,
    std::string_view signature
) -> canonicaljson::SerializeResult;
[[nodiscard]] auto verify_event_signature_presence(
    canonicaljson::Value const& event,
    SigningKeyId const& key_id
) -> SignatureVerificationResult;

} // namespace merovingian::events
