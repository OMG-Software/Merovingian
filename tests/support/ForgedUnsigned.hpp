// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/canonicaljson/CanonicalJsonError.hpp"
#include "merovingian/canonicaljson/ParseError.hpp"
#include "merovingian/canonicaljson/Value.hpp"
#include "merovingian/canonicaljson/Parser.hpp"
#include "merovingian/canonicaljson/Serializer.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <utility>
#include <variant>

namespace merovingian::tests
{

// The `unsigned` a hostile relaying server writes into a PDU: every key this server serves to clients
// as its own (ADR-0402).
inline constexpr auto forged_unsigned_json =
    R"({"age":1,"forged_extra":"x","m.relations":{"m.replace":{"content":{"body":"* forged"},"event_id":"$fake","sender":"@bob:remote.example.org","type":"m.room.message"}},"membership":"ban","prev_content":{"topic":"forged previous"},"redacted_because":{"content":{},"sender":"@admin:local.example.org","type":"m.room.redaction"},"transaction_id":"forged-txn"})";

// `signed_json` with `forged_unsigned_json` as its top-level `unsigned`. The signatures, the content
// hash and the event ID do not cover it (SS API "Signing events"), so the PDU still verifies.
[[nodiscard]] inline auto with_forged_unsigned(std::string const& signed_json) -> std::string
{
    auto parsed = canonicaljson::parse_lossless(signed_json);
    REQUIRE(parsed.error == canonicaljson::ParseError::none);
    auto object = std::get<canonicaljson::Object>(parsed.value.storage());
    auto forged = canonicaljson::parse_lossless(forged_unsigned_json);
    REQUIRE(forged.error == canonicaljson::ParseError::none);
    object.push_back(canonicaljson::make_member("unsigned", std::move(forged.value)));
    auto const serialized = canonicaljson::serialize_canonical(canonicaljson::Value{std::move(object)});
    REQUIRE(serialized.error == canonicaljson::CanonicalJsonError::none);
    return serialized.output;
}

} // namespace merovingian::tests
