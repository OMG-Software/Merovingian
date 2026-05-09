// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <merovingian/canonicaljson/value.hpp>

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace merovingian::events
{

struct EventSignature final
{
    std::string server_name{};
    std::string key_id{};
    std::string signature{};
};

struct EventEnvelope final
{
    canonicaljson::Value json{};
    std::string room_id{};
    std::string event_type{};
    std::string sender{};
    std::string state_key{};
    std::int64_t origin_server_ts{0};
    std::vector<EventSignature> signatures{};
};

struct EventParseResult final
{
    EventEnvelope event{};
    std::string error{};
};

[[nodiscard]] auto matrix_id_is_valid(std::string_view id, char sigil) noexcept -> bool;
[[nodiscard]] auto event_type_is_valid(std::string_view type) noexcept -> bool;
[[nodiscard]] auto parse_event_envelope(canonicaljson::Value const& json) -> EventParseResult;

} // namespace merovingian::events
