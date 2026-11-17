// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

// Helpers the `use_state_after` conformance and integration scenarios share: a runtime configuration, requests against
// the in-process client-server stack, and readers of a `/sync` response's rooms and state. They drive the runtime the
// caller started and assert with Catch2; they open nothing themselves.

#include "InMemoryDatabaseConfig.hpp"
#include "JsonTestSupport.hpp"
#include "MasterKey.hpp"
#include "RegistrationToken.hpp"
#include "merovingian/config/ClientRateLimitsConfig.hpp"
#include "merovingian/config/Config.hpp"
#include "merovingian/config/ListenersConfig.hpp"
#include "merovingian/config/LogModulesConfig.hpp"
#include "merovingian/config/SecurityConfig.hpp"
#include "merovingian/config/ServerConfig.hpp"
#include "merovingian/core/QueryParams.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace merovingian::tests::state_after_support
{

using merovingian::canonicaljson::Object;
using merovingian::homeserver::ClientServerRuntime;

constexpr auto k_state_after = std::string_view{"&use_state_after=true"};
constexpr auto k_state_before = std::string_view{"&use_state_after=false"};
constexpr auto k_no_filter = std::string_view{"{}"};
constexpr auto k_one_event = std::string_view{R"({"room":{"timeline":{"limit":1}}})"};
constexpr auto k_lazy = std::string_view{R"({"room":{"state":{"lazy_load_members":true}}})"};
constexpr auto k_lazy_one_event =
    std::string_view{R"({"room":{"timeline":{"limit":1},"state":{"lazy_load_members":true}}})"};
constexpr auto k_include_leave = std::string_view{R"({"room":{"include_leave":true}})"};

[[nodiscard]] inline auto state_after_config() -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    security.secrets.master_key_file = shared_master_key_file();
    enable_token_registration(security);
    return {
        merovingian::config::ServerConfig{},
        merovingian::config::ListenersConfig{},
        in_memory_database_config(),
        security,
        merovingian::config::ClientRateLimitsConfig{},
        merovingian::config::LogModulesConfig{},
    };
}

struct Reply final
{
    std::uint16_t status{0U};
    std::string body{};
};

[[nodiscard]] inline auto call(ClientServerRuntime& rt, std::string method, std::string target,
                               std::string const& token, std::string body = {}) -> Reply
{
    auto const result = merovingian::homeserver::handle_client_server_request(
        rt, {std::move(method), std::move(target), token, std::move(body)}, /*can_wait=*/false);
    return {static_cast<std::uint16_t>(result.response.status), result.response.body};
}

[[nodiscard]] inline auto user_id(std::string_view localpart) -> std::string
{
    return "@" + std::string{localpart} + ":example.org";
}

[[nodiscard]] inline auto register_user(ClientServerRuntime& rt, std::string const& localpart) -> std::string
{
    auto const registered =
        call(rt, "POST", "/_matrix/client/v3/register", {}, registration_json(localpart, "CorrectHorse7!"));
    REQUIRE(registered.status == 200U);
    return *string_member(parse_object(registered.body), "access_token");
}

[[nodiscard]] inline auto create_room(ClientServerRuntime& rt, std::string const& token, std::string const& preset)
    -> std::string
{
    auto const created = call(rt, "POST", "/_matrix/client/v3/createRoom", token, R"({"preset":")" + preset + R"("})");
    REQUIRE(created.status == 200U);
    return *string_member(parse_object(created.body), "room_id");
}

inline auto room_post(ClientServerRuntime& rt, std::string const& token, std::string const& room_id,
                      std::string const& action, std::string body = "{}") -> void
{
    REQUIRE(call(rt, "POST", "/_matrix/client/v3/rooms/" + room_id + "/" + action, token, std::move(body)).status ==
            200U);
}

inline auto say(ClientServerRuntime& rt, std::string const& token, std::string const& room_id, std::string const& text)
    -> void
{
    static auto counter = std::uint64_t{0U};
    auto const sent =
        call(rt, "PUT", "/_matrix/client/v3/rooms/" + room_id + "/send/m.room.message/sa" + std::to_string(++counter),
             token, R"({"msgtype":"m.text","body":")" + text + R"("})");
    REQUIRE(sent.status == 200U);
}

inline auto set_topic(ClientServerRuntime& rt, std::string const& token, std::string const& room_id,
                      std::string const& topic) -> std::string
{
    auto const sent = call(rt, "PUT", "/_matrix/client/v3/rooms/" + room_id + "/state/m.room.topic/", token,
                           R"({"topic":")" + topic + R"("})");
    REQUIRE(sent.status == 200U);
    return *string_member(parse_object(sent.body), "event_id");
}

inline auto set_display_name(ClientServerRuntime& rt, std::string const& token, std::string const& room_id,
                             std::string const& localpart, std::string const& name) -> void
{
    auto const sent =
        call(rt, "PUT", "/_matrix/client/v3/rooms/" + room_id + "/state/m.room.member/" + user_id(localpart), token,
             R"({"membership":"join","displayname":")" + name + R"("})");
    REQUIRE(sent.status == 200U);
}

struct Synced final
{
    Object body{};
    std::string next_batch{};
};

[[nodiscard]] inline auto sync(ClientServerRuntime& rt, std::string const& token, std::string_view filter,
                               std::string const& since = {}, std::string_view extra = {}) -> Synced
{
    auto target =
        std::string{"/_matrix/client/v3/sync?filter="} + merovingian::core::percent_encode_path_component(filter);
    if (!since.empty())
    {
        target += "&since=" + merovingian::core::percent_encode_path_component(since);
    }
    target += extra;
    auto const reply = call(rt, "GET", target, token);
    REQUIRE(reply.status == 200U);
    auto body = parse_object(reply.body);
    auto next = *string_member(body, "next_batch");
    return {std::move(body), std::move(next)};
}

// rooms.<section>.<room_id>, or nullptr.
[[nodiscard]] inline auto room_section(Synced const& synced, std::string_view section, std::string const& room_id)
    -> Object const*
{
    auto const* rooms = object_member_as_object(synced.body, "rooms");
    auto const* group = rooms == nullptr ? nullptr : object_member_as_object(*rooms, section);
    return group == nullptr ? nullptr : object_member_as_object(*group, room_id);
}

[[nodiscard]] inline auto required_room(Synced const& synced, std::string_view section, std::string const& room_id)
    -> Object const&
{
    auto const* room = room_section(synced, section, room_id);
    REQUIRE(room != nullptr);
    return *room;
}

// Whether `room` has the member `part`, whatever it holds.
[[nodiscard]] inline auto has_part(Object const& room, std::string_view part) -> bool
{
    return object_member(room, part) != nullptr;
}

// The events of `room.<part>`, which must be present.
[[nodiscard]] inline auto events_of(Object const& room, std::string_view part) -> std::vector<Object>
{
    auto const* section = object_member_as_object(room, part);
    REQUIRE(section != nullptr);
    auto const* events = object_member_as_array(*section, "events");
    REQUIRE(events != nullptr);
    auto out = std::vector<Object>{};
    for (auto const& entry : *events)
    {
        out.push_back(std::get<Object>(entry.storage()));
    }
    return out;
}

using Keys = std::multiset<std::string>;

[[nodiscard]] inline auto event_types(std::vector<Object> const& events) -> Keys
{
    auto types = Keys{};
    for (auto const& event : events)
    {
        types.insert(*string_member(event, "type"));
    }
    return types;
}

// The state_key of every m.room.member event.
[[nodiscard]] inline auto member_keys(std::vector<Object> const& events) -> Keys
{
    auto keys = Keys{};
    for (auto const& event : events)
    {
        if (*string_member(event, "type") == "m.room.member")
        {
            keys.insert(*string_member(event, "state_key"));
        }
    }
    return keys;
}

// `content.<field>` of the event of (type, state_key), or nullopt when `events` has none.
[[nodiscard]] inline auto content_of(std::vector<Object> const& events, std::string_view type,
                                     std::string_view state_key, std::string_view field) -> std::optional<std::string>
{
    for (auto const& event : events)
    {
        auto const* key = string_member(event, "state_key");
        if (*string_member(event, "type") == type && key != nullptr && *key == state_key)
        {
            auto const* content = object_member_as_object(event, "content");
            auto const* value = content == nullptr ? nullptr : string_member(*content, field);
            return value == nullptr ? std::optional<std::string>{} : std::optional<std::string>{*value};
        }
    }
    return std::nullopt;
}

// The `content.topic` of every m.room.topic event in `events`.
[[nodiscard]] inline auto topics_in(std::vector<Object> const& events) -> std::vector<std::string>
{
    auto topics = std::vector<std::string>{};
    for (auto const& event : events)
    {
        if (*string_member(event, "type") == "m.room.topic")
        {
            auto const* content = object_member_as_object(event, "content");
            topics.push_back(*string_member(*content, "topic"));
        }
    }
    return topics;
}

// The required section must exist, be an object and hold an `events` array, even an empty one (the spec's `State`).
inline auto require_state_section(Object const& room, std::string_view part) -> void
{
    REQUIRE(has_part(room, part));
    auto const* section = object_member_as_object(room, part);
    REQUIRE(section != nullptr);
    REQUIRE(object_member_as_array(*section, "events") != nullptr);
}

// The forbidden section is judged by presence: the key must not exist, whatever its value.
inline auto require_state_after_only(Object const& room) -> void
{
    require_state_section(room, "state_after");
    REQUIRE_FALSE(has_part(room, "state"));
}

inline auto require_state_only(Object const& room) -> void
{
    require_state_section(room, "state");
    REQUIRE_FALSE(has_part(room, "state_after"));
}

} // namespace merovingian::tests::state_after_support
