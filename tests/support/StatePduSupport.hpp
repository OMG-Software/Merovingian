// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

// Builds an inbound state PDU of a version 12 room for `homeserver::ingest_pdu_event`, with its content hash and no
// signatures, so a scenario can lay out an event graph (a fork, a resolution that moves a key back) through the real
// ingestion path. The caller chooses the event ID, the `prev_events`, the `auth_events` and the timestamp, which is the
// tie-break state resolution v2 applies between two non-power events at the same mainline position.

#include "merovingian/canonicaljson/CanonicalJsonError.hpp"
#include "merovingian/canonicaljson/ObjectMember.hpp"
#include "merovingian/canonicaljson/Serializer.hpp"
#include "merovingian/canonicaljson/Value.hpp"
#include "merovingian/events/EventId.hpp"
#include "merovingian/federation/InboundPduEnvelope.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace merovingian::tests::state_pdu_support
{

// A state event of `type` with `state_key` "" and `content`, at depth 10.
[[nodiscard]] inline auto make_state_pdu(std::string const& room_id, std::string const& event_id,
                                         std::string const& sender, std::string const& type,
                                         canonicaljson::Object content, std::vector<std::string> const& prev_event_ids,
                                         std::vector<std::string> const& auth_event_ids, std::int64_t ts)
    -> federation::InboundPduEnvelope
{
    auto obj = canonicaljson::Object{};
    obj.push_back(canonicaljson::make_member("type", canonicaljson::Value{type}));
    obj.push_back(canonicaljson::make_member("state_key", canonicaljson::Value{std::string{}}));
    obj.push_back(canonicaljson::make_member("room_id", canonicaljson::Value{room_id}));
    obj.push_back(canonicaljson::make_member("sender", canonicaljson::Value{sender}));
    obj.push_back(canonicaljson::make_member("content", canonicaljson::Value{std::move(content)}));
    obj.push_back(canonicaljson::make_member("origin_server_ts", canonicaljson::Value{ts}));
    obj.push_back(canonicaljson::make_member("depth", canonicaljson::Value{std::int64_t{10}}));
    auto prev_arr = canonicaljson::Array{};
    for (auto const& id : prev_event_ids)
    {
        prev_arr.push_back(canonicaljson::Value{id});
    }
    obj.push_back(canonicaljson::make_member("prev_events", canonicaljson::Value{std::move(prev_arr)}));
    auto auth_arr = canonicaljson::Array{};
    for (auto const& id : auth_event_ids)
    {
        auth_arr.push_back(canonicaljson::Value{id});
    }
    obj.push_back(canonicaljson::make_member("auth_events", canonicaljson::Value{std::move(auth_arr)}));

    auto const hash = events::make_content_hash(canonicaljson::Value{obj});
    REQUIRE(hash.error.empty());
    auto hashes = canonicaljson::Object{};
    hashes.push_back(canonicaljson::make_member("sha256", canonicaljson::Value{hash.sha256}));
    obj.push_back(canonicaljson::make_member("hashes", canonicaljson::Value{std::move(hashes)}));

    auto const serialized = canonicaljson::serialize_canonical(canonicaljson::Value{std::move(obj)});
    REQUIRE(serialized.error == canonicaljson::CanonicalJsonError::none);

    auto env = federation::InboundPduEnvelope{};
    env.event_id = event_id;
    env.room_id = room_id;
    env.room_version = "12";
    env.sender = sender;
    env.event_type = type;
    env.state_key = std::string{};
    env.origin_server_ts = ts;
    env.depth = 10U;
    env.prev_event_ids = prev_event_ids;
    env.auth_event_ids = auth_event_ids;
    env.json = serialized.output;
    return env;
}

// An `m.room.topic` event whose topic is `topic`.
[[nodiscard]] inline auto make_topic_pdu(std::string const& room_id, std::string const& event_id,
                                         std::string const& sender, std::string const& topic,
                                         std::vector<std::string> const& prev_event_ids,
                                         std::vector<std::string> const& auth_event_ids, std::int64_t ts)
    -> federation::InboundPduEnvelope
{
    auto content = canonicaljson::Object{};
    content.push_back(canonicaljson::make_member("topic", canonicaljson::Value{topic}));
    return make_state_pdu(room_id, event_id, sender, "m.room.topic", std::move(content), prev_event_ids, auth_event_ids,
                          ts);
}

} // namespace merovingian::tests::state_pdu_support
