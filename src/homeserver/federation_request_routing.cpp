// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/federation_request_routing.hpp"

#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/core/query_params.hpp"

#include <cstdint>
#include <string_view>
#include <utility>
#include <vector>

namespace merovingian::homeserver
{

namespace
{

    // Typed JSON accessors used to read room_id from /send bodies.  These avoid
    // the substring/escape pitfalls of the previous hand-rolled scanner.
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

    [[nodiscard]] auto array_member(canonicaljson::Object const& object, std::string_view key) noexcept
        -> canonicaljson::Array const*
    {
        auto const* value = object_member(object, key);
        if (value == nullptr)
        {
            return nullptr;
        }
        return std::get_if<canonicaljson::Array>(&value->storage());
    }

    // Federation endpoints where the room ID is a path segment. Order is not
    // important: the longest matching prefix is not required because the room ID
    // is always the first variable segment after the fixed prefix.
    [[nodiscard]] auto room_endpoint_prefixes() noexcept -> std::vector<std::string_view>
    {
        static auto const prefixes = std::vector<std::string_view>{
            "/_matrix/federation/v1/state/",
            "/_matrix/federation/v1/state_ids/",
            "/_matrix/federation/v1/invite/",
            "/_matrix/federation/v1/invite2/",
            "/_matrix/federation/v1/event_auth/",
            "/_matrix/federation/v1/backfill/",
            "/_matrix/federation/v1/get_missing_events/",
            "/_matrix/federation/v1/make_join/",
            "/_matrix/federation/v1/send_join/",
            "/_matrix/federation/v1/make_leave/",
            "/_matrix/federation/v1/send_leave/",
            "/_matrix/federation/v1/make_knock/",
            "/_matrix/federation/v1/send_knock/",
            // Deliberately no entry for /_matrix/federation/v1/query/directory:
            // per spec its room_alias is a query parameter, not a path segment
            // (GET .../query/directory?room_alias=...), so a path-prefix entry
            // here can never match a real request — it would be dead code, not
            // a fix. Hashing the alias wouldn't be correct anyway: it's an
            // unrelated string to the room_id notify_room_changed() partitions
            // by, and reload_room() doesn't sync room_aliases per-room today.
            // Tracked as a follow-up requiring a real design decision, not a
            // one-line patch (see docs/architecture.md, "Federation worker
            // room staleness"). Until then this endpoint always routes to
            // shard 0, same as any other non-room request.
            // v2 endpoints — required for correct shard routing; without these,
            // v2 requests fall through with no room_id and land on shard 0
            // regardless of which shard owns the room.
            "/_matrix/federation/v2/invite/",
            "/_matrix/federation/v2/send_join/",
            "/_matrix/federation/v2/send_leave/",
            "/_matrix/federation/v2/make_knock/",
            "/_matrix/federation/v2/send_knock/",
        };
        return prefixes;
    }

    // For /send/{txnId} the room ID is inside the request body. We parse the
    // whole body and extract the first PDU's room_id. All PDUs in a transaction
    // are for the same room in practice; routing by the first PDU is sufficient
    // for shard selection.  Using the canonical JSON parser avoids the escape
    // and substring pitfalls of the previous hand-rolled scanner.
    [[nodiscard]] auto room_id_from_send_body(std::string_view body) -> std::string
    {
        auto const parsed = canonicaljson::parse_json(body);
        if (parsed.error != canonicaljson::ParseError::none)
        {
            return {};
        }
        auto const* root = std::get_if<canonicaljson::Object>(&parsed.value.storage());
        if (root == nullptr)
        {
            return {};
        }
        auto const* pdus = array_member(*root, "pdus");
        if (pdus == nullptr || pdus->empty())
        {
            return {};
        }
        auto const* first_pdu = std::get_if<canonicaljson::Object>(&(*pdus)[0].storage());
        if (first_pdu == nullptr)
        {
            return {};
        }
        auto const* room_id = string_member(*first_pdu, "room_id");
        if (room_id == nullptr)
        {
            return {};
        }
        return *room_id;
    }

    [[nodiscard]] auto room_id_from_path_target(std::string_view target) -> std::string
    {
        for (auto const prefix : room_endpoint_prefixes())
        {
            if (target.size() > prefix.size() && target.substr(0U, prefix.size()) == prefix)
            {
                auto const remainder = target.substr(prefix.size());
                // Stop at next path separator or query string.
                auto const end = remainder.find_first_of("/?");
                // Room IDs contain '!' (and aliases '#'), which HTTP clients
                // percent-encode as a path segment (e.g. "%21room:example.com").
                // Decode before hashing for shard routing, otherwise this room
                // ID never matches the plain-text room_id used by
                // notify_room_changed()/room_service, and the request lands on
                // a shard that was never synced for this room — every
                // room-scoped federation request (make_join, send_join, ...)
                // 404s even though the room exists locally.
                return core::percent_decode_path_component(remainder.substr(0U, end));
            }
        }
        return {};
    }

    [[nodiscard]] auto is_federation_send_target(std::string_view target) noexcept -> bool
    {
        return target.find("/_matrix/federation/v1/send/") != std::string_view::npos;
    }

} // namespace

auto federation_worker_room_id_from_request(LocalHttpRequest const& request) -> std::string
{
    if (is_federation_send_target(request.target))
    {
        return room_id_from_send_body(request.body);
    }
    return room_id_from_path_target(request.target);
}

auto federation_request_should_bypass_worker(LocalHttpRequest const& request) -> bool
{
    // EDU-only /send transactions have no room_id to shard by and ultimately
    // relay back to main's edu_sink anyway. Handling them in main avoids shard
    // 0 becoming a choke point for to-device key shares.
    if (request.method == "PUT" && is_federation_send_target(request.target) &&
        room_id_from_send_body(request.body).empty())
    {
        return true;
    }
    // Media download needs the local media repository, which lives only in the
    // main process. The worker has no access to local blobs, so keep this route
    // on main even when the federation worker pool is active.
    if (request.method == "GET" && request.target.find("/_matrix/federation/v1/media/download/") == 0U)
    {
        return true;
    }
    return false;
}

auto is_federation_key_server_endpoint(std::string_view target) noexcept -> bool
{
    // The key server endpoint is the only inbound federation route that main
    // processes without worker involvement or X-Matrix signature verification.
    // It must match the full path exactly; anything else (including a longer
    // path that merely contains the same substring) must follow the normal
    // worker/verify path so that authorization checks run and routing is not
    // accidentally bypassed.
    auto const query_pos = target.find('?');
    auto const path = target.substr(0U, query_pos);
    return path == "/_matrix/key/v2/server";
}

} // namespace merovingian::homeserver
