// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/federation_request_routing.hpp"

#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/core/query_params.hpp"
#include "merovingian/federation/transactions.hpp"
#include "merovingian/homeserver/client_server.hpp"

#include <cstdint>
#include <optional>
#include <string>
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

    // An absent shard key is not proof that a transaction contains no PDUs.
    // Only an explicitly empty PDU array is safe for the EDU-only fast path.
    [[nodiscard]] auto send_body_has_empty_pdus(std::string_view body) -> bool
    {
        auto const parsed = canonicaljson::parse_json(body);
        if (parsed.error != canonicaljson::ParseError::none ||
            !std::holds_alternative<canonicaljson::Object>(parsed.value.storage()))
        {
            return false;
        }
        auto const* pdus = array_member(std::get<canonicaljson::Object>(parsed.value.storage()), "pdus");
        return pdus != nullptr && pdus->empty();
    }

    // For /send/{txnId}, use the first PDU's room_id as a shard hint only.
    // If it is malformed, leave the key empty so the whole transaction goes to
    // shard 0, rather than inspecting later PDUs or bypassing the worker.
    // Using the canonical JSON parser avoids escape and substring pitfalls.
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
        // Match against the path component only (#453): a substring scan over
        // the whole target let a query string like ?x=/_matrix/federation/v1/send/y
        // misclassify an unrelated endpoint as an EDU-only /send and bypass
        // the worker.
        auto const path = target.substr(0U, target.find('?'));
        return path.starts_with("/_matrix/federation/v1/send/");
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
    // EDU-only /send transactions relay back to main's edu_sink anyway.
    // Require an explicitly empty PDU array: a missing or malformed first
    // room_id must never bring the transaction's later PDUs into main.
    // Handling EDU-only sends in main avoids shard 0 becoming a choke point.
    if (request.method == "PUT" && is_federation_send_target(request.target) && send_body_has_empty_pdus(request.body))
    {
        return true;
    }
    // Media download needs the local media repository, which lives only in the
    // main process. The worker has no access to local blobs, so keep this route
    // on main even when the federation worker pool is active.
    if (request.method == "GET" && (request.target.find("/_matrix/federation/v1/media/download/") == 0U ||
                                    request.target.find("/_matrix/federation/v1/media/thumbnail/") == 0U))
    {
        return true;
    }
    return false;
}

auto federation_worker_room_read_may_fallback_to_main(LocalHttpRequest const& request) noexcept -> bool
{
    if (request.method != "GET")
    {
        return false;
    }
    auto const path = request.target.substr(0U, request.target.find('?'));
    static auto const prefixes = std::vector<std::string_view>{
        "/_matrix/federation/v1/state/",      "/_matrix/federation/v1/state_ids/",
        "/_matrix/federation/v1/backfill/",   "/_matrix/federation/v1/get_missing_events/",
        "/_matrix/federation/v1/event_auth/",
    };
    return std::ranges::any_of(prefixes, [&path](std::string_view prefix) {
        return path.starts_with(prefix);
    });
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

auto is_federation_openid_userinfo_endpoint(std::string_view target) noexcept -> bool
{
    auto const query_pos = target.find('?');
    auto const path = target.substr(0U, query_pos);
    return path == "/_matrix/federation/v1/openid/userinfo";
}

auto is_federation_version_endpoint(std::string_view target) noexcept -> bool
{
    auto const query_pos = target.find('?');
    auto const path = target.substr(0U, query_pos);
    return path == "/_matrix/federation/v1/version";
}

auto federation_unsupported_method_allow(std::string_view method, std::string_view target) -> std::optional<std::string>
{
    auto const path = target.substr(0U, target.find('?'));
    // The endpoints answered without an X-Matrix signature are GET only.
    if (path == "/_matrix/key/v2/server" || path == "/_matrix/federation/v1/version" ||
        path == "/_matrix/federation/v1/openid/userinfo")
    {
        return method == "GET" ? std::nullopt : std::optional<std::string>{"GET"};
    }
    if (federation::match_federation_route(method, target).matched)
    {
        return std::nullopt;
    }
    auto const methods = federation::federation_methods_for_path(target);
    if (methods.empty())
    {
        return std::nullopt;
    }
    auto allow = std::string{};
    for (auto const& served : methods)
    {
        if (!allow.empty())
        {
            allow.append(", ");
        }
        allow.append(served);
    }
    return allow;
}

auto federation_method_not_allowed_response(std::string_view allow) -> LocalHttpResponse
{
    auto response = LocalHttpResponse{};
    response.status = 405U;
    response.body = matrix_error("M_UNRECOGNIZED", "the endpoint does not support this HTTP method");
    response.errcode = "M_UNRECOGNIZED";
    response.headers.emplace_back("Allow", std::string{allow});
    return response;
}

} // namespace merovingian::homeserver
