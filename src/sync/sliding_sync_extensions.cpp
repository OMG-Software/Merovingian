// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/sync/sliding_sync_extensions.hpp"

#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/serializer.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/database/persistent_store.hpp"

#include <algorithm>
#include <cstdint>
#include <map>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace merovingian::sync
{
namespace
{

    // ── Minimal JSON construction helpers ────────────────────────────────────

    [[nodiscard]] auto jstr(std::string s) -> canonicaljson::Value
    {
        return canonicaljson::Value{std::move(s)};
    }

    [[nodiscard]] auto jint(std::int64_t n) -> canonicaljson::Value
    {
        return canonicaljson::Value{n};
    }

    [[nodiscard]] auto jobj(canonicaljson::Object obj) -> canonicaljson::Value
    {
        return canonicaljson::Value{std::move(obj)};
    }

    [[nodiscard]] auto jarr(canonicaljson::Array arr) -> canonicaljson::Value
    {
        return canonicaljson::Value{std::move(arr)};
    }

    [[nodiscard]] auto jserialize(canonicaljson::Value val) -> std::string
    {
        return canonicaljson::serialize_canonical(val).output;
    }

    // Parse a JSON body into a Value; returns an empty Object on failure so
    // callers always get a well-formed (if empty) content field.
    [[nodiscard]] auto parse_content(std::string_view json) -> canonicaljson::Value
    {
        auto const result = canonicaljson::parse_lossless(json);
        if (result.error != canonicaljson::ParseError::none)
        {
            return canonicaljson::Value{canonicaljson::Object{}};
        }
        return result.value;
    }

    // Extract the algorithm prefix from a key_id of the form "algorithm:version".
    [[nodiscard]] auto otk_algorithm(std::string const& key_id) -> std::string
    {
        auto const sep = key_id.find(':');
        return sep != std::string::npos ? key_id.substr(0U, sep) : key_id;
    }

    // ── to_device extension ───────────────────────────────────────────────────

    [[nodiscard]] auto build_to_device(
        database::PersistentStore& store,
        std::string_view           user,
        std::string_view           device_id,
        ExtToDeviceRequest const&  req,
        std::uint64_t              current_sync_stream_id) -> ExtToDeviceResponse
    {
        // The `since` token is a decimal string representation of a stream_id.
        auto since_stream_id = std::uint64_t{0U};
        if (req.since.has_value() && !req.since->empty())
        {
            for (auto const ch : *req.since)
            {
                if (ch < '0' || ch > '9')
                {
                    break;
                }
                since_stream_id = since_stream_id * 10U + static_cast<std::uint64_t>(ch - '0');
            }
        }

        auto const limit   = req.limit > 0U ? req.limit : 20U;
        auto const drained = database::drain_to_device_messages(
            store, user, device_id, since_stream_id, current_sync_stream_id);

        auto resp  = ExtToDeviceResponse{};
        auto count = std::uint64_t{0U};
        for (auto const& msg : drained)
        {
            if (count >= limit)
            {
                break;
            }
            auto event = canonicaljson::Object{};
            event.push_back(canonicaljson::make_member("type",    jstr(msg.message_type)));
            event.push_back(canonicaljson::make_member("sender",  jstr(msg.sender_user_id)));
            event.push_back(canonicaljson::make_member("content", parse_content(msg.content_json)));
            resp.events_json.push_back(jserialize(jobj(std::move(event))));
            ++count;
        }
        resp.next_batch = std::to_string(current_sync_stream_id);
        return resp;
    }

    // ── e2ee extension ────────────────────────────────────────────────────────

    [[nodiscard]] auto build_e2ee(
        homeserver::HomeserverRuntime const& rt,
        database::PersistentStore const&     store,
        std::string_view                     user,
        std::string_view                     device_id,
        std::uint64_t                        since_sync_stream_id) -> ExtE2eeResponse
    {
        auto resp = ExtE2eeResponse{};

        // Device list changed / left.
        for (auto const& change : store.device_list_changes)
        {
            if (change.observer_user_id != user || change.stream_id <= since_sync_stream_id)
            {
                continue;
            }
            if (change.change_type == "left")
            {
                resp.left.push_back(change.subject_user_id);
            }
            else
            {
                resp.changed.push_back(change.subject_user_id);
            }
        }

        // One-time key counts — seed with zero for signed_curve25519 so the
        // client knows it must upload keys even on a fresh device.
        if (!device_id.empty())
        {
            resp.device_one_time_keys_count.emplace("signed_curve25519", std::uint64_t{0U});
        }
        for (auto const& key : store.one_time_keys)
        {
            if (key.user_id != user || key.device_id != device_id)
            {
                continue;
            }
            resp.device_one_time_keys_count[otk_algorithm(key.key_id)] += 1U;
        }

        // Fallback key algorithms currently uploaded.
        for (auto const& key : store.fallback_keys)
        {
            if (key.user_id != user || key.device_id != device_id)
            {
                continue;
            }
            auto const algo = otk_algorithm(key.key_id);
            if (std::ranges::find(resp.device_unused_fallback_key_types, algo) ==
                resp.device_unused_fallback_key_types.end())
            {
                resp.device_unused_fallback_key_types.push_back(algo);
            }
        }

        std::ignore = rt;
        return resp;
    }

    // ── account_data extension ────────────────────────────────────────────────

    [[nodiscard]] auto build_account_data(
        database::PersistentStore const& store,
        std::string_view                 user,
        std::uint64_t                    since_sync_stream_id,
        std::vector<std::string> const&  response_room_ids) -> ExtAccountDataResponse
    {
        auto resp = ExtAccountDataResponse{};

        for (auto const& data : store.account_data)
        {
            if (data.user_id != user || data.stream_id <= since_sync_stream_id)
            {
                continue;
            }
            auto event = canonicaljson::Object{};
            event.push_back(canonicaljson::make_member("type",    jstr(data.event_type)));
            event.push_back(canonicaljson::make_member("content", parse_content(data.content_json)));
            auto json = jserialize(jobj(std::move(event)));

            if (data.room_id.empty())
            {
                resp.global_json.push_back(std::move(json));
            }
            else
            {
                // Room-scoped account data is only surfaced for rooms in the response.
                auto const in_resp =
                    std::ranges::find(response_room_ids, data.room_id) != response_room_ids.end();
                if (in_resp)
                {
                    resp.rooms_json[data.room_id].push_back(std::move(json));
                }
            }
        }
        return resp;
    }

    // ── Shared helper: effective room list ────────────────────────────────────

    // When an extension names explicit rooms, scope to those. Otherwise fall
    // back to all rooms that appear in the current response.
    [[nodiscard]] auto effective_rooms(
        std::vector<std::string> const& ext_rooms,
        std::vector<std::string> const& response_rooms) -> std::vector<std::string> const&
    {
        return ext_rooms.empty() ? response_rooms : ext_rooms;
    }

    // ── receipts extension ────────────────────────────────────────────────────

    [[nodiscard]] auto build_receipts(
        homeserver::HomeserverRuntime const& rt,
        std::uint64_t                        since_sync_stream_id,
        std::vector<std::string> const&      ext_rooms,
        std::vector<std::string> const&      response_room_ids) -> ExtReceiptsResponse
    {
        auto const& rooms = effective_rooms(ext_rooms, response_room_ids);
        auto resp         = ExtReceiptsResponse{};

        for (auto const& room_id : rooms)
        {
            // Index: event_id → receipt_type → user_id → ts
            auto idx = std::map<std::string,
                        std::map<std::string,
                        std::map<std::string, std::uint64_t>>>{};

            for (auto const& receipt : rt.receipts)
            {
                if (receipt.room_id != room_id || receipt.stream_id <= since_sync_stream_id)
                {
                    continue;
                }
                idx[receipt.event_id][receipt.receipt_type][receipt.user_id] = receipt.ts;
            }
            if (idx.empty())
            {
                continue;
            }

            // Build m.receipt content: {event_id: {receipt_type: {user_id: {ts: N}}}}
            auto content = canonicaljson::Object{};
            for (auto& [event_id, receipt_types] : idx)
            {
                auto type_obj = canonicaljson::Object{};
                for (auto& [receipt_type, users] : receipt_types)
                {
                    auto user_obj = canonicaljson::Object{};
                    for (auto const& [uid, ts] : users)
                    {
                        auto ts_obj = canonicaljson::Object{};
                        ts_obj.push_back(canonicaljson::make_member("ts", jint(static_cast<std::int64_t>(ts))));
                        user_obj.push_back(canonicaljson::make_member(uid, jobj(std::move(ts_obj))));
                    }
                    type_obj.push_back(canonicaljson::make_member(receipt_type, jobj(std::move(user_obj))));
                }
                content.push_back(canonicaljson::make_member(event_id, jobj(std::move(type_obj))));
            }
            resp.rooms_json.emplace(room_id, jserialize(jobj(std::move(content))));
        }
        return resp;
    }

    // ── typing extension ──────────────────────────────────────────────────────

    [[nodiscard]] auto build_typing(
        homeserver::HomeserverRuntime const& rt,
        std::uint64_t                        since_sync_stream_id,
        std::vector<std::string> const&      ext_rooms,
        std::vector<std::string> const&      response_room_ids) -> ExtTypingResponse
    {
        auto const& rooms = effective_rooms(ext_rooms, response_room_ids);
        auto resp         = ExtTypingResponse{};

        for (auto const& room_id : rooms)
        {
            auto user_ids = canonicaljson::Array{};
            for (auto const& entry : rt.typing_users)
            {
                if (entry.room_id != room_id || !entry.typing ||
                    entry.stream_id <= since_sync_stream_id)
                {
                    continue;
                }
                user_ids.push_back(jstr(entry.user_id));
            }
            if (user_ids.empty())
            {
                continue;
            }

            // Serialize as {"user_ids": [...]}
            auto content = canonicaljson::Object{};
            content.push_back(canonicaljson::make_member("user_ids", jarr(std::move(user_ids))));
            resp.rooms_json.emplace(room_id, jserialize(jobj(std::move(content))));
        }
        return resp;
    }

} // namespace

// ── Public API ───────────────────────────────────────────────────────────────

auto build_extensions(
    homeserver::HomeserverRuntime const& rt,
    std::string_view                     user,
    std::string_view                     device_id,
    SlidingSyncExtensionRequests const&  ext_req,
    std::uint64_t                        since_sync_stream_id,
    std::uint64_t                        current_sync_stream_id,
    database::PersistentStore&           store,
    std::vector<std::string> const&      response_room_ids) -> SlidingSyncExtensionResponses
{
    auto resp = SlidingSyncExtensionResponses{};

    if (ext_req.to_device.has_value() && ext_req.to_device->enabled)
    {
        resp.to_device = build_to_device(store, user, device_id, *ext_req.to_device, current_sync_stream_id);
    }

    if (ext_req.e2ee.has_value() && ext_req.e2ee->enabled)
    {
        resp.e2ee = build_e2ee(rt, store, user, device_id, since_sync_stream_id);
    }

    if (ext_req.account_data.has_value() && ext_req.account_data->enabled)
    {
        resp.account_data = build_account_data(store, user, since_sync_stream_id, response_room_ids);
    }

    if (ext_req.receipts.has_value() && ext_req.receipts->enabled)
    {
        resp.receipts = build_receipts(rt, since_sync_stream_id, ext_req.receipts->rooms, response_room_ids);
    }

    if (ext_req.typing.has_value() && ext_req.typing->enabled)
    {
        resp.typing = build_typing(rt, since_sync_stream_id, ext_req.typing->rooms, response_room_ids);
    }

    return resp;
}

} // namespace merovingian::sync
