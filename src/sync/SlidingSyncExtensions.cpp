// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/sync/SlidingSyncExtensions.hpp"

#include "merovingian/canonicaljson/ParseError.hpp"
#include "merovingian/canonicaljson/Value.hpp"
#include "merovingian/canonicaljson/Parser.hpp"
#include "merovingian/canonicaljson/Serializer.hpp"
#include "merovingian/database/ExaminedRows.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/database/PersistentToDeviceMessage.hpp"
#include "merovingian/sync/DeviceListDelta.hpp"
#include "merovingian/sync/ReceiptContentBuilder.hpp"
#include "merovingian/sync/RoomAccess.hpp"
#include "merovingian/sync/ToDevicePosition.hpp"
#include "merovingian/sync/ReceiptVisibility.hpp"
#include "merovingian/trust_safety/IgnoreList.hpp"

#include <algorithm>
#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <unordered_set>
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

    // As parse_content, for account-data content: it is never signed, so it is read with the
    // general JSON parser, which keeps fractional numbers such as m.tag's `order` (spec: "A
    // number in a range [0,1]") instead of failing and giving an empty object.
    [[nodiscard]] auto parse_account_data_content(std::string_view json) -> canonicaljson::Value
    {
        auto const result = canonicaljson::parse_json(json);
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

    [[nodiscard]] auto build_to_device(database::PersistentStore& store, std::string_view user,
                                       std::string_view device_id, ExtToDeviceRequest const& req,
                                       std::uint64_t current_sync_stream_id) -> ExtToDeviceResponse
    {
        // The `since` token is a ToDevicePosition. It acknowledges every message at or below its stream id,
        // so it counts only when it decodes exactly and is from this database's stream token epoch (ADR-0592):
        // one from before a restore, or one that does not decode, acknowledges nothing, and the queue is sent
        // from its start. Clients keep this token across an M_UNKNOWN_POS, so the pos check does not cover it.
        auto since_stream_id = std::uint64_t{0U};
        if (req.since.has_value())
        {
            auto const since = decode_to_device_position(*req.since);
            if (since.has_value() && since->epoch == store.stream_token_epoch)
            {
                since_stream_id = since->stream_id;
            }
        }

        auto const limit = req.limit > 0U ? req.limit : 20U;
        // next_batch is the stream id of the last message sent and acknowledges
        // every row at or below it, so the page is taken from the lowest ids
        // whatever order the store returned them in.
        auto drained =
            database::drain_to_device_messages(store, user, device_id, since_stream_id, current_sync_stream_id);
        std::ranges::stable_sort(drained, {}, &database::PersistentToDeviceMessage::stream_id);

        auto resp = ExtToDeviceResponse{};
        auto count = std::uint64_t{0U};
        auto last_included_stream_id = std::optional<std::uint64_t>{};
        for (auto const& msg : drained)
        {
            if (count >= limit)
            {
                break;
            }
            auto event = canonicaljson::Object{};
            event.push_back(canonicaljson::make_member("type", jstr(msg.message_type)));
            event.push_back(canonicaljson::make_member("sender", jstr(msg.sender_user_id)));
            event.push_back(canonicaljson::make_member("content", parse_content(msg.content_json)));
            resp.events_json.push_back(jserialize(jobj(std::move(event))));
            last_included_stream_id = msg.stream_id;
            ++count;
        }
        // MSC4186: the continuation position must only advance past messages
        // actually included in this response. If nothing was returned, the
        // client should keep the previous position so undelivered rows are not
        // acknowledged implicitly by a later global watermark.
        // The position is re-encoded rather than echoed, so a `since` this server would not honour (another
        // epoch, or one that does not decode) is replaced by one it does.
        resp.next_batch =
            encode_to_device_position({last_included_stream_id.value_or(since_stream_id), store.stream_token_epoch});
        return resp;
    }

    // ── e2ee extension ────────────────────────────────────────────────────────

    [[nodiscard]] auto build_e2ee(homeserver::HomeserverRuntime const&, database::PersistentStore const& store,
                                  std::string_view user, std::string_view device_id, std::uint64_t since_sync_stream_id)
        -> ExtE2eeResponse
    {
        auto resp = ExtE2eeResponse{};

        // Device list changed / left. The collector reports each subject user
        // once, however many rows the change log holds for it; appending per
        // row instead made an initial response repeat the same handful of user
        // IDs thousands of times.
        auto delta = collect_device_list_delta(store, user, since_sync_stream_id);
        resp.changed = std::move(delta.changed);
        resp.left = std::move(delta.left);

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

        return resp;
    }

    // ── account_data extension ────────────────────────────────────────────────

    [[nodiscard]] auto build_account_data(database::PersistentStore const& store, std::string_view user,
                                          std::uint64_t since_sync_stream_id,
                                          std::vector<std::string> const& response_room_ids,
                                          std::unordered_set<std::string> const& initial_room_ids)
        -> ExtAccountDataResponse
    {
        auto resp = ExtAccountDataResponse{};
        // One lookup per row, not a scan of the response's rooms per row.
        auto const response_rooms =
            std::unordered_set<std::string_view>{response_room_ids.begin(), response_room_ids.end()};

        database::for_each_user_account_data(store, user, [&](database::PersistentAccountData const& data) {
            // A room the connection has not been sent has had none of its account data, so every row of it goes
            // down whatever its age; any other row goes down when it changed after `since`. No spec text states
            // this; it is this server's reading (ADR-0493).
            auto const room_is_new_to_connection = !data.room_id.empty() && initial_room_ids.contains(data.room_id);
            if (data.stream_id <= since_sync_stream_id && !room_is_new_to_connection)
            {
                return;
            }
            auto event = canonicaljson::Object{};
            event.push_back(canonicaljson::make_member("type", jstr(data.event_type)));
            event.push_back(canonicaljson::make_member("content", parse_account_data_content(data.content_json)));
            auto json = jserialize(jobj(std::move(event)));

            if (data.room_id.empty())
            {
                resp.global_json.push_back(std::move(json));
            }
            else
            {
                // Room-scoped account data is only surfaced for rooms in the response.
                if (response_rooms.contains(data.room_id))
                {
                    resp.rooms_json[data.room_id].push_back(std::move(json));
                }
            }
        });
        return resp;
    }

    // ── Shared helper: effective room list ────────────────────────────────────

    // When an extension names explicit rooms, scope to those. Otherwise fall
    // back to all rooms that appear in the current response. Per MSC4186,
    // `"rooms":["*"]` is the `AllSubscribed` sentinel (ruma's
    // `ExtensionRoomConfig::AllSubscribed` serializes to the literal string
    // "*"), not a room named "*" — matrix-rust-sdk's RoomListService sends
    // exactly this for the receipts extension. Treat it the same as omitting
    // `rooms` entirely, rather than matching against a room that can never
    // exist.
    [[nodiscard]] auto effective_rooms(std::vector<std::string> const& ext_rooms,
                                       std::vector<std::string> const& response_rooms)
        -> std::vector<std::string> const&
    {
        auto const is_all_subscribed = ext_rooms.empty() || (ext_rooms.size() == 1U && ext_rooms.front() == "*");
        return is_all_subscribed ? response_rooms : ext_rooms;
    }

    // The requested rooms (after effective_rooms) that the caller has joined, each once.
    //
    // CSAZ-1: `rooms` is client-supplied, so only a room the caller has joined may be named.
    // The rooms are classified through one index over the caller's memberships, built once per
    // request, rather than one scan of every membership row per named room: this runs under
    // the runtime lock (security audit run-1, sp01.sliding-sync-extension-rooms-unbounded).
    [[nodiscard]] auto joined_rooms_among(std::vector<std::string> const& rooms,
                                          std::map<std::string, RoomAccess, std::less<>> const& access)
        -> std::set<std::string_view, std::less<>>
    {
        auto joined = std::set<std::string_view, std::less<>>{};
        for (auto const& room_id : rooms)
        {
            if (auto const found = access.find(room_id); found != access.end() && found->second == RoomAccess::joined)
            {
                joined.insert(room_id);
            }
        }
        return joined;
    }

    // ── receipts extension ────────────────────────────────────────────────────

    [[nodiscard]] auto build_receipts(homeserver::HomeserverRuntime const& rt, std::string_view user,
                                      std::uint64_t since_sync_stream_id,
                                      std::set<std::string_view, std::less<>> const& joined_rooms,
                                      std::unordered_set<std::string> const& ignored_senders) -> ExtReceiptsResponse
    {
        auto resp = ExtReceiptsResponse{};
        if (joined_rooms.empty())
        {
            return resp;
        }

        // The rows of each room that was asked for, through the receipt index (ADR-0737), never the whole table.
        auto by_room = std::map<std::string_view, ReceiptContentBuilder, std::less<>>{};
        auto rows = std::vector<database::PersistentReceipt const*>{};
        for (auto const room_id : joined_rooms)
        {
            auto room_rows = database::receipts_in_room(rt.database.persistent_store, room_id);
            rows.insert(rows.end(), room_rows.begin(), room_rows.end());
        }
        for (auto const* receipt_row : rows)
        {
            auto const& receipt = *receipt_row;
            if (receipt.stream_id <= since_sync_stream_id)
            {
                continue;
            }
            // CSAZ-4: m.read.private is for its sender alone and m.fully_read is never an
            // m.receipt (same rule as /sync).
            if (!receipt_visible_to(receipt.receipt_type, receipt.user_id, user))
            {
                continue;
            }
            // Ignoring Users: a read receipt is an event sent by its
            // `user_id`, not a state event, so it is withheld the same
            // way a timeline message from an ignored sender would be.
            if (trust_safety::is_delivery_suppressed(ignored_senders, receipt.user_id, /*is_state_event=*/false))
            {
                continue;
            }
            by_room[receipt.room_id].add(receipt);
        }

        for (auto& [room_id, receipts] : by_room)
        {
            if (receipts.empty())
            {
                continue;
            }
            // m.receipt content: {event_id: {receipt_type: {user_id: {ts: N, thread_id: T}}}}
            auto content = receipts.build();
            // m.receipt is an EphemeralRoom-kind event (ruma's SyncReceiptEvent):
            // the client expects {"type":"m.receipt","content":{...}}, not the
            // bare content object. Sending bare content fails deserialization
            // client-side, which matrix-rust-sdk treats as a failed sync
            // iteration — the position never advances and the client retries
            // forever, producing a busy-loop storm on any poll that returns a
            // non-empty receipt.
            auto event = canonicaljson::Object{};
            event.push_back(canonicaljson::make_member("type", jstr("m.receipt")));
            event.push_back(canonicaljson::make_member("content", jobj(std::move(content))));
            resp.rooms_json.emplace(std::string{room_id}, jserialize(jobj(std::move(event))));
        }
        return resp;
    }

    // ── typing extension ──────────────────────────────────────────────────────

    [[nodiscard]] auto build_typing(homeserver::HomeserverRuntime const& rt, std::uint64_t since_sync_stream_id,
                                    std::set<std::string_view, std::less<>> const& joined_rooms,
                                    std::unordered_set<std::string> const& ignored_senders) -> ExtTypingResponse
    {
        auto resp = ExtTypingResponse{};

        // Only rooms whose typing list changed since the caller's position are reported.
        auto user_ids_by_room = std::map<std::string_view, canonicaljson::Array, std::less<>>{};
        for (auto const room_id : joined_rooms)
        {
            if (homeserver::room_typing_stream_id_for(rt, room_id) > since_sync_stream_id)
            {
                user_ids_by_room.try_emplace(room_id);
            }
        }
        if (user_ids_by_room.empty())
        {
            return resp;
        }

        // One pass over the typing table, each entry kept for its room if that room is reported.
        for (auto const& entry : rt.typing_users)
        {
            if (!entry.typing)
            {
                continue;
            }
            auto const found = user_ids_by_room.find(entry.room_id);
            if (found == user_ids_by_room.end())
            {
                continue;
            }
            // Ignoring Users: typing is not a state event, so it is
            // withheld the same way a timeline message would be — see
            // build_receipts above for the identical reasoning.
            if (trust_safety::is_delivery_suppressed(ignored_senders, entry.user_id, /*is_state_event=*/false))
            {
                continue;
            }
            found->second.push_back(jstr(entry.user_id));
        }

        for (auto& [room_id, user_ids] : user_ids_by_room)
        {
            // Suppress empty typing lists on the first sync (since == 0); for
            // every subsequent position emit the current list even when empty so
            // clients can clear stale indicators.
            if (user_ids.empty() && since_sync_stream_id == std::uint64_t{0U})
            {
                continue;
            }

            // m.typing is an EphemeralRoom-kind event (ruma's SyncTypingEvent):
            // the client expects {"type":"m.typing","content":{"user_ids":[...]}},
            // not the bare content object — see the identical note in
            // build_receipts above for why a bare object here causes a
            // client-side sync storm.
            auto content = canonicaljson::Object{};
            content.push_back(canonicaljson::make_member("user_ids", jarr(std::move(user_ids))));
            auto event = canonicaljson::Object{};
            event.push_back(canonicaljson::make_member("type", jstr("m.typing")));
            event.push_back(canonicaljson::make_member("content", jobj(std::move(content))));
            resp.rooms_json.emplace(std::string{room_id}, jserialize(jobj(std::move(event))));
        }
        return resp;
    }

} // namespace

// ── Public API ───────────────────────────────────────────────────────────────

auto build_extensions(homeserver::HomeserverRuntime const& rt, std::string_view user, std::string_view device_id,
                      SlidingSyncExtensionRequests const& ext_req, std::uint64_t since_sync_stream_id,
                      std::uint64_t current_sync_stream_id, database::PersistentStore& store,
                      std::vector<std::string> const& response_room_ids,
                      std::unordered_set<std::string> const& ignored_senders,
                      std::unordered_set<std::string> const& initial_room_ids) -> SlidingSyncExtensionResponses
{
    // Only receipts and typing classify rooms; skip the membership pass when neither is on.
    auto const needs_access = (ext_req.receipts.has_value() && ext_req.receipts->enabled) ||
                              (ext_req.typing.has_value() && ext_req.typing->enabled);
    auto const room_access =
        needs_access ? room_access_index(store, user) : std::map<std::string, RoomAccess, std::less<>>{};
    return build_extensions(rt, user, device_id, ext_req, since_sync_stream_id, current_sync_stream_id, store,
                            room_access, response_room_ids, ignored_senders, initial_room_ids);
}

auto build_extensions(homeserver::HomeserverRuntime const& rt, std::string_view user, std::string_view device_id,
                      SlidingSyncExtensionRequests const& ext_req, std::uint64_t since_sync_stream_id,
                      std::uint64_t current_sync_stream_id, database::PersistentStore& store,
                      std::map<std::string, RoomAccess, std::less<>> const& room_access,
                      std::vector<std::string> const& response_room_ids,
                      std::unordered_set<std::string> const& ignored_senders,
                      std::unordered_set<std::string> const& initial_room_ids) -> SlidingSyncExtensionResponses
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
        resp.account_data = build_account_data(store, user, since_sync_stream_id, response_room_ids, initial_room_ids);
    }

    auto const wants_receipts = ext_req.receipts.has_value() && ext_req.receipts->enabled;
    auto const wants_typing = ext_req.typing.has_value() && ext_req.typing->enabled;
    // One room-access index per request, shared by both extensions (and, from the handler, by the
    // room_subscriptions classification).
    if (wants_receipts)
    {
        resp.receipts =
            build_receipts(rt, user, since_sync_stream_id,
                           joined_rooms_among(effective_rooms(ext_req.receipts->rooms, response_room_ids), room_access),
                           ignored_senders);
    }
    if (wants_typing)
    {
        resp.typing =
            build_typing(rt, since_sync_stream_id,
                         joined_rooms_among(effective_rooms(ext_req.typing->rooms, response_room_ids), room_access),
                         ignored_senders);
    }

    return resp;
}

} // namespace merovingian::sync
