// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/WorkerSnapshotService.hpp"

#include "merovingian/ipc/FederationIpcFrames.hpp"
#include "merovingian/observability/SingleLog.hpp"

#include <algorithm>
#include <iterator>
#include <utility>

namespace merovingian::homeserver
{

namespace
{

    constexpr auto room_list_type = std::string_view{"room_list_page"};
    constexpr auto room_snapshot_type = std::string_view{"room_snapshot_page"};
    constexpr auto server_keys_type = std::string_view{"server_keys_result"};

    // A refused worker request is logged: a worker that follows the protocol is refused only after a failed read.
    [[nodiscard]] auto refused(std::string_view type, std::string_view reason, std::string_view room_id = {})
        -> std::string
    {
        LOG_WARNING("Federation worker store: refused a " + std::string{type} + " request (" + std::string{reason} +
                    (room_id.empty() ? std::string{} : ", room_id=" + std::string{room_id}) + ")");
        return ipc::serialize_worker_store_refusal(type, reason);
    }

} // namespace

WorkerSnapshotService::WorkerSnapshotService(WorkerSnapshotSources sources, std::size_t page_budget)
    : sources_{std::move(sources)}
    , page_budget_{page_budget}
{
}

auto WorkerSnapshotService::permit_reload(ChannelKey const& channel, std::string_view room_id, std::uint64_t generation)
    -> void
{
    if (!channel)
    {
        return;
    }
    auto const lock = std::lock_guard{mu_};
    auto& permit = state_of(channel).reload_permits[std::string{room_id}];
    permit.issued = std::max(permit.issued, generation);
}

auto WorkerSnapshotService::answer(ChannelKey const& channel, std::string_view type, std::string_view json)
    -> std::string
{
    if (type == "server_keys_request")
    {
        return answer_server_keys(json);
    }
    if (!channel)
    {
        return refused(type == "room_list_request" ? room_list_type : room_snapshot_type, "no_channel");
    }
    if (type == "room_list_request")
    {
        return answer_room_list(channel, json);
    }
    if (type == "room_snapshot_request")
    {
        return answer_room_snapshot(channel, json);
    }
    return refused(type, "unknown_type");
}

auto WorkerSnapshotService::consume_fill_omission(ChannelKey const& channel, std::string_view room_id) -> bool
{
    if (!channel)
    {
        return false;
    }
    auto const lock = std::lock_guard{mu_};
    return state_of(channel).fill_omissions.erase(std::string{room_id}) == 1U;
}

auto WorkerSnapshotService::channels_tracked() -> std::size_t
{
    auto const lock = std::lock_guard{mu_};
    std::erase_if(channels_, [](auto const& entry) {
        return entry.first.expired();
    });
    return channels_.size();
}

auto WorkerSnapshotService::answer_room_list(ChannelKey const& channel, std::string_view json) -> std::string
{
    auto const page = ipc::deserialize_room_list_request(json);
    if (!page.has_value())
    {
        return refused(room_list_type, "malformed");
    }
    {
        auto const lock = std::lock_guard{mu_};
        auto& state = state_of(channel);
        if (state.listed)
        {
            // Later pages, each once and in order, from what the one read gave.
            if (*page != state.next_list_page || *page >= state.list_pages.size())
            {
                return refused(room_list_type, "not_permitted");
            }
            auto body = std::move(state.list_pages[state.next_list_page]);
            ++state.next_list_page;
            if (state.next_list_page == state.list_pages.size())
            {
                state.list_pages.clear();
            }
            return body;
        }
        if (*page != 0U)
        {
            return refused(room_list_type, "not_permitted");
        }
        // Consumed before the read: one listing per channel, even when the read fails.
        state.listed = true;
    }
    // mu_ is not held across the read, and nothing here takes runtime.mutex.
    auto room_ids = sources_.list_rooms();
    if (!room_ids.has_value())
    {
        return refused(room_list_type, "read_failed");
    }
    auto pages = ipc::paginate_room_list(*room_ids, page_budget_);
    if (pages.empty())
    {
        return refused(room_list_type, "over_page_budget");
    }
    auto const lock = std::lock_guard{mu_};
    auto& state = state_of(channel);
    state.fill_omissions.insert(room_ids->begin(), room_ids->end());
    state.fill_permits.insert(std::make_move_iterator(room_ids->begin()), std::make_move_iterator(room_ids->end()));
    auto first = std::move(pages.front());
    if (pages.size() > 1U)
    {
        state.list_pages = std::move(pages);
        state.next_list_page = 1U;
    }
    return first;
}

auto WorkerSnapshotService::answer_room_snapshot(ChannelKey const& channel, std::string_view json) -> std::string
{
    auto const request = ipc::deserialize_room_snapshot_request(json);
    if (!request.has_value())
    {
        return refused(room_snapshot_type, "malformed");
    }
    {
        auto const lock = std::lock_guard{mu_};
        auto& state = state_of(channel);
        if (state.held.has_value() && sources_.now() - state.held->read_at > held_pages_lifetime)
        {
            state.held.reset();
        }
        if (request->page > 0U)
        {
            // A later page of the snapshot read for page 0: served from memory, each once and in order.
            auto& held = state.held;
            if (!held.has_value() || held->room_id != request->room_id || held->generation != request->generation ||
                request->page != held->next_page || request->page >= held->pages.size())
            {
                return refused(room_snapshot_type, "not_permitted", request->room_id);
            }
            auto body = std::move(held->pages[held->next_page]);
            ++held->next_page;
            if (held->next_page == held->pages.size())
            {
                held.reset();
            }
            return body;
        }
        // Page 0 consumes a permit, under mu_ and before any read, so a permit gives at most one read.
        auto permitted = false;
        if (request->generation == 0U)
        {
            permitted = state.fill_permits.erase(request->room_id) == 1U;
        }
        else if (auto const found = state.reload_permits.find(request->room_id); found != state.reload_permits.end())
        {
            auto& permit = found->second;
            permitted = permit.admitted < request->generation && request->generation <= permit.issued;
            if (permitted)
            {
                permit.admitted = request->generation;
                if (permit.admitted == permit.issued)
                {
                    state.reload_permits.erase(found);
                }
            }
        }
        if (!permitted)
        {
            return refused(room_snapshot_type, "not_permitted", request->room_id);
        }
        // One held snapshot per channel: a page 0 drops what an earlier one left.
        state.held.reset();
    }
    // mu_ is not held across the read, and nothing here takes runtime.mutex. read_room returns only once its read
    // transaction has ended, so the transaction is closed before page 0 below is sent.
    auto snapshot = sources_.read_room(request->room_id);
    if (!snapshot.has_value())
    {
        return refused(room_snapshot_type, "read_failed", request->room_id);
    }
    auto pagination = ipc::paginate_room_snapshot(*snapshot, request->generation, page_budget_);
    if (!pagination.refusal.empty())
    {
        return refused(room_snapshot_type, pagination.refusal, request->room_id);
    }
    auto first = std::move(pagination.pages.front());
    if (pagination.pages.size() > 1U)
    {
        auto const lock = std::lock_guard{mu_};
        state_of(channel).held =
            HeldPages{request->room_id, request->generation, std::move(pagination.pages), 1U, sources_.now()};
    }
    return first;
}

auto WorkerSnapshotService::answer_server_keys(std::string_view json) const -> std::string
{
    // No permit: the keys are public, and a key lookup may run on any worker thread at any time. Main answers from
    // memory, at most max_server_key_rows rows, and never reads the database for it.
    auto const server_name = ipc::deserialize_server_keys_request(json);
    if (!server_name.has_value())
    {
        return refused(server_keys_type, "malformed");
    }
    return ipc::serialize_server_keys_result(sources_.server_keys(*server_name, max_server_key_rows));
}

auto WorkerSnapshotService::state_of(ChannelKey const& channel) -> ChannelState&
{
    std::erase_if(channels_, [](auto const& entry) {
        return entry.first.expired();
    });
    return channels_[std::weak_ptr<void const>{channel}];
}

} // namespace merovingian::homeserver
