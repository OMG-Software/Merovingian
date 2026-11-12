// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/http/InFlightBudget.hpp"

#include <algorithm>
#include <condition_variable>
#include <cstddef>
#include <mutex>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace merovingian::homeserver
{

// What the workers of one make_join race share with the request that started it (C33, ADR-0725).
//
// Invariants:
//   - At most `worker_count()` threads exist for one join, however many candidates there are. Each worker takes the
//   next
//     candidate with `next_candidate()` when it has finished the last, so a candidate is not given a thread of its own.
//   - Once the race is decided (a winner) or over (the caller stopped waiting, `cancel()`), `next_candidate()` hands
//   out
//     nothing: no further outbound call is started.
//   - The request's client-outbound slot lives here, not with the request (`adopt_slot()`). The last worker to finish
//     (`worker_finished()`) releases it, so a client's in-flight budget still counts the join while any of its calls
//     runs, after the request has returned.
//
// Every member is guarded by `mtx`. The methods take it themselves; the caller takes it to read `winner`, `last_error`,
// `refused` and `remaining` after the race.
struct MakeJoinRaceState final
{
    // The number of worker threads a race over `candidates` candidates uses with `parallelism` allowed: never more than
    // either, and none for no candidates.
    [[nodiscard]] static auto worker_count(std::size_t parallelism, std::size_t candidates) noexcept -> std::size_t
    {
        return std::min(parallelism, candidates);
    }

    MakeJoinRaceState(std::vector<std::string> candidate_list, std::size_t workers)
        : candidates{std::move(candidate_list)}
        , remaining{static_cast<int>(candidates.size())}
        , live_workers{workers}
    {
    }

    std::mutex mtx{};
    std::condition_variable cv{};
    std::vector<std::string> candidates;
    std::size_t next_index{0U};
    std::optional<std::pair<std::string, std::string>> winner{}; // {server, body}
    std::string last_error{};
    // A candidate answered 403: a resident refused this user the room, which the client is told as 403 rather than as
    // an upstream failure.
    bool refused{false};
    // Candidates that have not finished (answered, failed, or been counted out because the race ended).
    int remaining;
    // The caller has stopped waiting.
    bool cancelled{false};
    // Workers that have not finished, and the slot they hold between them.
    std::size_t live_workers;
    std::optional<http::InFlightBudget::Slot> held_slot{};

    // The next candidate to call, or nullopt when the race is decided or over, or none is left. When it is decided or
    // over, the candidates not yet taken are counted out.
    [[nodiscard]] auto next_candidate() -> std::optional<std::string>
    {
        auto taken = std::optional<std::string>{};
        auto counted_out = false;
        {
            auto lock = std::unique_lock{mtx};
            if (winner.has_value() || cancelled)
            {
                if (next_index < candidates.size())
                {
                    remaining -= static_cast<int>(candidates.size() - next_index);
                    next_index = candidates.size();
                    counted_out = true;
                }
            }
            else if (next_index < candidates.size())
            {
                taken = candidates[next_index];
                ++next_index;
            }
        }
        if (counted_out)
        {
            cv.notify_one();
        }
        return taken;
    }

    // A candidate's outcome. The first success wins; failures keep the last error and whether any was a 403.
    auto record_answer(std::string const& server, bool ok, std::string body, bool remote_forbade) -> void
    {
        {
            auto lock = std::unique_lock{mtx};
            if (ok && !winner.has_value())
            {
                winner = {server, std::move(body)};
            }
            else if (!ok && !winner.has_value())
            {
                last_error = std::move(body);
                refused = refused || remote_forbade;
            }
            --remaining;
        }
        cv.notify_one();
    }

    // The caller stops waiting: candidates that have not been taken will not be.
    auto cancel() -> void
    {
        auto lock = std::unique_lock{mtx};
        cancelled = true;
    }

    // Takes over the request's slot. With every worker already finished there is nothing left to hold it for, and it is
    // released here.
    auto adopt_slot(std::optional<http::InFlightBudget::Slot> slot) -> void
    {
        auto lock = std::unique_lock{mtx};
        if (live_workers > 0U && slot.has_value())
        {
            held_slot.emplace(std::move(*slot));
        }
    }

    // A worker has ended, by return or by exception. The last one releases the slot.
    auto worker_finished() noexcept -> void
    {
        auto lock = std::unique_lock{mtx};
        if (live_workers > 0U)
        {
            --live_workers;
        }
        if (live_workers == 0U)
        {
            auto released = std::move(held_slot);
            held_slot.reset();
            lock.unlock(); // LOCK_RELEASE: reviewed — the slot's release takes the budget's own mutex, never ours
        }
    }
};

} // namespace merovingian::homeserver
