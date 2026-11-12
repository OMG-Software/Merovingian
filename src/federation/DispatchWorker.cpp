// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/federation/DispatchWorker.hpp"

#include "merovingian/federation/DispatchDestinationSnapshot.hpp"
#include "merovingian/federation/DispatchWorkerConfig.hpp"
#include "merovingian/federation/DispatchWorkerSummary.hpp"
#include "merovingian/federation/OutboundCall.hpp"
#include "merovingian/federation/OutboundTransactionResult.hpp"
#include "merovingian/federation/OutboundTransactionSupport.hpp"
#include "merovingian/observability/LogEventSeverity.hpp"
#include "merovingian/observability/SingleLog.hpp"
#include "merovingian/observability/StructuredLogField.hpp"

#include <algorithm>
#include <charconv>
#include <chrono>
#include <limits>
#include <string>
#include <system_error>
#include <thread>
#include <tuple>
#include <utility>
#include <vector>

namespace merovingian::federation
{
namespace
{

    auto log_diagnostic(std::string_view event, std::vector<observability::StructuredLogField> fields,
                        observability::LogEventSeverity severity = observability::LogEventSeverity::debug) -> void
    {
        observability::log_diagnostic("dispatch_worker", event, fields, severity);
    }

    [[nodiscard]] auto transaction_is_well_formed(OutboundTransaction const& transaction) noexcept -> bool
    {
        return !transaction.transaction_id.empty() && !transaction.destination.empty() && !transaction.method.empty() &&
               !transaction.target.empty() && !transaction.origin.empty() && !transaction.body.empty();
    }

    [[nodiscard]] auto to_persistent_transaction(OutboundTransaction const& transaction)
        -> database::PersistentFederationTransaction
    {
        return {transaction.transaction_id, transaction.destination, transaction.method,
                transaction.target,         transaction.origin,      transaction.origin_server_ts,
                transaction.body,           transaction.retry_count, transaction.next_retry_ts};
    }

    [[nodiscard]] auto to_outbound_transaction(database::PersistentFederationTransaction const& transaction)
        -> OutboundTransaction
    {
        return {transaction.transaction_id, transaction.server_name, transaction.method,
                transaction.target,         transaction.origin,      transaction.origin_server_ts,
                transaction.body,           transaction.retry_count, transaction.next_retry_ts};
    }

    [[nodiscard]] auto to_persistent_destination(FederationDestination const& destination)
        -> database::PersistentFederationDestination
    {
        return {destination.server_name, destination.state, destination.retry_after_ts, destination.last_success_ts,
                destination.consecutive_failures};
    }

    [[nodiscard]] auto to_federation_destination(database::PersistentFederationDestination const& destination)
        -> FederationDestination
    {
        return {destination.server_name, destination.retry_after_ts, destination.last_success_ts,
                destination.consecutive_failures, destination.state};
    }

    [[nodiscard]] auto default_now_ms() -> std::uint64_t
    {
        return static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
                .count());
    }

    auto default_sleep_for(std::chrono::milliseconds duration) -> void
    {
        std::this_thread::sleep_for(duration);
    }

    // When a transaction was admitted, from the stamp `enqueue_batch` put in `origin_server_ts`; nullopt for a row
    // without a usable one.
    [[nodiscard]] auto admitted_at(OutboundTransaction const& transaction) noexcept -> std::optional<std::uint64_t>
    {
        auto const& text = transaction.origin_server_ts;
        auto value = std::uint64_t{0U};
        auto const parsed = std::from_chars(text.data(), text.data() + text.size(), value);
        if (parsed.ec != std::errc{} || parsed.ptr != text.data() + text.size())
        {
            return std::nullopt;
        }
        return value;
    }

    // Removes the entries at `positions`, which are ascending, in one pass.
    auto erase_positions(std::deque<OutboundTransaction>& entries, std::vector<std::size_t> const& positions) -> void
    {
        auto next = positions.begin();
        auto kept = std::size_t{0U};
        for (auto position = std::size_t{0U}; position < entries.size(); ++position)
        {
            if (next != positions.end() && *next == position)
            {
                ++next;
                continue;
            }
            if (kept != position)
            {
                entries[kept] = std::move(entries[position]);
            }
            ++kept;
        }
        entries.resize(kept);
    }

} // namespace

DispatchWorker::DispatchWorker(DispatchWorkerConfig config, http::OutboundClient& client, DispatchResolver resolver,
                               DispatchClock now_ms, DispatchSleep sleep_for,
                               database::PersistentStore* persistent_store)
    : config_{std::move(config)}
    , client_{client}
    , resolver_{std::move(resolver)}
    , now_ms_{now_ms ? std::move(now_ms) : DispatchClock{default_now_ms}}
    , sleep_for_{sleep_for ? std::move(sleep_for) : DispatchSleep{default_sleep_for}}
    , persistent_store_{persistent_store}
{
}

DispatchWorker::~DispatchWorker()
{
    request_shutdown();
    join();
}

auto DispatchWorker::enqueue(OutboundTransaction transaction) -> bool
{
    auto batch = std::vector<OutboundTransaction>{};
    batch.push_back(std::move(transaction));
    return enqueue_batch(std::move(batch)).front();
}

auto DispatchWorker::enqueue_batch(std::vector<OutboundTransaction> batch) -> std::vector<bool>
{
    auto accepted = std::vector<bool>(batch.size(), false);
    // The batch's admissible members, as positions in `batch`. A transaction the shape or the policy refuses is
    // refused alone, as before; only a failed commit refuses all that were admitted.
    auto admitted = std::vector<std::size_t>{};
    for (auto position = std::size_t{0U}; position < batch.size(); ++position)
    {
        auto const& transaction = batch[position];
        if (!transaction_is_well_formed(transaction))
        {
            log_diagnostic("enqueue.rejected", {
                                                   {"transaction_id", transaction.transaction_id, false},
                                                   {"destination",    transaction.destination,    false},
                                                   {"reason",         "transaction is malformed", false}
            });
            continue;
        }
        if (config_.destination_refusal)
        {
            if (auto const refusal = config_.destination_refusal(transaction.destination); !refusal.empty())
            {
                log_diagnostic("enqueue.rejected", {
                                                       {"transaction_id", transaction.transaction_id, false},
                                                       {"destination",    transaction.destination,    false},
                                                       {"reason",         refusal,                    false}
                });
                auto lock = std::lock_guard{mutex_};
                ++summary_.rejected;
                continue;
            }
        }
        admitted.push_back(position);
    }
    if (admitted.empty())
    {
        return accepted;
    }
    {
        auto lock = std::lock_guard{mutex_};
        if (shutdown_requested_.load())
        {
            for (auto const position : admitted)
            {
                log_diagnostic("enqueue.rejected", {
                                                       {"transaction_id", batch[position].transaction_id, false},
                                                       {"destination",    batch[position].destination,    false},
                                                       {"reason",         "worker is shutting down",      false}
                });
            }
            return accepted;
        }
        // The bounds count the batch's own earlier members, which are not in the queue yet.
        auto taken = std::vector<std::size_t>{};
        auto taken_per_destination = std::unordered_map<std::string, std::size_t>{};
        auto taken_failing = std::size_t{0U};
        auto taken_slow = std::size_t{0U};
        auto const now = now_ms_();
        for (auto const position : admitted)
        {
            auto& transaction = batch[position];
            if (config_.max_queue_depth != 0U && queue_.size() + taken.size() >= config_.max_queue_depth)
            {
                log_diagnostic("enqueue.rejected",
                               {
                                   {"transaction_id", transaction.transaction_id,                   false},
                                   {"destination",    transaction.destination,                      false},
                                   {"queue_depth",    std::to_string(queue_.size() + taken.size()), false},
                                   {"reason",         "queue depth limit reached",                  false}
                });
                ++summary_.rejected;
                continue;
            }
            auto const held = queued_per_destination_.find(transaction.destination);
            auto const already_held = (held != queued_per_destination_.end() ? held->second : std::size_t{0U}) +
                                      taken_per_destination[transaction.destination];
            if (already_held >= effective_max_pending_per_destination(config_))
            {
                log_diagnostic("enqueue.rejected", {
                                                       {"transaction_id", transaction.transaction_id,        false},
                                                       {"destination",    transaction.destination,           false},
                                                       {"reason",         "destination queue share reached", false}
                });
                ++summary_.rejected;
                continue;
            }
            if (failing_destinations_.contains(transaction.destination))
            {
                if (failing_share_reached_locked(transaction.destination, now, taken_failing))
                {
                    log_diagnostic("enqueue.rejected", {
                                                           {"transaction_id", transaction.transaction_id,            false},
                                                           {"destination",    transaction.destination,               false},
                                                           {"reason",         "failing destinations' share reached", false}
                    });
                    ++summary_.rejected;
                    continue;
                }
                ++taken_failing;
            }
            if (slow_destinations_.contains(transaction.destination))
            {
                // C20: a destination that answers slowly keeps what it holds, but cannot take the queue.
                if (slow_slots_ + taken_slow >= effective_max_pending_failing(config_))
                {
                    log_diagnostic("enqueue.rejected", {
                                                           {"transaction_id", transaction.transaction_id,         false},
                                                           {"destination",    transaction.destination,            false},
                                                           {"reason",         "slow destinations' share reached", false}
                    });
                    ++summary_.rejected;
                    continue;
                }
                ++taken_slow;
            }
            // The age limit reads this. The transaction's body carries its own timestamp, set when it is sent.
            if (transaction.origin_server_ts.empty())
            {
                transaction.origin_server_ts = std::to_string(now);
            }
            ++taken_per_destination[transaction.destination];
            taken.push_back(position);
        }
        if (taken.empty())
        {
            return accepted;
        }
        // One commit for the batch (ADR-0441): every row is durable before any can be sent, and a failure leaves
        // none of them in the database or the queue.
        if (persistent_store_ != nullptr)
        {
            auto rows = std::vector<database::PersistentFederationTransaction>{};
            rows.reserve(taken.size());
            for (auto const position : taken)
            {
                rows.push_back(to_persistent_transaction(batch[position]));
            }
            if (!database::store_federation_transactions(*persistent_store_, std::move(rows)))
            {
                for (auto const position : taken)
                {
                    log_diagnostic("enqueue.rejected", {
                                                           {"transaction_id", batch[position].transaction_id,  false},
                                                           {"destination",    batch[position].destination,     false},
                                                           {"reason",         "failed to persist transaction", false}
                    });
                }
                return accepted;
            }
        }
        for (auto const position : taken)
        {
            accepted[position] = true;
            push_queue_locked(std::move(batch[position]));
            ++summary_.enqueued;
            ++summary_.pending;
        }
    }
    cv_.notify_all();
    return accepted;
}

auto effective_max_pending_per_destination(DispatchWorkerConfig const& config) noexcept -> std::size_t
{
    if (config.max_pending_per_destination != 0U)
    {
        return config.max_pending_per_destination;
    }
    return std::max<std::size_t>(16U, config.max_queue_depth / 16U);
}

auto effective_max_pending_failing(DispatchWorkerConfig const& config) noexcept -> std::size_t
{
    if (config.max_pending_failing_destinations != 0U)
    {
        return config.max_pending_failing_destinations;
    }
    if (config.max_queue_depth == 0U)
    {
        return std::numeric_limits<std::size_t>::max();
    }
    // Never below one destination's own share: this bound is against many dead peers together, and a single one that
    // fails once must not lose what ADR-0177 lets it hold. Only a queue too small to divide is affected.
    return std::max<std::size_t>(effective_max_pending_per_destination(config), config.max_queue_depth / 2U);
}

auto DispatchWorker::push_queue_locked(OutboundTransaction transaction) -> void
{
    ++queued_per_destination_[transaction.destination];
    if (failing_destinations_.contains(transaction.destination))
    {
        ++failing_slots_;
    }
    if (slow_destinations_.contains(transaction.destination))
    {
        ++slow_slots_;
    }
    queue_.push_back(std::move(transaction));
}

auto DispatchWorker::requeue_locked(OutboundTransaction transaction) -> void
{
    // The transaction kept its slot while it was in flight; it is not counted again. At the front:
    // it was its destination's oldest, and stays so (next_ready_locked).
    queue_.push_front(std::move(transaction));
}

auto DispatchWorker::destination_at_share_locked(std::string const& destination) const -> bool
{
    auto const held = queued_per_destination_.find(destination);
    return held != queued_per_destination_.end() && held->second >= effective_max_pending_per_destination(config_);
}

auto DispatchWorker::release_destination_slot_locked(std::string const& destination) -> void
{
    auto const held = queued_per_destination_.find(destination);
    if (held == queued_per_destination_.end())
    {
        return;
    }
    if (failing_destinations_.contains(destination) && failing_slots_ > 0U)
    {
        --failing_slots_;
    }
    if (slow_destinations_.contains(destination) && slow_slots_ > 0U)
    {
        --slow_slots_;
    }
    if (held->second <= 1U)
    {
        slow_destinations_.erase(destination);
        queued_per_destination_.erase(held);
        return;
    }
    --held->second;
}

auto DispatchWorker::set_slow_locked(std::string const& destination, bool slow) -> void
{
    auto const marked = slow_destinations_.contains(destination);
    if (slow == marked)
    {
        return;
    }
    auto const held = queued_per_destination_.find(destination);
    auto const slots = held != queued_per_destination_.end() ? held->second : std::size_t{0U};
    if (!slow)
    {
        slow_slots_ -= std::min(slow_slots_, slots);
        slow_destinations_.erase(destination);
        return;
    }
    if (slots == 0U)
    {
        return; // nothing queued to protect the queue from; and the set stays bounded by the destinations holding a
                // slot
    }
    slow_slots_ += slots;
    slow_destinations_.insert(destination);
}

auto DispatchWorker::failing_share_reached_locked(std::string const& destination, std::uint64_t now,
                                                  std::size_t taken) const -> bool
{
    auto const failing = failing_destinations_.find(destination);
    if (failing == failing_destinations_.end() || now >= failing->second)
    {
        // Past its backoff a destination is due a try, and only a try can show it has recovered.
        return false;
    }
    return failing_slots_ + taken >= effective_max_pending_failing(config_);
}

auto DispatchWorker::discard_locked(std::vector<std::size_t> const& queued, std::vector<std::size_t> const& parked,
                                    std::string_view reason) -> void
{
    if (queued.empty() && parked.empty())
    {
        return;
    }
    if (persistent_store_ != nullptr)
    {
        auto ids = std::vector<std::string>{};
        ids.reserve(queued.size() + parked.size());
        for (auto const position : queued)
        {
            ids.push_back(queue_[position].transaction_id);
        }
        for (auto const position : parked)
        {
            ids.push_back(pending_replay_[position].transaction_id);
        }
        // Same rule as a single drop: a row that could not be deleted would come back at the next start, so the
        // transactions stay, and the next pass tries again.
        if (!database::delete_federation_transactions(*persistent_store_, ids))
        {
            summary_.failed += ids.size();
            log_diagnostic("transaction.discard_failed",
                           {
                               {"count",  std::to_string(ids.size()), false},
                               {"reason", std::string{reason},        false}
            },
                           observability::LogEventSeverity::warning);
            return;
        }
    }
    for (auto const position : queued)
    {
        release_destination_slot_locked(queue_[position].destination);
    }
    erase_positions(queue_, queued);
    erase_positions(pending_replay_, parked);
    summary_.dropped += queued.size() + parked.size();
    summary_.pending -= std::min<std::size_t>(summary_.pending, queued.size());
    log_diagnostic(
        "transaction.discarded",
        {
            {"count",  std::to_string(queued.size() + parked.size()), false},
            {"reason", std::string{reason},                           false}
    },
        observability::LogEventSeverity::warning);
}

auto DispatchWorker::shed_failing_over_share_locked() -> void
{
    auto const budget = effective_max_pending_failing(config_);
    if (failing_slots_ <= budget)
    {
        return;
    }
    // The largest number each failing destination may keep so that all of them fit: the small holders keep
    // everything, and the budget left is divided among the rest.
    auto holdings = std::vector<std::size_t>{};
    holdings.reserve(failing_destinations_.size());
    for (auto const& [name, retry_after] : failing_destinations_)
    {
        if (auto const held = queued_per_destination_.find(name); held != queued_per_destination_.end())
        {
            holdings.push_back(held->second);
        }
    }
    std::ranges::sort(holdings);
    auto keep = std::size_t{0U};
    auto left = budget;
    for (auto index = std::size_t{0U}; index < holdings.size(); ++index)
    {
        auto const share = left / (holdings.size() - index);
        if (holdings[index] > share)
        {
            keep = share;
            break;
        }
        left -= holdings[index];
    }
    // Newest first, so each destination keeps the transactions it is retrying. What a peer misses it fetches itself
    // once it is reachable (prev_events, /get_missing_events).
    auto excess = failing_slots_ - budget;
    auto held_now = std::unordered_map<std::string_view, std::size_t>{};
    auto queued = std::vector<std::size_t>{};
    for (auto position = queue_.size(); position > 0U && excess > 0U; --position)
    {
        auto const& candidate = queue_[position - 1U];
        if (!failing_destinations_.contains(candidate.destination))
        {
            continue;
        }
        auto const [held, first_seen] = held_now.try_emplace(candidate.destination, std::size_t{0U});
        if (first_seen)
        {
            held->second = queued_per_destination_.find(candidate.destination)->second;
        }
        if (held->second <= keep)
        {
            continue;
        }
        --held->second;
        --excess;
        queued.push_back(position - 1U);
    }
    std::ranges::reverse(queued);
    discard_locked(queued, {}, "failing destinations' share exceeded");
}

auto DispatchWorker::sweep_aged_locked(std::uint64_t now) -> void
{
    if (now < next_age_sweep_ms_)
    {
        return;
    }
    next_age_sweep_ms_ = now + config_.age_sweep_interval_ms;
    if (failing_destinations_.empty())
    {
        return;
    }
    auto const expired = [this, now](OutboundTransaction const& candidate) {
        if (!failing_destinations_.contains(candidate.destination))
        {
            return false;
        }
        auto const since = admitted_at(candidate);
        return since.has_value() && now > *since && now - *since > config_.max_failing_transaction_age_ms;
    };
    auto const positions_of = [&expired](std::deque<OutboundTransaction> const& entries) {
        auto positions = std::vector<std::size_t>{};
        for (auto position = std::size_t{0U}; position < entries.size(); ++position)
        {
            if (expired(entries[position]))
            {
                positions.push_back(position);
            }
        }
        return positions;
    };
    discard_locked(positions_of(queue_), positions_of(pending_replay_), "past the failing transaction age limit");
}

auto DispatchWorker::start() -> void
{
    auto already_started = started_.exchange(true, std::memory_order_acq_rel);
    if (already_started)
    {
        return;
    }
    auto const wanted = std::max<std::size_t>(1U, config_.delivery_threads);
    threads_.reserve(wanted);
    for (auto index = std::size_t{0U}; index < wanted; ++index)
    {
        try
        {
            threads_.emplace_back([this] {
                loop();
            });
        }
        catch (std::system_error const& error)
        {
            if (threads_.empty())
            {
                // Reset so a subsequent start() attempt (after the caller resolves
                // the underlying cause) can try again rather than silently no-oping.
                started_.store(false, std::memory_order_release);
                throw;
            }
            // Fewer threads still deliver; one peer can then hold a larger part of them.
            log_diagnostic("start.fewer_threads",
                           {
                               {"wanted",  std::to_string(wanted),          false},
                               {"started", std::to_string(threads_.size()), false},
                               {"reason",  error.what(),                    false}
            },
                           observability::LogEventSeverity::warning);
            return;
        }
    }
}

auto DispatchWorker::request_shutdown() noexcept -> void
{
    {
        // Set under mutex_: the idle wait reads the flag under it and then blocks, so a store
        // without the lock can land between the two and its notify wakes nobody (ADR-0312).
        auto lock = std::lock_guard{mutex_};
        shutdown_requested_.store(true);
    }
    cv_.notify_all();
}

auto DispatchWorker::join() -> void
{
    for (auto& thread : threads_)
    {
        if (thread.joinable())
        {
            thread.join();
        }
    }
}

auto DispatchWorker::next_ready_locked(std::uint64_t due_by) const -> std::optional<std::size_t>
{
    auto held_back = std::set<std::string_view>{in_flight_destinations_.begin(), in_flight_destinations_.end()};
    // C20: a destination that answers slowly goes after every other destination that is ready, so it cannot keep every
    // thread busy while others wait. It still goes when nothing else is ready. Its later rows stay behind its oldest.
    auto slow_fallback = std::optional<std::size_t>{};
    for (auto position = std::size_t{0U}; position < queue_.size(); ++position)
    {
        auto const& candidate = queue_[position];
        if (held_back.contains(candidate.destination))
        {
            continue;
        }
        if (candidate.next_retry_ts <= due_by)
        {
            if (!slow_destinations_.contains(candidate.destination))
            {
                return position;
            }
            if (!slow_fallback.has_value())
            {
                slow_fallback = position;
            }
        }
        held_back.insert(candidate.destination);
    }
    return slow_fallback;
}

auto DispatchWorker::take_next(OutboundTransaction& out, std::uint64_t due_by) -> bool
{
    auto lock = std::lock_guard{mutex_};
    auto const ready = next_ready_locked(due_by);
    if (!ready.has_value())
    {
        return false;
    }
    auto const position = queue_.begin() + static_cast<std::ptrdiff_t>(*ready);
    out = std::move(*position);
    queue_.erase(position);
    in_flight_destinations_.insert(out.destination);
    if (summary_.pending > 0U)
    {
        --summary_.pending;
    }
    // Removing an entry frees a slot under max_queue_depth — top up the
    // active queue from any replay overflow that was parked at startup.
    std::ignore = top_up_replay_locked();
    return true;
}

DispatchWorker::InFlightSlot::InFlightSlot(DispatchWorker& worker, std::string destination) noexcept
    : worker_{worker}
    , destination_{std::move(destination)}
{
}

DispatchWorker::InFlightSlot::~InFlightSlot()
{
    {
        auto lock = std::lock_guard{worker_.mutex_};
        worker_.in_flight_destinations_.erase(destination_);
    }
    worker_.cv_.notify_all();
}

auto DispatchWorker::find_or_create_destination(std::string_view server_name) -> FederationDestination&
{
    auto const existing =
        std::ranges::find_if(destinations_, [server_name](DispatchDestinationSnapshot const& snapshot) {
            return snapshot.server_name == server_name;
        });
    if (existing != destinations_.end())
    {
        return existing->state;
    }
    auto destination = FederationDestination{};
    destination.server_name = std::string{server_name};
    destinations_.push_back({std::string{server_name}, std::move(destination)});
    return destinations_.back().state;
}

auto DispatchWorker::remember_destination_locked(FederationDestination const& destination) -> void
{
    find_or_create_destination(destination.server_name) = destination;
    if (persistent_store_ != nullptr)
    {
        std::ignore =
            database::store_federation_destination(*persistent_store_, to_persistent_destination(destination));
    }
    auto const held = queued_per_destination_.find(destination.server_name);
    auto const slots = held != queued_per_destination_.end() ? held->second : std::size_t{0U};
    auto const failing = failing_destinations_.find(destination.server_name);
    if (destination.consecutive_failures == 0U)
    {
        if (failing != failing_destinations_.end())
        {
            failing_slots_ -= std::min(failing_slots_, slots);
            failing_destinations_.erase(failing);
        }
        return;
    }
    set_slow_locked(destination.server_name, false);
    if (failing == failing_destinations_.end())
    {
        failing_slots_ += slots;
        failing_destinations_.emplace(destination.server_name, destination.retry_after_ts);
    }
    else
    {
        failing->second = destination.retry_after_ts;
    }
    shed_failing_over_share_locked();
}

auto DispatchWorker::re_enqueue_with_backoff(OutboundTransaction transaction, std::uint64_t now_ts) -> void
{
    transaction.retry_count += 1U;
    if (transaction.retry_count >= config_.max_retries)
    {
        log_diagnostic("transaction.dropped", {
                                                  {"transaction_id", transaction.transaction_id,              false},
                                                  {"destination",    transaction.destination,                 false},
                                                  {"retry_count",    std::to_string(transaction.retry_count), false},
                                                  {"reason",         "max retries exhausted",                 false}
        });
        // Hold the worker mutex while mutating durable state. The persistent
        // store helpers mutate shared vectors in-place; enqueue/run_once also
        // touch them under this same mutex, so without serialization the
        // concurrent access is a data race. If the durable delete fails we
        // surface the transaction as failed instead of dropping it cleanly,
        // so the row survives in storage and is replayed next start.
        auto lock = std::lock_guard{mutex_};
        release_destination_slot_locked(transaction.destination);
        if (persistent_store_ != nullptr &&
            !database::delete_federation_transaction(*persistent_store_, transaction.transaction_id))
        {
            ++summary_.failed;
            return;
        }
        ++summary_.dropped;
        return;
    }
    transaction.next_retry_ts = now_ts + compute_backoff(transaction.retry_count);
    log_diagnostic("transaction.retried", {
                                              {"transaction_id", transaction.transaction_id,                false},
                                              {"destination",    transaction.destination,                   false},
                                              {"retry_count",    std::to_string(transaction.retry_count),   false},
                                              {"next_retry_ts",  std::to_string(transaction.next_retry_ts), false}
    });
    {
        auto lock = std::lock_guard{mutex_};
        // Persist the bumped retry state before re-queuing. A persist failure
        // is a hard failure: silently re-queuing would let durable retry
        // state diverge from in-memory state, and on restart the older
        // (or missing) durable row would replace the live one.
        if (persistent_store_ != nullptr &&
            !database::store_federation_transaction(*persistent_store_, to_persistent_transaction(transaction)))
        {
            release_destination_slot_locked(transaction.destination);
            ++summary_.failed;
            return;
        }
        requeue_locked(std::move(transaction));
        ++summary_.pending;
    }
    cv_.notify_one();
}

auto DispatchWorker::run_once() -> bool
{
    return run_due(now_ms_());
}

auto DispatchWorker::run_due(std::uint64_t due_by) -> bool
{
    {
        auto lock = std::lock_guard{mutex_};
        sweep_aged_locked(now_ms_());
    }
    auto transaction = OutboundTransaction{};
    if (!take_next(transaction, due_by))
    {
        return false;
    }
    auto const in_flight = InFlightSlot{*this, transaction.destination};
    attempt(std::move(transaction));
    return true;
}

auto DispatchWorker::wait_out_open_circuit(OutboundTransaction transaction, FederationDestination const& destination,
                                           std::uint64_t now_ts) -> void
{
    log_diagnostic("transaction.circuit_open", {
                                                   {"transaction_id", transaction.transaction_id,              false},
                                                   {"destination",    transaction.destination,                 false},
                                                   {"retry_count",    std::to_string(transaction.retry_count), false}
    });
    transaction.next_retry_ts = destination.retry_after_ts > now_ts ? destination.retry_after_ts
                                                                    : now_ts + compute_backoff(transaction.retry_count);
    {
        auto lock = std::lock_guard{mutex_};
        ++summary_.failed;
        // Same hard-failure rule as re_enqueue_with_backoff: persisting the
        // updated next_retry_ts must succeed before we trust the in-memory
        // queue entry to remain authoritative across a restart.
        if (persistent_store_ != nullptr &&
            !database::store_federation_transaction(*persistent_store_, to_persistent_transaction(transaction)))
        {
            release_destination_slot_locked(transaction.destination);
            ++summary_.failed;
            return;
        }
        requeue_locked(std::move(transaction));
        ++summary_.pending;
    }
    cv_.notify_one();
}

auto DispatchWorker::attempt(OutboundTransaction transaction) -> void
{
    auto const now = now_ms_();
    auto destination = FederationDestination{};
    {
        auto lock = std::lock_guard{mutex_};
        destination = find_or_create_destination(transaction.destination);
    }
    // Before discovery: a destination that is backing off takes no thread at all, so a peer whose
    // discovery stalls holds one only as often as its backoff allows.
    if (!destination_should_retry(destination, now))
    {
        wait_out_open_circuit(std::move(transaction), destination, now);
        return;
    }

    auto resolution = resolver_ ? resolver_(transaction.destination) : std::nullopt;
    if (!resolution.has_value() || !resolution->discovery_allowed)
    {
        log_diagnostic("transaction.discovery_failed",
                       {
                           {"transaction_id", transaction.transaction_id,              false},
                           {"destination",    transaction.destination,                 false},
                           {"retry_count",    std::to_string(transaction.retry_count), false}
        });
        // Resolver failure: surface as a transport failure so the destination
        // accounting captures it, and let the backoff curve gate the next
        // attempt. The transaction goes back on the queue with retry+1.
        // ADR-0309: the backoff runs from when the failure was known, not from when the attempt began.
        auto const failed_at = now_ms_();
        auto result = OutboundTransactionResult{};
        result.sent = false;
        result.error = "discovery_failed";
        apply_outbound_result(destination, result, failed_at);
        {
            auto lock = std::lock_guard{mutex_};
            remember_destination_locked(destination);
            ++summary_.failed;
        }
        re_enqueue_with_backoff(std::move(transaction), failed_at);
        return;
    }

    auto call = OutboundCall{};
    call.transaction = transaction;
    call.resolved_host = resolution->resolved_host;
    // M-02: carry the certificate identity alongside the resolved target.
    call.tls_server_name = resolution->tls_server_name;
    call.resolved_port = resolution->resolved_port;
    call.pinned_addresses = resolution->pinned_addresses;
    // Take a private copy of the signing identity under the lock:
    // update_signing_identity may replace config_.secret_key while this attempt
    // is mid-flight, so OutboundCall owns its own mlocked copy.
    {
        auto lock = std::lock_guard{mutex_};
        call.key_id = config_.key_id;
        call.secret_key = core::SecretBuffer{config_.secret_key.bytes()};
        call.total_timeout_seconds = config_.attempt_timeout_seconds;
        call.trusted_ca_pem = config_.trusted_ca_pem;
    }

    auto const failures_before = destination.consecutive_failures;
    auto const result = perform_outbound_transaction(client_, call, destination, now, now_ms_);
    // ADR-0309: every retry scheduled below runs from the end of this attempt.
    auto const finished_at = now_ms_();

    if (result.sent && result.http_status >= 200U && result.http_status < 300U)
    {
        log_diagnostic("transaction.delivered", {
                                                    {"transaction_id", transaction.transaction_id,         false},
                                                    {"destination",    transaction.destination,            false},
                                                    {"http_status",    std::to_string(result.http_status), false}
        });
        // ADR-0354: answering just inside the deadline must not make a peer free to hold a thread for
        // every transaction it is sent.
        if (finished_at > now && finished_at - now > config_.slow_attempt_ms)
        {
            apply_slow_success(destination, failures_before, finished_at);
            log_diagnostic("transaction.slow_success",
                           {
                               {"destination", transaction.destination,                          false},
                               {"elapsed_ms",  std::to_string(finished_at - now),                false},
                               {"failures",    std::to_string(destination.consecutive_failures), false}
            },
                           observability::LogEventSeverity::warning);
        }
        // Persist destination success state and drop the durable queue row.
        // If the durable delete fails, do NOT count the transaction as
        // delivered: leaving the row would cause replay-on-restart to re-send
        // a transaction this run already reported as delivered. Treat as a
        // transport failure and let the standard retry path handle it.
        auto durable_drop_failed = false;
        {
            auto lock = std::lock_guard{mutex_};
            remember_destination_locked(destination);
            // C20: an answer that took more than a quarter of the slow limit marks the destination slow, a quicker one
            // clears it.
            set_slow_locked(transaction.destination, destination.consecutive_failures == 0U && finished_at > now &&
                                                         (finished_at - now) > config_.slow_attempt_ms / 4U);
            if (persistent_store_ != nullptr &&
                !database::delete_federation_transaction(*persistent_store_, transaction.transaction_id))
            {
                durable_drop_failed = true;
                ++summary_.failed;
            }
            if (!durable_drop_failed)
            {
                release_destination_slot_locked(transaction.destination);
                ++summary_.delivered;
            }
        }
        if (durable_drop_failed)
        {
            re_enqueue_with_backoff(std::move(transaction), finished_at);
        }
        return;
    }
    {
        auto lock = std::lock_guard{mutex_};
        remember_destination_locked(destination);
        ++summary_.failed;
    }
    re_enqueue_with_backoff(std::move(transaction), finished_at);
}

auto DispatchWorker::top_up_replay_locked() -> std::size_t
{
    auto promoted = std::size_t{0U};
    auto const now = now_ms_();
    // Look at each parked row at most once. A row whose destination is at its share goes to the
    // back, so it does not hold up rows for other destinations.
    for (auto remaining = pending_replay_.size(); remaining > 0U && !pending_replay_.empty(); --remaining)
    {
        if (config_.max_queue_depth != 0U && queue_.size() >= config_.max_queue_depth)
        {
            break;
        }
        auto row = std::move(pending_replay_.front());
        pending_replay_.pop_front();
        if (destination_at_share_locked(row.destination) || failing_share_reached_locked(row.destination, now, 0U))
        {
            pending_replay_.push_back(std::move(row));
            continue;
        }
        push_queue_locked(std::move(row));
        ++summary_.enqueued;
        ++summary_.pending;
        ++promoted;
    }
    return promoted;
}

auto DispatchWorker::replay_pending() -> std::size_t
{
    if (persistent_store_ == nullptr)
    {
        return 0U;
    }
    auto replayed = std::size_t{0U};
    {
        auto lock = std::lock_guard{mutex_};
        for (auto const& destination : persistent_store_->federation_destinations)
        {
            auto existing =
                std::ranges::find_if(destinations_, [&destination](DispatchDestinationSnapshot const& snapshot) {
                    return snapshot.server_name == destination.server_name;
                });
            if (existing != destinations_.end())
            {
                existing->state = to_federation_destination(destination);
                continue;
            }
            destinations_.push_back({destination.server_name, to_federation_destination(destination)});
        }
        for (auto const& destination : persistent_store_->federation_destinations)
        {
            if (destination.consecutive_failures > 0U)
            {
                failing_destinations_.insert_or_assign(destination.server_name, destination.retry_after_ts);
            }
        }
        auto const now = now_ms_();
        // A row can outlive the policy it was queued under (ADR-0391). It will never be sent, so it goes.
        auto excluded_rows = std::vector<std::string>{};
        for (auto const& transaction : persistent_store_->federation_transactions)
        {
            auto outbound = to_outbound_transaction(transaction);
            if (!transaction_is_well_formed(outbound))
            {
                continue;
            }
            if (config_.destination_refusal && !config_.destination_refusal(outbound.destination).empty())
            {
                excluded_rows.push_back(std::move(outbound.transaction_id));
                continue;
            }
            if (outbound.origin_server_ts.empty())
            {
                outbound.origin_server_ts = std::to_string(now);
            }
            if ((config_.max_queue_depth != 0U && queue_.size() >= config_.max_queue_depth) ||
                destination_at_share_locked(outbound.destination) ||
                failing_share_reached_locked(outbound.destination, now, 0U))
            {
                // Park overflow, and rows past their destination's share, in pending_replay_
                // instead of stranding them in durable storage. top_up_replay_locked() pulls
                // them in as in-flight work completes.
                pending_replay_.push_back(std::move(outbound));
                continue;
            }
            push_queue_locked(std::move(outbound));
            ++summary_.enqueued;
            ++summary_.pending;
            ++replayed;
        }
        for (auto const& transaction_id : excluded_rows)
        {
            if (database::delete_federation_transaction(*persistent_store_, transaction_id))
            {
                ++summary_.dropped;
            }
            else
            {
                ++summary_.failed;
            }
        }
    }
    cv_.notify_one();
    return replayed;
}

auto DispatchWorker::loop() -> void
{
    while (!shutdown_requested_.load())
    {
        if (!run_once())
        {
            // Wait for a transaction that is due, an enqueue, or shutdown. A queue holding only
            // transactions still in backoff is no reason to wake: waking on "not empty" spun this
            // thread for the whole backoff (ADR-0309).
            auto lock = std::unique_lock{mutex_};
            cv_.wait_for(lock, config_.idle_poll, [this] {
                return shutdown_requested_.load() || next_ready_locked(now_ms_()).has_value();
            });
        }
    }
    // Drain phase: shutdown was requested. Process what was due when the drain began, so work
    // already scheduled completes. A transaction that fails during the drain is due again only
    // later, so it stays pending and durable replay handles it next start; retrying it here kept
    // a process whose peer was down alive until it was killed (ADR-0309). The budget bounds the rest:
    // what it does not reach stays durable (ADR-0354).
    auto due_by = std::uint64_t{0U};
    auto deadline = std::chrono::steady_clock::time_point{};
    {
        auto lock = std::lock_guard{mutex_};
        if (!drain_due_by_.has_value())
        {
            drain_due_by_ = now_ms_();
            drain_deadline_ = std::chrono::steady_clock::now() + config_.shutdown_drain_budget;
        }
        due_by = *drain_due_by_;
        deadline = drain_deadline_;
    }
    while (std::chrono::steady_clock::now() < deadline && run_due(due_by))
    {
    }
}

auto DispatchWorker::signing_key_id() const -> std::string
{
    auto lock = std::lock_guard{mutex_};
    return config_.key_id;
}

auto DispatchWorker::update_signing_identity(std::string key_id, core::SecretBuffer secret_key) -> void
{
    auto lock = std::lock_guard{mutex_};
    config_.key_id = std::move(key_id);
    config_.secret_key = std::move(secret_key);
}

auto DispatchWorker::summary() const noexcept -> DispatchWorkerSummary
{
    auto lock = std::lock_guard{mutex_};
    return summary_;
}

} // namespace merovingian::federation
