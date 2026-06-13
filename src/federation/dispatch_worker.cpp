// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/federation/dispatch_worker.hpp"

#include "merovingian/observability/logger.hpp"
#include "merovingian/observability/observability.hpp"

#include <algorithm>
#include <chrono>
#include <string>
#include <thread>
#include <tuple>
#include <utility>
#include <vector>

namespace merovingian::federation
{
namespace
{

    auto log_diagnostic(std::string_view event, std::vector<observability::StructuredLogField> fields) -> void
    {
        LOG_DEBUG(observability::diagnostic_log_summary("dispatch_worker", event, std::move(fields)));
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
    if (!transaction_is_well_formed(transaction))
    {
        log_diagnostic("enqueue.rejected",
                       {{"transaction_id", transaction.transaction_id, false},
                        {"destination", transaction.destination, false},
                        {"reason", "transaction is malformed", false}});
        return false;
    }
    {
        auto lock = std::lock_guard{mutex_};
        if (shutdown_requested_.load(std::memory_order_acquire))
        {
            log_diagnostic("enqueue.rejected",
                           {{"transaction_id", transaction.transaction_id, false},
                            {"destination", transaction.destination, false},
                            {"reason", "worker is shutting down", false}});
            return false;
        }
        if (config_.max_queue_depth != 0U && queue_.size() >= config_.max_queue_depth)
        {
            log_diagnostic("enqueue.rejected",
                           {{"transaction_id", transaction.transaction_id, false},
                            {"destination", transaction.destination, false},
                            {"queue_depth", std::to_string(queue_.size()), false},
                            {"reason", "queue depth limit reached", false}});
            return false;
        }
        if (persistent_store_ != nullptr &&
            !database::store_federation_transaction(*persistent_store_, to_persistent_transaction(transaction)))
        {
            log_diagnostic("enqueue.rejected",
                           {{"transaction_id", transaction.transaction_id, false},
                            {"destination", transaction.destination, false},
                            {"reason", "failed to persist transaction", false}});
            return false;
        }
        queue_.push_back(std::move(transaction));
        ++summary_.enqueued;
        ++summary_.pending;
    }
    cv_.notify_one();
    return true;
}

auto DispatchWorker::start() -> void
{
    auto already_started = started_.exchange(true, std::memory_order_acq_rel);
    if (already_started)
    {
        return;
    }
    thread_ = std::thread{[this] {
        loop();
    }};
}

auto DispatchWorker::request_shutdown() noexcept -> void
{
    shutdown_requested_.store(true, std::memory_order_release);
    cv_.notify_all();
}

auto DispatchWorker::join() -> void
{
    if (thread_.joinable())
    {
        thread_.join();
    }
}

auto DispatchWorker::take_next(OutboundTransaction& out) -> bool
{
    auto lock = std::lock_guard{mutex_};
    if (queue_.empty())
    {
        return false;
    }
    auto const now = now_ms_();
    // Pull the next transaction whose retry delay has elapsed. Skipping
    // future-scheduled retries preserves FIFO among ready work without
    // burning CPU on items still in backoff.
    auto const ready = std::ranges::find_if(queue_, [now](OutboundTransaction const& candidate) {
        return candidate.next_retry_ts <= now;
    });
    if (ready == queue_.end())
    {
        return false;
    }
    out = std::move(*ready);
    queue_.erase(ready);
    // Removing an entry frees a slot under max_queue_depth — top up the
    // active queue from any replay overflow that was parked at startup.
    std::ignore = top_up_replay_locked();
    return true;
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

auto DispatchWorker::re_enqueue_with_backoff(OutboundTransaction transaction, std::uint64_t now_ts) -> void
{
    transaction.retry_count += 1U;
    if (transaction.retry_count >= config_.max_retries)
    {
        log_diagnostic("transaction.dropped",
                       {{"transaction_id", transaction.transaction_id, false},
                        {"destination", transaction.destination, false},
                        {"retry_count", std::to_string(transaction.retry_count), false},
                        {"reason", "max retries exhausted", false}});
        // Hold the worker mutex while mutating durable state. The persistent
        // store helpers mutate shared vectors in-place; enqueue/run_once also
        // touch them under this same mutex, so without serialization the
        // concurrent access is a data race. If the durable delete fails we
        // surface the transaction as failed instead of dropping it cleanly,
        // so the row survives in storage and is replayed next start.
        auto lock = std::lock_guard{mutex_};
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
    log_diagnostic("transaction.retried",
                   {{"transaction_id", transaction.transaction_id, false},
                    {"destination", transaction.destination, false},
                    {"retry_count", std::to_string(transaction.retry_count), false},
                    {"next_retry_ts", std::to_string(transaction.next_retry_ts), false}});
    {
        auto lock = std::lock_guard{mutex_};
        // Persist the bumped retry state before re-queuing. A persist failure
        // is a hard failure: silently re-queuing would let durable retry
        // state diverge from in-memory state, and on restart the older
        // (or missing) durable row would replace the live one.
        if (persistent_store_ != nullptr &&
            !database::store_federation_transaction(*persistent_store_, to_persistent_transaction(transaction)))
        {
            ++summary_.failed;
            return;
        }
        queue_.push_back(std::move(transaction));
        ++summary_.pending;
    }
    cv_.notify_one();
}

auto DispatchWorker::run_once() -> bool
{
    auto transaction = OutboundTransaction{};
    if (!take_next(transaction))
    {
        return false;
    }
    {
        auto lock = std::lock_guard{mutex_};
        if (summary_.pending > 0U)
        {
            --summary_.pending;
        }
    }

    auto const now = now_ms_();
    auto resolution = resolver_ ? resolver_(transaction.destination) : std::nullopt;
    if (!resolution.has_value() || !resolution->discovery_allowed)
    {
        log_diagnostic("transaction.discovery_failed",
                       {{"transaction_id", transaction.transaction_id, false},
                        {"destination", transaction.destination, false},
                        {"retry_count", std::to_string(transaction.retry_count), false}});
        // Resolver failure: surface as a transport failure so the destination
        // accounting captures it, and let the backoff curve gate the next
        // attempt. The transaction goes back on the queue with retry+1.
        auto& destination = find_or_create_destination(transaction.destination);
        auto result = OutboundTransactionResult{};
        result.sent = false;
        result.error = "discovery_failed";
        apply_outbound_result(destination, result, now);
        {
            auto lock = std::lock_guard{mutex_};
            if (persistent_store_ != nullptr)
            {
                std::ignore = database::store_federation_destination(*persistent_store_,
                                                             to_persistent_destination(destination));
            }
            ++summary_.failed;
        }
        re_enqueue_with_backoff(std::move(transaction), now);
        return true;
    }

    auto call = OutboundCall{};
    call.transaction = transaction;
    call.resolved_host = resolution->resolved_host;
    call.resolved_port = resolution->resolved_port;
    call.pinned_addresses = resolution->pinned_addresses;
    call.key_id = config_.key_id;
    call.secret_key = config_.secret_key;

    auto& destination = find_or_create_destination(transaction.destination);
    auto const result = perform_outbound_transaction(client_, call, destination, now);

    if (result.sent && result.http_status >= 200U && result.http_status < 300U)
    {
        log_diagnostic("transaction.delivered",
                       {{"transaction_id", transaction.transaction_id, false},
                        {"destination", transaction.destination, false},
                        {"http_status", std::to_string(result.http_status), false}});
        // Persist destination success state and drop the durable queue row.
        // If the durable delete fails, do NOT count the transaction as
        // delivered: leaving the row would cause replay-on-restart to re-send
        // a transaction this run already reported as delivered. Treat as a
        // transport failure and let the standard retry path handle it.
        auto durable_drop_failed = false;
        {
            auto lock = std::lock_guard{mutex_};
            if (persistent_store_ != nullptr)
            {
                std::ignore = database::store_federation_destination(*persistent_store_,
                                                             to_persistent_destination(destination));
                if (!database::delete_federation_transaction(*persistent_store_, transaction.transaction_id))
                {
                    durable_drop_failed = true;
                    ++summary_.failed;
                }
            }
            if (!durable_drop_failed)
            {
                ++summary_.delivered;
            }
        }
        if (durable_drop_failed)
        {
            re_enqueue_with_backoff(std::move(transaction), now);
        }
        return true;
    }
    {
        auto lock = std::lock_guard{mutex_};
        if (persistent_store_ != nullptr)
        {
            std::ignore = database::store_federation_destination(*persistent_store_, to_persistent_destination(destination));
        }
        ++summary_.failed;
    }
    if (result.error == "circuit_open")
    {
        log_diagnostic("transaction.circuit_open",
                       {{"transaction_id", transaction.transaction_id, false},
                        {"destination", transaction.destination, false},
                        {"retry_count", std::to_string(transaction.retry_count), false}});
        transaction.next_retry_ts = destination.retry_after_ts > now ? destination.retry_after_ts
                                                                     : now + compute_backoff(transaction.retry_count);
        {
            auto lock = std::lock_guard{mutex_};
            // Same hard-failure rule as re_enqueue_with_backoff: persisting the
            // updated next_retry_ts must succeed before we trust the in-memory
            // queue entry to remain authoritative across a restart.
            if (persistent_store_ != nullptr &&
                !database::store_federation_transaction(*persistent_store_, to_persistent_transaction(transaction)))
            {
                ++summary_.failed;
                return true;
            }
            queue_.push_back(std::move(transaction));
            ++summary_.pending;
        }
        cv_.notify_one();
        return true;
    }
    re_enqueue_with_backoff(std::move(transaction), now);
    return true;
}

auto DispatchWorker::top_up_replay_locked() -> std::size_t
{
    auto promoted = std::size_t{0U};
    while (!pending_replay_.empty())
    {
        if (config_.max_queue_depth != 0U && queue_.size() >= config_.max_queue_depth)
        {
            break;
        }
        queue_.push_back(std::move(pending_replay_.front()));
        pending_replay_.pop_front();
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
        for (auto const& transaction : persistent_store_->federation_transactions)
        {
            auto outbound = to_outbound_transaction(transaction);
            if (!transaction_is_well_formed(outbound))
            {
                continue;
            }
            if (config_.max_queue_depth != 0U && queue_.size() >= config_.max_queue_depth)
            {
                // Park overflow in pending_replay_ instead of stranding it in
                // durable storage. top_up_replay_locked() pulls more rows in
                // as in-flight work completes.
                pending_replay_.push_back(std::move(outbound));
                continue;
            }
            queue_.push_back(std::move(outbound));
            ++summary_.enqueued;
            ++summary_.pending;
            ++replayed;
        }
    }
    cv_.notify_one();
    return replayed;
}

auto DispatchWorker::loop() -> void
{
    while (!shutdown_requested_.load(std::memory_order_acquire))
    {
        if (!run_once())
        {
            auto lock = std::unique_lock{mutex_};
            cv_.wait_for(lock, config_.idle_poll, [this] {
                return !queue_.empty() || shutdown_requested_.load(std::memory_order_acquire);
            });
        }
    }
    // Drain phase: shutdown was requested. Continue processing transactions
    // whose retry deadline is reached so in-flight work completes. Work
    // still in backoff stays pending and durable replay handles it next start.
    while (true)
    {
        if (!run_once())
        {
            break;
        }
    }
}

auto DispatchWorker::summary() const noexcept -> DispatchWorkerSummary
{
    auto lock = std::lock_guard{mutex_};
    return summary_;
}

} // namespace merovingian::federation
