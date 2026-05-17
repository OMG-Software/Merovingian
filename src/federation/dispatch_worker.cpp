// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/federation/dispatch_worker.hpp"

#include <algorithm>
#include <chrono>
#include <thread>
#include <utility>

namespace merovingian::federation
{
namespace
{

    [[nodiscard]] auto transaction_is_well_formed(OutboundTransaction const& transaction) noexcept -> bool
    {
        return !transaction.destination.empty() && !transaction.method.empty() && !transaction.target.empty() &&
               !transaction.origin.empty();
    }

    [[nodiscard]] auto default_now_ms() -> std::uint64_t
    {
        return static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch())
                .count());
    }

    auto default_sleep_for(std::chrono::milliseconds duration) -> void
    {
        std::this_thread::sleep_for(duration);
    }

} // namespace

DispatchWorker::DispatchWorker(DispatchWorkerConfig config, http::OutboundClient& client, DispatchResolver resolver,
                               DispatchClock now_ms, DispatchSleep sleep_for)
    : config_{std::move(config)}
    , client_{client}
    , resolver_{std::move(resolver)}
    , now_ms_{now_ms ? std::move(now_ms) : DispatchClock{default_now_ms}}
    , sleep_for_{sleep_for ? std::move(sleep_for) : DispatchSleep{default_sleep_for}}
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
        return false;
    }
    {
        auto lock = std::lock_guard{mutex_};
        if (shutdown_requested_.load(std::memory_order_acquire))
        {
            return false;
        }
        if (config_.max_queue_depth != 0U && queue_.size() >= config_.max_queue_depth)
        {
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
    thread_ = std::thread{[this] { loop(); }};
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
        auto lock = std::lock_guard{mutex_};
        ++summary_.dropped;
        return;
    }
    transaction.next_retry_ts = now_ts + compute_backoff(transaction.retry_count);
    {
        auto lock = std::lock_guard{mutex_};
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
    call.verify_token = config_.verify_token;
    call.origin_server_ts = now;

    auto& destination = find_or_create_destination(transaction.destination);
    auto const result = perform_outbound_transaction(client_, call, destination, now);

    if (result.sent && result.http_status >= 200U && result.http_status < 300U)
    {
        auto lock = std::lock_guard{mutex_};
        ++summary_.delivered;
        return true;
    }
    {
        auto lock = std::lock_guard{mutex_};
        ++summary_.failed;
    }
    // Don't requeue a circuit-open result on the spot: the destination
    // already says "wait until retry_after_ts", so we surface the failure
    // and let the next enqueue or external retry trigger reattempt.
    if (result.error != "circuit_open")
    {
        re_enqueue_with_backoff(std::move(transaction), now);
    }
    return true;
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
    // still in backoff stays on the queue and is reported as pending in the
    // summary — the persistent replay (item 2) takes responsibility for it.
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
