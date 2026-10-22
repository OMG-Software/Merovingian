// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/push_retry.hpp"

#include "merovingian/homeserver/runtime.hpp"
#include "merovingian/observability/logger.hpp"

#include <algorithm>
#include <mutex>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

namespace merovingian::homeserver
{
namespace
{

    // Push delivery has always logged under the rooms logger (room_service.cpp).
    auto log_push(std::string_view event, std::vector<observability::StructuredLogField> fields,
                  observability::LogEventSeverity severity = observability::LogEventSeverity::debug) -> void
    {
        observability::log_diagnostic("rooms", event, fields, severity);
    }

    // Counts the attempt that just failed and queues the next one, or gives up.
    auto schedule_retry(HomeserverRuntime& runtime, push::PushRetry delivery, std::chrono::steady_clock::time_point now)
        -> void
    {
        ++delivery.failed_attempts;
        auto const user_id = delivery.user_id;
        auto const attempts = std::to_string(delivery.failed_attempts);
        auto const admission = runtime.push_retry_queue_ == nullptr
                                   ? push::PushRetryAdmission::queue_full
                                   : runtime.push_retry_queue_->schedule(std::move(delivery), now);
        switch (admission)
        {
        case push::PushRetryAdmission::queued:
            log_push("push.delivery.retry_scheduled",
                     {
                         {"recipient", user_id,  false},
                         {"attempts",  attempts, false}
            });
            break;
        case push::PushRetryAdmission::gave_up:
            log_push("push.delivery.gave_up",
                     {
                         {"recipient", user_id,  false},
                         {"attempts",  attempts, false}
            },
                     observability::LogEventSeverity::warning);
            break;
        case push::PushRetryAdmission::queue_full:
            log_push("push.delivery.retry_dropped",
                     {
                         {"recipient", user_id,  false},
                         {"attempts",  attempts, false}
            },
                     observability::LogEventSeverity::warning);
            break;
        }
    }

    // Whether `delivery`'s pusher is still registered with the URL the retry would use. A pusher
    // removed or re-pointed since the first attempt must not be sent to.
    [[nodiscard]] auto pusher_still_registered(HomeserverRuntime& runtime, push::PushRetry const& delivery) -> bool
    {
        auto const guard = std::unique_lock<RuntimeMutex>{runtime.mutex};
        auto const pushers = database::list_pushers_for_user(runtime.database.persistent_store, delivery.user_id);
        return std::ranges::any_of(pushers, [&delivery](database::PersistentPusher const& pusher) {
            return pusher.app_id == delivery.app_id && pusher.pushkey == delivery.pushkey &&
                   pusher.data_url == delivery.gateway_url;
        });
    }

} // namespace

auto attempt_push_delivery(HomeserverRuntime& runtime, push::PushGatewayClient& client, push::PushRetry delivery,
                           std::chrono::steady_clock::time_point now) -> void
{
    // A failure is scheduled from when it happened: `now` plus the time this attempt has taken. A
    // gateway can take its whole timeout to answer with an error, which would otherwise use up the
    // backoff before the retry is queued.
    auto const attempt_started = std::chrono::steady_clock::now();
    auto const failed_at = [&now, attempt_started]() {
        return now + (std::chrono::steady_clock::now() - attempt_started);
    };
    auto const& push_config = runtime.config.server().push;
    auto const breaker_policy = push::GatewayCircuitBreakerPolicy{
        push_config.gateway_failure_threshold, std::chrono::seconds{push_config.gateway_cooldown_seconds}};
    // OUT-3, ADR-0151: a host that keeps failing is skipped for a cooldown, so its stalled requests
    // stop holding delivery capacity. The skipped notification is retried like a failed one.
    auto const host = push::push_gateway_host(delivery.gateway_url);
    if (host.has_value() && runtime.push_gateway_breaker_ != nullptr &&
        !runtime.push_gateway_breaker_->allow(*host, std::chrono::steady_clock::now(), breaker_policy))
    {
        log_push("push.delivery.circuit_open",
                 {
                     {"gateway_host", *host,            false},
                     {"recipient",    delivery.user_id, false}
        },
                 observability::LogEventSeverity::warning);
        schedule_retry(runtime, std::move(delivery), failed_at());
        return;
    }
    auto const result = client.notify(delivery.gateway_url, delivery.notification);
    // ADR-0151: only an unreachable host counts toward its circuit; any HTTP answer, a 5xx included,
    // shows the shared host is reachable.
    if (auto const outcome = push::gateway_circuit_outcome(result);
        host.has_value() && runtime.push_gateway_breaker_ != nullptr &&
        outcome != push::GatewayCircuitOutcome::not_attempted)
    {
        runtime.push_gateway_breaker_->record(*host, outcome == push::GatewayCircuitOutcome::reachable,
                                              std::chrono::steady_clock::now(), breaker_policy);
    }
    // Spec: "Homeservers must cease sending notification requests for these pushkeys and remove the
    // associated pushers." That includes the retries already queued for the pushkey.
    if (push::pushkey_was_rejected(result, delivery.pushkey))
    {
        {
            auto const guard = std::unique_lock<RuntimeMutex>{runtime.mutex};
            std::ignore = database::delete_pusher(runtime.database.persistent_store, delivery.user_id, delivery.app_id,
                                                  delivery.pushkey);
        }
        if (runtime.push_retry_queue_ != nullptr)
        {
            std::ignore = runtime.push_retry_queue_->drop_pushkey(delivery.app_id, delivery.pushkey);
        }
        return;
    }
    if (push::push_delivery_should_retry(result))
    {
        schedule_retry(runtime, std::move(delivery), failed_at());
    }
}

auto retry_due_push_deliveries(HomeserverRuntime& runtime, StopFlag const& stop,
                               std::chrono::steady_clock::time_point now) -> std::chrono::milliseconds
{
    auto const idle = std::chrono::milliseconds{push_retry_idle_delay};
    if (runtime.push_retry_queue_ == nullptr)
    {
        return idle;
    }
    auto due = runtime.push_retry_queue_->take_due(now, push_retry_batch);
    // A batch can take up to its size times the gateway timeout. Time spent in it is added to `now`,
    // so a failure late in the batch is scheduled from when it failed and the next wait is not cut
    // short by the time the batch took.
    auto const batch_started = std::chrono::steady_clock::now();
    auto const current = [&now, batch_started]() {
        return now + (std::chrono::steady_clock::now() - batch_started);
    };
    if (!due.empty() && runtime.outbound_client != nullptr && runtime.cached_discovery != nullptr)
    {
        auto client =
            push::PushGatewayClient{*runtime.outbound_client, *runtime.cached_discovery, runtime.config.server().push,
                                    &runtime.test_forced_push_gateway_resolution};
        for (auto& delivery : due)
        {
            if (stop.stop_requested())
            {
                break;
            }
            if (!pusher_still_registered(runtime, delivery))
            {
                log_push("push.delivery.retry_abandoned",
                         {
                             {"recipient", delivery.user_id,       false},
                             {"reason",    "pusher no longer set", false}
                });
                continue;
            }
            attempt_push_delivery(runtime, client, std::move(delivery), current());
        }
    }
    auto const next = runtime.push_retry_queue_->next_due();
    if (!next.has_value())
    {
        return idle;
    }
    auto const wait = std::chrono::duration_cast<std::chrono::milliseconds>(*next - current());
    return std::clamp(wait, std::chrono::milliseconds{std::chrono::seconds{1}}, idle);
}

PushRetryJob::PushRetryJob(HomeserverRuntime& runtime)
    : runtime_{runtime}
    , job_{"push-retry", [&runtime](StopFlag const& stop) {
               return retry_due_push_deliveries(runtime, stop, std::chrono::steady_clock::now());
           }}
{
}

PushRetryJob::~PushRetryJob()
{
    stop();
}

auto PushRetryJob::start() -> bool
{
    if (!job_.start())
    {
        return false;
    }
    if (runtime_.push_retry_queue_ != nullptr)
    {
        runtime_.push_retry_queue_->set_wake([this]() {
            job_.wake();
        });
    }
    return true;
}

auto PushRetryJob::stop() noexcept -> void
{
    if (runtime_.push_retry_queue_ != nullptr)
    {
        try
        {
            runtime_.push_retry_queue_->set_wake({});
        }
        catch (...)
        {
            // Clearing a std::function does not throw; set_wake's mutex could, in principle.
        }
    }
    job_.stop();
}

} // namespace merovingian::homeserver
