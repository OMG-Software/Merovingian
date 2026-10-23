// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/push/push_gateway_client.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace merovingian::push
{

// Spec (push-gateway-api.md): "If the endpoint returns an HTTP error code, the homeserver SHOULD
// retry for a reasonable amount of time using exponential backoff." (R14, ADR-0206.) A failed
// notification is tried again after 5 s, doubling to at most 10 minutes, and given up after 8
// retries: about 20 minutes after the first attempt.
inline constexpr auto push_retry_initial_backoff = std::chrono::seconds{5};
inline constexpr auto push_retry_max_backoff = std::chrono::minutes{10};
inline constexpr auto push_retry_max_retries = std::uint32_t{8U};
// How many notifications wait for a retry, in all and per recipient. A notification carries the
// event's content (up to 64 KiB), so the queue is bounded in memory; a retry past either bound is
// dropped and logged, as ADR-0028 drops deliveries past the in-flight cap.
inline constexpr auto push_retry_queue_capacity = std::size_t{1024U};
inline constexpr auto push_retry_per_user_capacity = std::size_t{32U};

// The wait before the retry that follows `failed_attempts` failed attempts (at least 1).
[[nodiscard]] auto push_retry_backoff(std::uint32_t failed_attempts) noexcept -> std::chrono::milliseconds;

// Whether a notification whose attempt ended with `result` is tried again: when the gateway
// answered with an HTTP error status, or could not be reached. Not when it accepted the
// notification, when delivery is disabled, or when this server refused the URL or the response
// (a retry would be refused again). A rejected pushkey is never retried; see
// pushkey_was_rejected.
[[nodiscard]] auto push_delivery_should_retry(PushGatewayResult const& result) noexcept -> bool;

// One notification to one pusher that failed and may be tried again.
struct PushRetry final
{
    std::string user_id{};
    std::string app_id{};
    std::string pushkey{};
    std::string gateway_url{};
    PushGatewayNotification notification{};
    // Attempts that have failed: 0 before the first attempt. schedule() is given the count that
    // includes the attempt that has just failed.
    std::uint32_t failed_attempts{0U};
    std::chrono::steady_clock::time_point due{};
};

enum class PushRetryAdmission : std::uint8_t
{
    queued,
    // push_retry_max_retries retries have already been made.
    gave_up,
    // The queue, or the recipient's share of it, is full.
    queue_full,
};

// The notifications waiting to be tried again. Thread-safe: delivery tasks schedule retries and
// drop rejected pushkeys, and the retry job takes the due ones, each under this queue's own mutex
// (never runtime.mutex). Holds no network state; the caller sends.
class PushRetryQueue final
{
public:
    PushRetryQueue() = default;
    ~PushRetryQueue() = default;
    PushRetryQueue(PushRetryQueue const&) = delete;
    PushRetryQueue(PushRetryQueue&&) = delete;
    auto operator=(PushRetryQueue const&) -> PushRetryQueue& = delete;
    auto operator=(PushRetryQueue&&) -> PushRetryQueue& = delete;

    // Queues `retry`, whose attempt number `retry.failed_attempts` has just failed, for
    // `now + push_retry_backoff(failed_attempts)`, then calls the wake hook.
    [[nodiscard]] auto schedule(PushRetry retry, std::chrono::steady_clock::time_point now) -> PushRetryAdmission;

    // Removes and returns up to `max` retries due at `now`, earliest first.
    [[nodiscard]] auto take_due(std::chrono::steady_clock::time_point now, std::size_t max) -> std::vector<PushRetry>;

    // Drops every queued retry to (`app_id`, `pushkey`), which the gateway has rejected ("Homeservers
    // must cease sending notification requests for these pushkeys"). Returns how many were dropped.
    auto drop_pushkey(std::string_view app_id, std::string_view pushkey) -> std::size_t;

    // When the earliest queued retry is due, or nullopt when none is queued.
    [[nodiscard]] auto next_due() const -> std::optional<std::chrono::steady_clock::time_point>;

    [[nodiscard]] auto size() const -> std::size_t;

    // Called, under this queue's mutex, after each queued retry; the retry job installs its
    // PeriodicJob::wake here and clears it (an empty function) before it stops.
    auto set_wake(std::function<void()> wake) -> void;

private:
    mutable std::mutex mutex_{};
    std::vector<PushRetry> entries_{};
    std::function<void()> wake_{};
};

} // namespace merovingian::push
