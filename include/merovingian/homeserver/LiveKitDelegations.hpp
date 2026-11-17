// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/homeserver/OperationResult.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace merovingian::homeserver
{

struct ClientServerRuntime;
struct LocalHttpRequest;
class StopFlag;

// MSC4195's delegated delayed leave (ADR-0832) and the LiveKit webhook that prompts its checks (ADR-0833).

// A delegated event's delay must be at least this long (MSC4195 lets a server refuse a short one): a restart is due
// when half the delay remains, and LiveKit is asked only every `livekit_delegation_check_interval`.
inline constexpr auto livekit_delegation_min_delay_ms = std::uint64_t{300'000U};
// Delegations one user may hold. One more is refused (429), nothing is evicted.
inline constexpr auto livekit_delegations_per_user = std::size_t{20U};
// How often each delegation is checked with GetParticipant, unless a webhook brings the check forward.
inline constexpr auto livekit_delegation_check_interval = std::chrono::milliseconds{30'000};
// A delegation whose participant has never been seen is given this long to connect before a "gone" answer sends it.
inline constexpr auto livekit_delegation_connect_grace_ms = std::uint64_t{120'000U};
// GetParticipant calls made by one run of the job, so one run's lock-free stretch stays bounded.
inline constexpr auto livekit_delegation_checks_per_run = std::size_t{16U};
// At most this many delegations are dropped in one run, each a commit under the lock; the rest wait for the next run.
inline constexpr auto livekit_delegation_drops_per_run = std::size_t{64U};
// The webhook body and the event `id` LiveKit sends, at most.
inline constexpr auto livekit_webhook_max_body_bytes = std::size_t{64U * 1024U};
inline constexpr auto livekit_webhook_max_event_id_bytes = std::size_t{128U};
// Webhook event IDs remembered, to ignore a replay inside the token's own lifetime.
inline constexpr auto livekit_webhook_seen_ids = std::size_t{1024U};
// How far a webhook's `createdAt` may be from now, and the allowance on its token's `nbf` and `exp`.
inline constexpr auto livekit_webhook_max_age_seconds = std::int64_t{300};
inline constexpr auto livekit_webhook_clock_leeway_seconds = std::int64_t{60};
inline constexpr auto livekit_webhook_path = std::string_view{"/_merovingian/livekit/webhook"};

// POST .../rtc/livekit/delegate_delayed_leave for `user_id`, whose access token the caller checked. Caller holds
// `runtime.homeserver.mutex`. Answers per ADR-0832: 404 M_UNRECOGNIZED with the service off; 400 for a malformed body;
// 400 M_INVALID_PARAM for a `url` that is not the SFU; 403 M_FORBIDDEN when the user is not joined; 400
// M_INVALID_PARAM, one answer, for a delayed event that is not the user's, not in the room or not scheduled, or whose
// delay is under `livekit_delegation_min_delay_ms`; 429 M_LIMIT_EXCEEDED at `livekit_delegations_per_user`; 500 when
// the row cannot be stored. On success stores the delegation (replacing any for the same user, room, slot and member,
// or the same delay ID), marks it for a check now, wakes the job, and answers 200 `{}`. Makes no network call.
[[nodiscard]] auto delegate_livekit_delayed_leave(ClientServerRuntime& runtime, std::string_view body,
                                                  std::string const& user_id) -> OperationResult;

// The "livekit-delegations" job's body (main.cpp; tests call it directly with their own `now_ms`). Takes
// `runtime.homeserver.mutex` itself. Drops the delegations that can no longer be acted on, then checks at most
// `livekit_delegation_checks_per_run` due ones with GetParticipant with the lock released, then applies each answer
// under the lock through `manage_delayed_event`. Returns how long to wait before the next run: the time to the next
// due check, at most `livekit_delegation_check_interval`, at least 1 s; 1 s also when more checks are already due.
[[nodiscard]] auto run_livekit_delegations(ClientServerRuntime& runtime, std::uint64_t now_ms, StopFlag const& stop)
    -> std::chrono::milliseconds;

// POST /_merovingian/livekit/webhook (ADR-0833). Caller holds `runtime.homeserver.mutex` and has checked nothing:
// this is called before any access-token handling. 404 M_UNRECOGNIZED with the service off; 413 for a body over
// `livekit_webhook_max_body_bytes`; 401 M_UNAUTHORIZED for any authentication failure; otherwise 200 `{}`. At most
// marks one recorded delegation to be checked at the next run and wakes the job; never restarts or sends an event.
[[nodiscard]] auto receive_livekit_webhook(ClientServerRuntime& runtime, LocalHttpRequest const& request,
                                           std::int64_t now_seconds) -> OperationResult;

} // namespace merovingian::homeserver
