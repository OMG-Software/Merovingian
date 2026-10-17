// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/persistent_store.hpp"
#include "merovingian/federation/inbound_ingestion.hpp"
#include "merovingian/homeserver/periodic_job.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <stop_token>
#include <string>
#include <string_view>

namespace merovingian::homeserver
{

struct HomeserverRuntime;

// R03 (ADR-0165): federation PDUs this server could not yet place (a prev_event
// or auth_event is unknown, or the state before the event is not recorded) are
// retained and retried, not dropped. Spec: server-server-api.md "Transactions"
// (the sender is told the PDU was handled and does not resend it) and
// "Backfilling and retrieving missing events" (a server fills the gap itself).

// Retries are spaced from 30 seconds, doubling after each attempt that did not
// place the PDU, to at most an hour. Only the earliest-attempt time is kept, in
// memory (HomeserverRuntime::deferred_pdu_next_attempt); after a restart every
// retained PDU is due at once.
inline constexpr auto deferred_pdu_initial_backoff = std::chrono::seconds{30};
inline constexpr auto deferred_pdu_max_backoff = std::chrono::hours{1};
// At most this many PDUs are retried by one call, so one call cannot hold the
// retry thread (or the stop request) behind a whole backlog.
inline constexpr auto deferred_pdu_retry_batch = std::size_t{32U};
// How long the retry job sleeps when nothing is due sooner, and the longest it
// ever sleeps: a PDU retained while the job sleeps is picked up within this.
inline constexpr auto deferred_pdu_idle_delay = std::chrono::minutes{5};

// The back-off before the attempt that follows `attempts_so_far` failed ones.
[[nodiscard]] auto deferred_pdu_backoff(std::uint32_t attempts_so_far) noexcept -> std::chrono::milliseconds;

// Retains `stored_json` (the envelope exactly as ingestion would have stored it,
// possibly the redacted copy) for a retry. A PDU already retained keeps its
// receive time and attempt count. Returns false, retaining nothing, when the
// envelope has no origin to fetch its history from, or a bound of
// database::max_deferred_pdus_* is reached. The caller holds
// HomeserverRuntime::mutex.
[[nodiscard]] auto defer_unresolved_pdu(HomeserverRuntime& runtime, federation::InboundPduEnvelope const& envelope,
                                        std::string const& stored_json) -> bool;

// After a PDU of `room_id` has been stored: makes due every retained PDU of that
// room whose JSON names `event_id` (a prev_event or auth_event it was waiting
// for) and, if there was one, calls HomeserverRuntime::deferred_pdu_retry_wake.
// Takes HomeserverRuntime::mutex; call it with no room stripe held.
auto wake_deferred_pdus_waiting_for(HomeserverRuntime& runtime, std::string_view room_id, std::string_view event_id)
    -> void;

// Drops the retained PDUs that are over age or attempt limits, then retries the
// due ones (at most deferred_pdu_retry_batch), checking `stop` between PDUs.
// A PDU that is now placed (accepted, soft-failed or rejected -- all of which
// store it) or that can never be placed (rejected as invalid, e.g. we left the
// room) is removed; one that still cannot be placed gets one more attempt and a
// later retry time. Returns how long to wait before the next call: until the
// earliest retry time, between one second and deferred_pdu_idle_delay.
//
// Takes no lock across the retry itself: ingestion takes its own locks and may
// fetch missing history over the network. The retry re-enters ingestion after
// the sender's signature has been verified, which is safe because a row is only
// written by ingest_pdu_event, after that verification (the same-process
// /send path in federation::authorize_federation_pdu, or the worker relay's
// re-verification in homeserver::handle_pdu_ingest_request, ADR-0071).
[[nodiscard]] auto retry_deferred_pdus(HomeserverRuntime& runtime, std::stop_token const& stop)
    -> std::chrono::milliseconds;

// Runs retry_deferred_pdus on its own thread and keeps the runtime's wake hook
// pointing at it. The thread starts only in start(), after process hardening
// (ADR-0082). stop() (and the destructor) clear the hook under
// HomeserverRuntime::mutex before stopping the thread, so no request thread can
// wake a job that no longer exists; call it before the runtime is torn down.
class DeferredPduRetryJob final
{
public:
    explicit DeferredPduRetryJob(HomeserverRuntime& runtime);
    ~DeferredPduRetryJob();

    DeferredPduRetryJob(DeferredPduRetryJob const&) = delete;
    DeferredPduRetryJob(DeferredPduRetryJob&&) = delete;
    auto operator=(DeferredPduRetryJob const&) -> DeferredPduRetryJob& = delete;
    auto operator=(DeferredPduRetryJob&&) -> DeferredPduRetryJob& = delete;

    // Installs the wake hook and starts the thread. False if the thread could
    // not be started (the hook is then left unset).
    [[nodiscard]] auto start() -> bool;
    // Clears the wake hook, then stops and joins the thread. Idempotent.
    auto stop() noexcept -> void;

private:
    HomeserverRuntime& runtime_;
    PeriodicJob job_;
};

} // namespace merovingian::homeserver
