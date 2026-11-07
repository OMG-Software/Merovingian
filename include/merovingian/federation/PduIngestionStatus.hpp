// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>

namespace merovingian::federation
{

enum class PduIngestionStatus : std::uint8_t
{
    accepted,
    rejected_auth,
    // Legacy status from the pre-ADR-0064 state-conflict-resolver plumbing
    // (removed in phase B2 — see the ADR). No production sink produces this
    // any more; kept only so the worker IPC wire format
    // (worker_pool.cpp/worker_event_loop.cpp) stays a stable, exhaustive set.
    rejected_state_conflict,
    rejected_invalid,
    internal_error,
    // ADR-0064 phase B1: a prev_event this PDU depends on has no recorded
    // state group (an older, pre-Phase-A event, or a genuine gap in our
    // history of the room). The event is NOT stored — applying it would mean
    // either guessing its state-before or silently substituting current
    // state, both of which reintroduce delivery-order dependence. The spec
    // treats a delayed-but-legitimate PDU the same as one we simply have not
    // backfilled yet, so this is not a rejection: the transaction still
    // returns 200 and a later phase is expected to fetch the gap
    // (/get_missing_events, /state_ids) and retry.
    missing_prev_state,
    // ADR-0064 phase B2: the PDU passed auth against its own auth_events and
    // against the state before it, but fails auth against the room's
    // *current* (resolved) state. Spec: server-server-api.md "Soft failure".
    // The event IS stored, given an after-state group, and takes part in
    // state resolution as normal — it is never rejected — but it is not a
    // forward extremity and is not relayed to clients, except that a
    // soft-failed *state* event which resolution later admits into current
    // state is shown to clients in the state section as usual.
    soft_failed,
    // ADR-0065 (0.12.13 audit, finding H2): main is at its per-channel IPC
    // in-flight cap and explicitly rejected the pdu_ingest request. The
    // transaction handler must answer the remote with a retryable 5xx.
    main_overloaded,
    // R03 (ADR-0165): like missing_prev_state, but this server has kept the
    // PDU (durably, as received) and will try to place it again once the gap
    // is filled. Spec: server-server-api.md "Transactions" -- a PDU with no
    // error in the response "can be considered successfully handled", which a
    // retained PDU is. missing_prev_state now means the PDU was NOT kept (no
    // origin to fetch from, or the retained set is full): the sender is told
    // so in the transaction response because nothing will retry it.
    deferred,
    // Complement run 12: the event ID is already stored here, in any status, so this server handled the
    // PDU when it first arrived. Spec: server-server-api.md "PDU Processing Result" -- a PDU with no
    // error "can be considered successfully handled". It is answered as handled (no error entry) and
    // is NOT verified, authorised or stored again: no stream ordering, push, fan-out or membership
    // projection. A stored copy is never re-judged, whatever its status (ADR-0285).
    already_stored,
    // F-24 (ADR-0359): main judged the PDU against its own room m.room.server_acl and the transport origin
    // or the sender's server is denied. Spec: server-server-api.md "Server Access Control Lists (ACLs)" --
    // such a PDU "MUST be ignored with an appropriate error included in the response for the respective
    // event ID". Nothing is stored, and unlike a rejection (which is stored) the transaction answer carries
    // an `error` entry for it.
    rejected_acl,
};

} // namespace merovingian::federation
