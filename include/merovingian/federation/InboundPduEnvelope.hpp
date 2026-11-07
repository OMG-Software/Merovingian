// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/events/event.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace merovingian::federation
{

// Per-PDU envelope passed to the injected ingestion sink. Carries the
// minimum surface the persistent store needs to append an event to the
// graph; consumers may also parse `json` directly for fields not surfaced
// here.
struct InboundPduEnvelope final
{
    std::string event_id{};
    std::string room_id{};
    std::string room_version{};
    std::string sender{};
    std::string event_type{};
    std::optional<std::string> state_key{};
    std::int64_t origin_server_ts{0};
    std::uint64_t depth{0U};
    std::vector<std::string> prev_event_ids{};
    std::vector<std::string> auth_event_ids{};
    std::vector<events::EventSignature> signatures{};
    std::string json{};
    // ADR-0064 phase C: the server that sent this PDU over federation. Used to
    // fetch missing prev_events / auth_events and to request state from the
    // origin when our own copy of the DAG is incomplete. Not present in the
    // PDU JSON itself; set by the transaction handler before invoking pdu_sink.
    std::string origin{};
    // PUT /send_join only: the request's `omit_members` query parameter (server-server-api.md),
    // which says the calling server accepts an answer without membership events. Like `origin`, not
    // part of the PDU: the join handler sets it from the request target, and the worker relay
    // carries it to main in the membership_ingest frame.
    bool omit_members{false};
};

} // namespace merovingian::federation
