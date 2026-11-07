// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/core/secret_buffer.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <string_view>

namespace merovingian::federation
{

struct DispatchWorkerConfig final
{
    // Identity used when signing outbound traffic. The signing identity
    // mirrors the runtime's persisted Ed25519 signing key. `secret_key` is
    // the raw 64-byte libsodium Ed25519 secret key, held in an owning,
    // mlocked, zeroised SecretBuffer so the worker never keeps an unpinned
    // std::string copy. Per-call OutboundCall objects borrow it via .bytes().
    std::string origin{};
    std::string key_id{};
    core::SecretBuffer secret_key{};
    // Bound on the in-memory enqueue list. Enforced fail-closed: enqueue
    // returns false once the limit is hit. Zero disables the bound for tests.
    std::size_t max_queue_depth{1024U};
    // Bound on how many queued transactions one destination may hold, so a dead or hostile peer
    // whose circuit stays open cannot fill the queue every other peer shares (security audit
    // run-1). Past it enqueue refuses the transaction and counts it in `rejected`; the peer
    // fetches what it missed itself once it is reachable (prev_events, /get_missing_events).
    // Zero derives it from max_queue_depth: see effective_max_pending_per_destination.
    std::size_t max_pending_per_destination{0U};
    // Why the operator's policy excludes a destination, empty when it does not (ADR-0391). Enqueue refuses such a
    // transaction and replay drops its durable row, so nothing queued can reach one: the policy cannot change
    // while the process runs. Unset excludes nothing.
    std::function<std::string(std::string_view destination)> destination_refusal{};
    // Maximum number of retry attempts before a transaction is dropped and
    // recorded as terminally failed. Matches the federation backoff curve.
    std::uint32_t max_retries{8U};
    // Threads delivering at once. One destination holds at most one of them at a time (ADR-0354).
    std::size_t delivery_threads{1U};
    // The whole of one attempt once the destination is known.
    std::uint32_t attempt_timeout_seconds{30U};
    // An attempt, discovery included, that took longer than this and then succeeded counts against
    // the destination all the same (ADR-0354).
    std::uint64_t slow_attempt_ms{10000U};
    // How long a shutdown keeps delivering what was already due. What it does not reach stays durable.
    std::chrono::milliseconds shutdown_drain_budget{std::chrono::seconds{30}};
    // Optional PEM CA bundle trusted in place of the system trust store. Only ever set by tests, as
    // with OutboundCall::trusted_ca_pem.
    std::string trusted_ca_pem{};
    // How long the worker sleeps when the queue is empty before re-checking
    // for shutdown. Smaller values shorten shutdown latency.
    std::chrono::milliseconds idle_poll{std::chrono::milliseconds{50}};
};

} // namespace merovingian::federation
