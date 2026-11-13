// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>

namespace merovingian::config
{

// Out-of-process federation worker configuration.
// All inbound federation requests (except key-server) are dispatched to
// merovingian-fed-worker over an encrypted AF_UNIX socketpair channel,
// freeing the main thread pool for client-server requests.
// The worker is mandatory: startup fails if the worker process cannot be launched.
struct FederationWorkerConfig final
{
    // Maximum seconds to wait for the worker to respond.
    std::uint32_t request_timeout_seconds{120U};
    // Number of processing threads in the worker process reserved for
    // endpoints answerable entirely from the worker's own local, room-scoped
    // snapshot: make_leave/make_knock, backfill, state, state_ids,
    // get_missing_events, hierarchy. These never block on
    // main and should always complete quickly.
    std::uint32_t threads{4U};
    // Number of processing threads reserved for endpoints that can block on a
    // synchronous IPC round-trip back to main (transaction PDUs/EDUs,
    // send_join/send_leave/send_knock, invite, and the query-provider relays:
    // profile, directory, keys, claim_keys, user_devices, event, make_join,
    // publicRooms) or on outbound HTTP to a
    // remote server. Deliberately a separate pool from `threads`: these
    // threads spend nearly all their time blocked on I/O rather than
    // consuming CPU, so sizing generously is cheap, whereas sharing a single
    // small pool between the two classes lets a burst of slow relay calls
    // starve the fast local endpoints above of any thread to run on — see
    // docs/architecture.md, "Federation worker relay pool separation".
    std::uint32_t relay_threads{32U};
    // Number of independent federation worker processes. shard=1 is the
    // Phase 1/2 single-worker behaviour. Requests are routed by
    // fnv1a_32(room_id) % shards; non-room endpoints go to shard 0. shards=0
    // is rejected at config validation time.
    std::uint32_t shards{1U};
    // ADR-0065 (0.12.13 audit, finding H2): per-channel cap on in-flight IPC
    // requests the main process will accept from one federation worker. A
    // request over the cap is rejected with an explicit error reply so the
    // worker answers the remote server with a retryable 5xx. 0 disables the
    // cap (not recommended). Restart required.
    std::uint32_t ipc_max_in_flight_requests{256U};
    // CRY-2 (0.12.12 audit): maximum number of request frames the reader thread
    // will queue for the dispatch thread before treating the channel as flooded.
    // Bound together with ipc_max_dispatch_queue_bytes so a compromised worker
    // cannot pin unbounded heap in the main process. 0 disables the cap (not
    // recommended). Restart required.
    std::uint32_t ipc_max_dispatch_queue_count{1024U};
    // CRY-2 (0.12.12 audit): maximum queued request bytes the reader thread will
    // hold for the dispatch thread. Bound together with
    // ipc_max_dispatch_queue_count. 0 disables the cap (not recommended). Restart
    // required.
    std::uint64_t ipc_max_dispatch_queue_bytes{128U * 1024U * 1024U};
    // Absolute path to the merovingian-fed-worker binary. Empty means use
    // the compile-time libexec default.
    std::string worker_binary{};
    // Apply the worker-specific runtime hardening sequence (RLIMIT_CORE=0,
    // PR_SET_NO_NEW_PRIVS, capability-bounding drop, worker seccomp-bpf filter
    // that denies execve/execveat) at worker startup (issue #319). Default true
    // so production workers are sandboxed; tests that exercise the worker
    // binary directly set this false to avoid the strict filter while the
    // filter allowlist is validated separately in unit tests.
    bool apply_hardening{true};
    // ADR-0062 part 3 (0.12.13 audit, finding N1): on Linux, the worker
    // restricts its own filesystem access with Landlock
    // (platform::apply_worker_landlock) before handling any untrusted input,
    // so that a compromise reached through a memory-safety bug cannot open
    // the operator master key, TLS private keys, main's database URI file,
    // or the worker's own database URI file directly off disk. When the
    // running kernel has no Landlock support (ABI query < 1: kernel older
    // than 5.13, or Landlock disabled at boot), the worker refuses to start
    // unless this is set true, in which case it logs CRITICAL on every start
    // and continues without the filesystem sandbox -- mirroring
    // apply_hardening's fail-closed contract (ADR-0041). Any Landlock
    // failure OTHER than "unavailable" (ruleset create/add_rule/
    // restrict_self erroring on a kernel that does support it) is always
    // fatal regardless of this flag. Default false so production workers
    // refuse to run unsandboxed by default. Ignored on non-Linux platforms,
    // which have no Landlock equivalent and already fail closed via
    // apply_hardening's own platform gate.
    bool allow_without_landlock{false};
};

} // namespace merovingian::config
