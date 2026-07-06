// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/core/file_descriptor.hpp"
#include "merovingian/crypto/ipc_auth_key.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <utility>

#include <sodium.h>

namespace merovingian::ipc
{

// Default maximum plaintext size for a single IPC frame (24 MiB).
// Federation transactions have no hard spec limit, but a 50 MiB cap (the prior
// default) let a single oversized frame pin 50 MiB of heap and silently stall
// federation when it was dropped. 16 MiB (the immediately prior default)
// bounded the per-frame allocation but was sized as if a frame's body cost
// equalled the raw HTTP payload it carries. It doesn't: outbound_http_response
// and fed_response frames (src/ipc/federation_ipc_frames.cpp) base64-encode
// the HTTP response body before framing, a fixed 4/3 expansion. A response
// body at http::OutboundRequest::max_response_body_bytes (16 MiB by default —
// the ceiling a large room's send_join response legitimately reaches) becomes
// ~21.3 MiB once encoded plus envelope overhead, which no longer fits under a
// 16 MiB cap; the oversize-frame guard below then drops it and the caller
// sees a bare IPC timeout instead of the join succeeding. 24 MiB restores
// headroom above that ~21.3 MiB worst case while still keeping the per-frame
// allocation a compromised worker can pin tightly bounded.
inline constexpr std::uint32_t kIpcMaxFrameBytes{24U * 1024U * 1024U};

// Computes the max_frame_bytes an IpcChannel needs to carry an
// outbound_http_response/fed_response frame whose HTTP body is up to
// max_response_body_bytes (see kIpcMaxFrameBytes above for why the frame
// must be sized off the base64-encoded 4/3 expansion, not the raw body).
// Adds 2 MiB of headroom for the surrounding JSON envelope and never returns
// less than kIpcMaxFrameBytes, so callers passing the 16 MiB default get
// exactly today's behaviour. Both the supervisor (main process) and the
// worker must compute this the same way from the same config value, or the
// smaller side silently drops the other's oversize frames.
[[nodiscard]] auto frame_bytes_for_response_cap(std::uint64_t max_response_body_bytes) noexcept -> std::uint32_t;

// Bidirectional encrypted IPC channel over an AF_UNIX socketpair fd.
//
// Security model:
//   - Ephemeral crypto_kx key exchange on construction; keys are wiped after derivation.
//   - The KX handshake is mutually authenticated: both peers derive the same
//     crypto::IpcAuthKey from the operator master-key file and MAC each other's
//     ephemeral public keys with it. A peer that cannot prove possession of the
//     master key is rejected (fail-closed). crypto_kx alone is confidentiality only.
//   - All subsequent traffic is AEAD-encrypted via crypto_secretstream_xchacha20poly1305.
//   - No filesystem socket path: fd is inherited from posix_spawn, invisible to ls/netstat.
//
// Wire format (post-handshake, all big-endian):
//   [4-byte ciphertext length][ciphertext = plaintext + ABYTES overhead]
//
// JSON framing:
//   The channel injects "id" (and "reply_to" for responses) into every frame.
//   Callers provide JSON bodies WITHOUT these fields; the channel prepends them.
//
// Thread safety:
//   - One reader thread (started by start()) owns all decryption/read state.
//     It only routes frames: responses wake their pending send_request waiter,
//     and request frames are queued for the dispatch thread. The reader never
//     runs caller code, so a blocked request handler can never stall response
//     delivery (the federation-worker drip-feed deadlock: a handler waiting on
//     a lock held by a thread that is itself blocked in send_request would
//     otherwise wedge the channel until the send_request timeout).
//   - One dispatch thread (also started by start()) invokes the request
//     handler for queued request frames, one at a time, in arrival order.
//   - Any number of threads may call send_request/send_response/send_notification;
//     a write mutex serialises their encryption/write operations.
class IpcChannel final
{
public:
    enum class Role
    {
        server, // crypto_kx server role; sends secretstream header first
        client, // crypto_kx client role; receives secretstream header first
    };

    // Invoked from the channel's dispatch thread for every inbound frame with
    // no "reply_to", one frame at a time, in arrival order.
    // id: the frame's "id". json: the full JSON frame string.
    // A handler that blocks does not stall response routing (the reader thread
    // keeps delivering send_request replies), but it does delay every later
    // request frame on this channel — still dispatch expensive work to a
    // thread pool. Handlers must never call stop() on their own channel: stop()
    // joins the dispatch thread, and a thread cannot join itself.
    using RequestHandler = std::function<void(std::uint64_t id, std::string json)>;

    // Performs the ephemeral key exchange synchronously and authenticates the
    // peer by MACing the ephemeral KX public keys with auth_key. Throws
    // std::runtime_error on failure (including authentication failure). Does not
    // start the reader thread; call start() after set_request_handler().
    explicit IpcChannel(core::FileDescriptor fd, Role role, crypto::IpcAuthKey auth_key,
                        std::uint32_t max_frame_bytes = kIpcMaxFrameBytes);
    ~IpcChannel();

    IpcChannel(IpcChannel const&) = delete;
    auto operator=(IpcChannel const&) -> IpcChannel& = delete;
    IpcChannel(IpcChannel&&) = delete;
    auto operator=(IpcChannel&&) -> IpcChannel& = delete;

    // Must be set before start().
    auto set_request_handler(RequestHandler handler) -> void;

    // Starts the reader and dispatch threads. May only be called once.
    auto start() -> void;

    // Closes the fd (unblocking any blocked read) and joins the reader and
    // dispatch threads. Request frames already queued for dispatch are still
    // handled before the dispatch thread exits. Must not be called from a
    // request handler (see RequestHandler).
    auto stop() noexcept -> void;

    // Sends a request and blocks until a matching reply_to frame arrives.
    // Returns nullopt on timeout or channel failure.
    // json_body: a JSON object WITHOUT "id" or "reply_to".
    [[nodiscard]] auto send_request(std::string_view json_body, std::chrono::seconds timeout = std::chrono::seconds{30})
        -> std::optional<std::string>;

    // Sends a response to an inbound request. json_body: without "id"/"reply_to".
    auto send_response(std::uint64_t reply_to, std::string_view json_body) -> void;

    // Sends a one-way notification (no response expected). json_body: without "id"/"reply_to".
    auto send_notification(std::string_view json_body) -> void;

    [[nodiscard]] auto healthy() const noexcept -> bool;

private:
    [[nodiscard]] auto raw_send_exact(void const* buf, std::size_t n) noexcept -> bool;
    [[nodiscard]] auto raw_recv_exact(void* buf, std::size_t n) noexcept -> bool;
    [[nodiscard]] auto write_frame(std::string_view plaintext) noexcept -> bool;
    [[nodiscard]] auto read_frame() noexcept -> std::optional<std::string>;
    [[nodiscard]] auto build_frame(std::uint64_t id, std::optional<std::uint64_t> reply_to, std::string_view body)
        -> std::string;
    // Logs a warning that a frame of `body.size()` bytes for the given IPC
    // message kind was dropped for exceeding the frame cap. The frame "type"
    // is extracted from the body for diagnostics. Used by the send paths so an
    // oversize frame is never silently dropped (issue #325).
    auto report_oversize_drop(std::string_view json_body, char const* kind) const noexcept -> void;
    auto reader_loop() -> void;
    auto dispatcher_loop() -> void;

    core::FileDescriptor fd_;
    Role role_;
    std::uint32_t max_frame_bytes_{kIpcMaxFrameBytes};

    crypto_secretstream_xchacha20poly1305_state push_state_{};
    crypto_secretstream_xchacha20poly1305_state pull_state_{};

    std::mutex write_mu_{};
    std::atomic<std::uint64_t> next_id_{1U};

    struct PendingEntry final
    {
        std::optional<std::string> response{};
        bool ready{false};
        std::condition_variable cv{};
    };
    std::mutex pending_mu_{};
    // Reader thread and waiting caller each hold a reference; the map entry is
    // erased while the caller still holds its copy, so the entry is destroyed
    // only after the waiter has consumed the response.
    std::map<std::uint64_t, std::shared_ptr<PendingEntry>> pending_{}; // SHARED_PTR: reviewed — reader/caller co-own

    RequestHandler request_handler_{};
    std::thread reader_thread_{};
    std::atomic<bool> running_{false};
    std::atomic<bool> healthy_{true};

    // Request frames queued by the reader thread for the dispatch thread.
    // Keeping the reader out of handler code is what guarantees responses are
    // always routed promptly (see the thread-safety notes above).
    std::mutex dispatch_mu_{};
    std::condition_variable dispatch_cv_{};
    std::deque<std::pair<std::uint64_t, std::string>> dispatch_queue_{};
    std::thread dispatch_thread_{};
};

} // namespace merovingian::ipc
