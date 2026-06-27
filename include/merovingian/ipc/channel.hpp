// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/core/file_descriptor.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <thread>

#include <sodium.h>

namespace merovingian::ipc
{

// Maximum plaintext size for a single IPC frame (4 MiB).
inline constexpr std::uint32_t kIpcMaxFrameBytes{4U * 1024U * 1024U};

// Bidirectional encrypted IPC channel over an AF_UNIX socketpair fd.
//
// Security model:
//   - Ephemeral crypto_kx key exchange on construction; keys are wiped after derivation.
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

    // Invoked from the reader thread for every inbound frame with no "reply_to".
    // id: the frame's "id". json: the full JSON frame string.
    // Must not block — dispatch expensive work to a thread pool.
    using RequestHandler = std::function<void(std::uint64_t id, std::string json)>;

    // Performs the ephemeral key exchange synchronously. Throws std::runtime_error on failure.
    // Does not start the reader thread; call start() after set_request_handler().
    explicit IpcChannel(core::FileDescriptor fd, Role role);
    ~IpcChannel();

    IpcChannel(IpcChannel const&) = delete;
    auto operator=(IpcChannel const&) -> IpcChannel& = delete;
    IpcChannel(IpcChannel&&) = delete;
    auto operator=(IpcChannel&&) -> IpcChannel& = delete;

    // Must be set before start().
    auto set_request_handler(RequestHandler handler) -> void;

    // Starts the reader thread. May only be called once.
    auto start() -> void;

    // Closes the fd (unblocking any blocked read) and joins the reader thread.
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
    auto reader_loop() -> void;

    core::FileDescriptor fd_;
    Role role_;

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
    std::map<std::uint64_t, std::shared_ptr<PendingEntry>> pending_{}; // SHARED_PTR: reviewed — caller/reader co-own

    RequestHandler request_handler_{};
    std::thread reader_thread_{};
    std::atomic<bool> running_{false};
    std::atomic<bool> healthy_{true};
};

} // namespace merovingian::ipc
