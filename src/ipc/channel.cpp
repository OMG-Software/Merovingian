// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/ipc/channel.hpp"

#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/crypto/ipc_stream_cipher.hpp"
#include "merovingian/ipc/federation_ipc_frames.hpp"
#include "merovingian/observability/logger.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <limits>
#include <new>
#include <span>
#include <stdexcept>
#include <string>
#include <utility>
#include <variant>
#include <vector>

#include <arpa/inet.h>
#include <sys/socket.h>

namespace merovingian::ipc
{

namespace
{

    // Extracts a uint64 value for a JSON key from a parsed object. The
    // canonicaljson DOM stores integers as int64; values are monotonic frame
    // ids/reply_tos starting at 0, so the int64 range is sufficient. Returns
    // nullopt for a missing key or a non-integer value.
    [[nodiscard]] auto extract_uint64(canonicaljson::Object const& obj, std::string_view key) noexcept
        -> std::optional<std::uint64_t>
    {
        for (auto const& member : obj)
        {
            if (member.key == key)
            {
                auto const* num = std::get_if<std::int64_t>(&member.value->storage());
                if (num == nullptr || *num < 0)
                {
                    return std::nullopt;
                }
                return static_cast<std::uint64_t>(*num);
            }
        }
        return std::nullopt;
    }

} // namespace

auto frame_bytes_for_response_cap(std::uint64_t max_response_body_bytes) noexcept -> std::uint32_t
{
    constexpr std::uint64_t kEnvelopeHeadroom{2U * 1024U * 1024U};
    constexpr std::uint64_t kU32Max{static_cast<std::uint64_t>(std::numeric_limits<std::uint32_t>::max())};
    // base64 expands by 4/3, rounded up to a whole 4-byte group.
    auto const encoded = ((max_response_body_bytes + 2U) / 3U) * 4U;
    auto const needed = std::max<std::uint64_t>(encoded + kEnvelopeHeadroom, kIpcMaxFrameBytes);
    return static_cast<std::uint32_t>(std::min(needed, kU32Max));
}

IpcChannel::IpcChannel(core::FileDescriptor fd, Role role, crypto::IpcAuthKey auth_key, std::uint32_t max_frame_bytes)
    : fd_{std::move(fd)}
    , max_frame_bytes_{max_frame_bytes == 0U ? kIpcMaxFrameBytes : max_frame_bytes}
    , cipher_{std::make_unique<crypto::IpcStreamCipher>(
          role == Role::server ? crypto::IpcStreamCipher::Role::server : crypto::IpcStreamCipher::Role::client,
          std::move(auth_key),
          [this](void const* buf, std::size_t n) {
              return raw_send_exact(buf, n);
          },
          [this](void* buf, std::size_t n) {
              return raw_recv_exact(buf, n);
          })}
{
}

IpcChannel::~IpcChannel()
{
    stop();
}

auto IpcChannel::set_request_handler(RequestHandler handler) -> void
{
    request_handler_ = std::move(handler);
}

auto IpcChannel::start() -> void
{
    running_.store(true);
    reader_thread_ = std::thread{[this] {
        reader_loop();
    }};
    dispatch_thread_ = std::thread{[this] {
        dispatcher_loop();
    }};
}

auto IpcChannel::stop() noexcept -> void
{
    running_.store(false);
    healthy_.store(false);

    // Wake every pending send_request waiter so callers return quickly instead
    // of continuing to use the file descriptor while it is being closed.
    {
        auto const lk = std::lock_guard{pending_mu_};
        for (auto& [_, e] : pending_)
        {
            e->ready = true;
            e->cv.notify_one();
        }
    }

    // shutdown() is the reliable way to unblock recv() in the reader thread
    // and to fail in-flight send()/recv() calls without waiting for timeouts.
    // The reader thread must be joined before the descriptor is closed; closing
    // it earlier creates a data race between the close and the reader's use of
    // the same fd (ThreadSanitizer: FileDescriptor::reset vs get).
    if (fd_.get() >= 0)
    {
        ::shutdown(fd_.get(), SHUT_RDWR);
    }

    if (reader_thread_.joinable())
    {
        reader_thread_.join();
    }

    // Wake the dispatch thread so it drains any queued request frames and
    // exits (running_ is already false). Joined after the reader so no new
    // frames can be queued behind the drain.
    dispatch_cv_.notify_all();
    if (dispatch_thread_.joinable())
    {
        dispatch_thread_.join();
    }

    // No writer can hold write_mu_ once shutdown() has caused the blocked
    // send() to return, so take the lock while closing the fd to serialize
    // the last close with any straggling write_frame call.
    {
        auto const lk = std::lock_guard{write_mu_};
        fd_.reset();
    }
}

auto IpcChannel::healthy() const noexcept -> bool
{
    return healthy_.load();
}

auto IpcChannel::raw_send_exact(void const* buf, std::size_t n) noexcept -> bool
{
    auto const* p = static_cast<char const*>(buf);
    std::size_t sent{0};
    while (sent < n)
    {
        auto const rc = ::send(fd_.get(), p + sent, n - sent, MSG_NOSIGNAL);
        if (rc <= 0)
        {
            return false;
        }
        sent += static_cast<std::size_t>(rc);
    }
    return true;
}

auto IpcChannel::raw_recv_exact(void* buf, std::size_t n) noexcept -> bool
{
    auto* p = static_cast<char*>(buf);
    std::size_t received{0};
    while (received < n)
    {
        auto const rc = ::recv(fd_.get(), p + received, n - received, 0);
        if (rc <= 0)
        {
            return false;
        }
        received += static_cast<std::size_t>(rc);
    }
    return true;
}

auto IpcChannel::write_frame(std::string_view plaintext) noexcept -> bool
{
    auto const pt_len = plaintext.size();
    if (pt_len > max_frame_bytes_)
    {
        return false;
    }
    auto const ct_len = static_cast<std::uint32_t>(cipher_->ciphertext_size(pt_len));
    // Allocation can throw std::bad_alloc; this function is noexcept, so an
    // uncaught exception would call std::terminate. Allocate defensively and
    // treat allocation failure as a normal send failure (issue #324).
    auto ct = std::vector<uint8_t>{};
    try
    {
        ct.resize(ct_len);
    }
    catch (std::bad_alloc const&)
    {
        return false;
    }

    if (!cipher_->encrypt(std::span<uint8_t const>{reinterpret_cast<uint8_t const*>(plaintext.data()), pt_len},
                          std::span<uint8_t>{ct.data(), ct_len}))
    {
        return false;
    }

    auto const net_len = htonl(ct_len);
    return raw_send_exact(&net_len, 4U) && raw_send_exact(ct.data(), ct_len);
}

auto IpcChannel::read_frame() noexcept -> std::optional<std::string>
{
    uint32_t net_len{};
    if (!raw_recv_exact(&net_len, 4U))
    {
        return std::nullopt;
    }
    auto const ct_len = ntohl(net_len);
    if (ct_len < static_cast<std::uint32_t>(cipher_->ciphertext_size(0U)) ||
        ct_len > max_frame_bytes_ + static_cast<std::uint32_t>(cipher_->ciphertext_size(0U)))
    {
        return std::nullopt;
    }

    // See write_frame: defend the noexcept contract against std::bad_alloc.
    auto ct = std::vector<uint8_t>{};
    try
    {
        ct.resize(ct_len);
    }
    catch (std::bad_alloc const&)
    {
        return std::nullopt;
    }
    if (!raw_recv_exact(ct.data(), ct_len))
    {
        return std::nullopt;
    }

    auto const pt_len = ct_len - static_cast<std::uint32_t>(cipher_->ciphertext_size(0U));
    auto pt = std::string{};
    try
    {
        pt.resize(pt_len);
    }
    catch (std::bad_alloc const&)
    {
        return std::nullopt;
    }
    if (!cipher_->decrypt(std::span<uint8_t const>{ct.data(), ct_len}, std::span<char>{pt.data(), pt_len}))
    {
        return std::nullopt;
    }
    return pt;
}

auto IpcChannel::build_frame(std::uint64_t id, std::optional<std::uint64_t> reply_to, std::string_view body)
    -> std::string
{
    auto frame = std::string{"{\"id\":"};
    frame += std::to_string(id);
    if (reply_to.has_value())
    {
        frame += ",\"reply_to\":";
        frame += std::to_string(*reply_to);
    }
    // Append body fields after the opening '{'.
    if (body.size() > 1U)
    {
        frame += ',';
        frame.append(body.data() + 1U, body.size() - 1U);
    }
    else
    {
        frame += '}';
    }
    return frame;
}

auto IpcChannel::report_oversize_drop(std::string_view json_body, char const* kind) const noexcept -> void
{
    // Extract the frame "type" for diagnostics without trusting the body to be
    // well-formed; a failed parse just yields an empty type string.
    auto const type = ipc::ipc_json_get_str(json_body, "type");
    LOG_WARNING("ipc: dropping oversize " + std::string{kind} +
                " frame: body_bytes=" + std::to_string(json_body.size()) + " cap=" + std::to_string(max_frame_bytes_) +
                " type=\"" + type + "\"");
}

auto IpcChannel::send_request(std::string_view json_body, std::chrono::seconds timeout) -> std::optional<std::string>
{
    // Reject before build_frame so an oversize body never pins a huge allocation
    // (issue #325). The id/reply_to overhead is < 64 bytes, so a body within the
    // cap cannot push the frame materially over it; the edge case is caught by
    // write_frame's cap check.
    if (json_body.size() > max_frame_bytes_)
    {
        report_oversize_drop(json_body, "request");
        return std::nullopt;
    }
    auto const id = next_id_.fetch_add(1U, std::memory_order_relaxed);
    auto const frame = build_frame(id, std::nullopt, json_body);

    auto entry = std::make_shared<PendingEntry>();
    {
        auto const lk = std::lock_guard{pending_mu_};
        pending_[id] = entry;
    }

    {
        auto const lk = std::lock_guard{write_mu_};
        if (!write_frame(frame))
        {
            auto const lk2 = std::lock_guard{pending_mu_};
            pending_.erase(id);
            return std::nullopt;
        }
    }

    auto const deadline = std::chrono::steady_clock::now() + timeout;
    auto lk = std::unique_lock{pending_mu_};
    auto const ok = entry->cv.wait_until(lk, deadline, [&] {
        return entry->ready;
    });
    pending_.erase(id);
    if (!ok || !entry->response.has_value())
    {
        return std::nullopt;
    }
    return std::move(entry->response);
}

auto IpcChannel::send_response(std::uint64_t reply_to, std::string_view json_body) -> void
{
    if (json_body.size() > max_frame_bytes_)
    {
        report_oversize_drop(json_body, "response");
        return;
    }
    auto const id = next_id_.fetch_add(1U, std::memory_order_relaxed);
    auto const frame = build_frame(id, reply_to, json_body);
    auto const lk = std::lock_guard{write_mu_};
    std::ignore = write_frame(frame);
}

auto IpcChannel::send_notification(std::string_view json_body) -> void
{
    if (json_body.size() > max_frame_bytes_)
    {
        report_oversize_drop(json_body, "notification");
        return;
    }
    auto const id = next_id_.fetch_add(1U, std::memory_order_relaxed);
    auto const frame = build_frame(id, std::nullopt, json_body);
    auto const lk = std::lock_guard{write_mu_};
    std::ignore = write_frame(frame);
}

auto IpcChannel::reader_loop() -> void
{
    while (running_.load())
    {
        auto frame = read_frame();
        if (!frame.has_value())
        {
            healthy_.store(false);
            break;
        }

        // Parse the frame once with the fuzzed, depth-bounded canonicaljson
        // parser and read id/reply_to from the DOM. The previous substring
        // scanner misparsed frames whose body string values contained
        // `"id":`-shaped substrings (issue #320). On a malformed frame, drop
        // it and stop the loop rather than act on garbage routing metadata.
        auto const parsed = canonicaljson::parse_json(*frame);
        auto const* obj = std::get_if<canonicaljson::Object>(&parsed.value.storage());
        if (parsed.error != canonicaljson::ParseError::none || obj == nullptr)
        {
            healthy_.store(false);
            break;
        }
        auto const id = extract_uint64(*obj, "id").value_or(0U);
        auto const reply_to = extract_uint64(*obj, "reply_to");

        if (reply_to.has_value())
        {
            // Response to one of our pending send_request calls.
            // Extract before releasing the lock so cv.notify_one() is called
            // outside the critical section — notifying under the mutex would
            // let the waiter wake and immediately re-lock, defeating the cv.
            std::shared_ptr<PendingEntry> entry; // SHARED_PTR: reviewed — outlives lock for cv::notify_one()
            {
                auto const lk = std::lock_guard{pending_mu_};
                auto const it = pending_.find(*reply_to);
                if (it != pending_.end())
                {
                    it->second->response = std::move(*frame);
                    it->second->ready = true;
                    entry = it->second;
                }
            }
            if (entry)
            {
                entry->cv.notify_one();
            }
        }
        else if (id != 0U && request_handler_)
        {
            // Queue for the dispatch thread rather than invoking the handler
            // here: a handler that blocks (e.g. on a lock held by a thread
            // that is itself waiting inside send_request) must never prevent
            // this loop from routing the responses queued behind it.
            {
                auto const lk = std::lock_guard{dispatch_mu_};
                dispatch_queue_.emplace_back(id, std::move(*frame));
            }
            dispatch_cv_.notify_one();
        }
    }

    // Wake all pending waiters so send_request callers return nullopt.
    auto const lk = std::lock_guard{pending_mu_};
    for (auto& [_, e] : pending_)
    {
        e->ready = true;
        e->cv.notify_one();
    }
}

auto IpcChannel::dispatcher_loop() -> void
{
    while (true)
    {
        auto item = std::pair<std::uint64_t, std::string>{};
        {
            auto lk = std::unique_lock{dispatch_mu_};
            dispatch_cv_.wait(lk, [this] {
                return !dispatch_queue_.empty() || !running_.load();
            });
            if (dispatch_queue_.empty())
            {
                // running_ is false and the queue is drained — exit.
                break;
            }
            item = std::move(dispatch_queue_.front());
            dispatch_queue_.pop_front();
        }
        // Invoked outside dispatch_mu_ so a long-running handler never blocks
        // the reader thread from queuing further request frames.
        try
        {
            request_handler_(item.first, std::move(item.second));
        }
        catch (...)
        {
            // A request handler must not be allowed to crash the channel's
            // dispatch thread and call std::terminate(). Mark the channel
            // unhealthy and wake every pending send_request waiter so callers
            // return nullopt instead of hanging.
            healthy_.store(false);
            LOG_WARNING("ipc: unhandled exception in request handler; marking channel unhealthy");
            {
                auto const lk = std::lock_guard{pending_mu_};
                for (auto& [_, e] : pending_)
                {
                    e->ready = true;
                    e->cv.notify_one();
                }
            }
            break;
        }
    }
}

} // namespace merovingian::ipc
