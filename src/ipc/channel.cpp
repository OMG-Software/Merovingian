// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/ipc/channel.hpp"

#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/ipc/federation_ipc_frames.hpp"
#include "merovingian/observability/logger.hpp"

#include <array>
#include <cstring>
#include <new>
#include <stdexcept>
#include <string>
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

IpcChannel::IpcChannel(core::FileDescriptor fd, Role role, crypto::IpcAuthKey auth_key, std::uint32_t max_frame_bytes)
    : fd_{std::move(fd)}
    , role_{role}
    , max_frame_bytes_{max_frame_bytes == 0U ? kIpcMaxFrameBytes : max_frame_bytes}
{
    uint8_t my_pk[crypto_kx_PUBLICKEYBYTES]{};
    uint8_t my_sk[crypto_kx_SECRETKEYBYTES]{};
    crypto_kx_keypair(my_pk, my_sk);

    uint8_t peer_pk[crypto_kx_PUBLICKEYBYTES]{};

    // Both sides write then read — AF_UNIX socketpair kernel buffer absorbs
    // the 32-byte writes, so there is no send/recv ordering deadlock here.
    if (!raw_send_exact(my_pk, sizeof(my_pk)) || !raw_recv_exact(peer_pk, sizeof(peer_pk)))
    {
        sodium_memzero(my_sk, sizeof(my_sk));
        throw std::runtime_error{"ipc: public key exchange failed"};
    }

    // Authenticate the peer: both sides MAC (role_byte || my_pk || peer_pk)
    // with the master-key-derived IpcAuthKey and exchange MACs. The role byte
    // is role-dependent so a server MAC cannot be replayed as a client MAC.
    // crypto_kx is confidentiality-only; this proves both peers hold the master
    // key, preventing an unauthorised process from completing the handshake.
    auto const role_byte = static_cast<uint8_t>(role_ == Role::server ? 0x01U : 0x02U);
    auto const peer_role_byte = static_cast<uint8_t>(role_ == Role::server ? 0x02U : 0x01U);
    auto mac_msg = std::array<uint8_t, 1U + crypto_kx_PUBLICKEYBYTES + crypto_kx_PUBLICKEYBYTES>{};
    mac_msg[0U] = role_byte;
    std::memcpy(mac_msg.data() + 1U, my_pk, crypto_kx_PUBLICKEYBYTES);
    std::memcpy(mac_msg.data() + 1U + crypto_kx_PUBLICKEYBYTES, peer_pk, crypto_kx_PUBLICKEYBYTES);

    uint8_t my_mac[crypto_auth_BYTES]{};
    crypto_auth(my_mac, mac_msg.data(), mac_msg.size(), auth_key.bytes.data());

    uint8_t peer_mac[crypto_auth_BYTES]{};
    if (!raw_send_exact(my_mac, sizeof(my_mac)) || !raw_recv_exact(peer_mac, sizeof(peer_mac)))
    {
        sodium_memzero(my_sk, sizeof(my_sk));
        sodium_memzero(my_mac, sizeof(my_mac));
        sodium_memzero(auth_key.bytes.data(), auth_key.bytes.size());
        throw std::runtime_error{"ipc: auth MAC exchange failed"};
    }

    // Verify the peer's MAC against (peer_role_byte || peer_pk || my_pk).
    mac_msg[0U] = peer_role_byte;
    std::memcpy(mac_msg.data() + 1U, peer_pk, crypto_kx_PUBLICKEYBYTES);
    std::memcpy(mac_msg.data() + 1U + crypto_kx_PUBLICKEYBYTES, my_pk, crypto_kx_PUBLICKEYBYTES);
    if (crypto_auth_verify(peer_mac, mac_msg.data(), mac_msg.size(), auth_key.bytes.data()) != 0)
    {
        sodium_memzero(my_sk, sizeof(my_sk));
        sodium_memzero(my_mac, sizeof(my_mac));
        sodium_memzero(peer_mac, sizeof(peer_mac));
        sodium_memzero(auth_key.bytes.data(), auth_key.bytes.size());
        throw std::runtime_error{"ipc: peer authentication failed"};
    }
    sodium_memzero(my_mac, sizeof(my_mac));
    sodium_memzero(peer_mac, sizeof(peer_mac));
    sodium_memzero(auth_key.bytes.data(), auth_key.bytes.size());

    uint8_t rx[crypto_kx_SESSIONKEYBYTES]{};
    uint8_t tx[crypto_kx_SESSIONKEYBYTES]{};
    auto const rc = (role_ == Role::server) ? crypto_kx_server_session_keys(rx, tx, my_pk, my_sk, peer_pk)
                                            : crypto_kx_client_session_keys(rx, tx, my_pk, my_sk, peer_pk);
    sodium_memzero(my_sk, sizeof(my_sk));
    sodium_memzero(my_pk, sizeof(my_pk));
    sodium_memzero(peer_pk, sizeof(peer_pk));

    if (rc != 0)
    {
        sodium_memzero(rx, sizeof(rx));
        sodium_memzero(tx, sizeof(tx));
        throw std::runtime_error{"ipc: session key derivation failed"};
    }

    // Init our push (outgoing) stream.
    uint8_t our_header[crypto_secretstream_xchacha20poly1305_HEADERBYTES]{};
    crypto_secretstream_xchacha20poly1305_init_push(&push_state_, our_header, tx);
    sodium_memzero(tx, sizeof(tx));

    // Server sends its push header first; client receives first.
    uint8_t peer_header[crypto_secretstream_xchacha20poly1305_HEADERBYTES]{};
    if (role_ == Role::server)
    {
        if (!raw_send_exact(our_header, sizeof(our_header)) || !raw_recv_exact(peer_header, sizeof(peer_header)))
        {
            sodium_memzero(rx, sizeof(rx));
            throw std::runtime_error{"ipc: secretstream header exchange failed"};
        }
    }
    else
    {
        if (!raw_recv_exact(peer_header, sizeof(peer_header)) || !raw_send_exact(our_header, sizeof(our_header)))
        {
            sodium_memzero(rx, sizeof(rx));
            throw std::runtime_error{"ipc: secretstream header exchange failed"};
        }
    }

    if (crypto_secretstream_xchacha20poly1305_init_pull(&pull_state_, peer_header, rx) != 0)
    {
        sodium_memzero(rx, sizeof(rx));
        throw std::runtime_error{"ipc: secretstream pull init failed"};
    }

    sodium_memzero(rx, sizeof(rx));
    sodium_memzero(our_header, sizeof(our_header));
    sodium_memzero(peer_header, sizeof(peer_header));
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
    auto const ct_len = static_cast<std::uint32_t>(pt_len + crypto_secretstream_xchacha20poly1305_ABYTES);
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

    crypto_secretstream_xchacha20poly1305_push(&push_state_, ct.data(), nullptr,
                                               reinterpret_cast<uint8_t const*>(plaintext.data()), pt_len, nullptr, 0,
                                               crypto_secretstream_xchacha20poly1305_TAG_MESSAGE);

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
    if (ct_len < static_cast<std::uint32_t>(crypto_secretstream_xchacha20poly1305_ABYTES) ||
        ct_len > max_frame_bytes_ + static_cast<std::uint32_t>(crypto_secretstream_xchacha20poly1305_ABYTES))
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

    auto const pt_len = ct_len - static_cast<std::uint32_t>(crypto_secretstream_xchacha20poly1305_ABYTES);
    auto pt = std::string{};
    try
    {
        pt.resize(pt_len);
    }
    catch (std::bad_alloc const&)
    {
        return std::nullopt;
    }
    uint8_t tag{};
    if (crypto_secretstream_xchacha20poly1305_pull(&pull_state_, reinterpret_cast<uint8_t*>(pt.data()), nullptr, &tag,
                                                   ct.data(), ct_len, nullptr, 0) != 0)
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
            request_handler_(id, std::move(*frame));
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

} // namespace merovingian::ipc
