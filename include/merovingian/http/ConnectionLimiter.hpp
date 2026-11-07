// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>

namespace merovingian::http
{

// Counts open connections per client key (see client_address_key) and refuses
// a new one once a key holds `cap` of them. Admission is decided at accept
// time, before a single byte is read, so one host cannot take the whole
// connection budget by holding connections open just under the slow-request
// thresholds. Thread-safe.
class ConnectionLimiter final
{
public:
    // One admitted connection. Releases its count when destroyed, on every
    // path, so no error path can leak a slot. Move-only; the limiter must
    // outlive every slot it hands out.
    class Slot final
    {
    public:
        Slot(Slot const&) = delete;
        auto operator=(Slot const&) -> Slot& = delete;
        Slot(Slot&& other) noexcept;
        auto operator=(Slot&&) -> Slot& = delete;
        ~Slot();

    private:
        friend class ConnectionLimiter;
        Slot(ConnectionLimiter& limiter, std::string key) noexcept;

        ConnectionLimiter& m_limiter;
        std::string m_key;
        bool m_held{true};
    };

    ConnectionLimiter() = default;
    ConnectionLimiter(ConnectionLimiter const&) = delete;
    auto operator=(ConnectionLimiter const&) -> ConnectionLimiter& = delete;
    ConnectionLimiter(ConnectionLimiter&&) = delete;
    auto operator=(ConnectionLimiter&&) -> ConnectionLimiter& = delete;
    ~ConnectionLimiter() = default;

    // A slot for `key` when it holds fewer than `cap` connections; nullopt
    // when the cap is reached. A cap of 0 admits nothing.
    [[nodiscard]] auto try_acquire(std::string key, std::uint32_t cap) -> std::optional<Slot>;

    // Connections currently open under `key`.
    [[nodiscard]] auto active(std::string_view key) const -> std::uint32_t;

    // Keys with at least one open connection. Keys are erased when their
    // count reaches zero, so memory is bounded by live connections.
    [[nodiscard]] auto tracked_keys() const -> std::size_t;

private:
    auto release(std::string const& key) noexcept -> void;

    mutable std::mutex m_mutex;
    std::unordered_map<std::string, std::uint32_t> m_counts;
};

} // namespace merovingian::http
