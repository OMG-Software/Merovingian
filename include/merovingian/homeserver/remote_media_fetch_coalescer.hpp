// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_set>

namespace merovingian::homeserver
{

// One fetch from the origin per remote file at a time (ADR-0121).
//
// Two requests for the same remote file must not both fetch it: storing the
// second copy displaces the first from the remote media cache and deletes it
// (plan_remote_media_admission), and a request still reading the first copy
// then fails. The first request to ask leads the fetch; a later one waits until
// the lead ends and then reads the copy the leader stored.
//
// Locking: the coalescer's mutex is a leaf. Never wait while holding
// HomeserverRuntime::mutex (release it first, RuntimeLockRelease), and never
// take HomeserverRuntime::mutex while holding this mutex. A Lead may be
// released with the runtime mutex held. Thread-safe.
class RemoteMediaFetchCoalescer final
{
public:
    // The right to fetch one file. Releases it, and wakes every waiter, when
    // destroyed. Move-only; the coalescer must outlive every lead.
    class Lead final
    {
    public:
        Lead(Lead const&) = delete;
        auto operator=(Lead const&) -> Lead& = delete;
        Lead(Lead&& other) noexcept;
        auto operator=(Lead&&) -> Lead& = delete;
        ~Lead();

    private:
        friend class RemoteMediaFetchCoalescer;
        Lead(RemoteMediaFetchCoalescer& coalescer, std::string key) noexcept;

        RemoteMediaFetchCoalescer& m_coalescer;
        std::string m_key;
        bool m_held{true};
    };

    RemoteMediaFetchCoalescer() = default;
    RemoteMediaFetchCoalescer(RemoteMediaFetchCoalescer const&) = delete;
    auto operator=(RemoteMediaFetchCoalescer const&) -> RemoteMediaFetchCoalescer& = delete;
    RemoteMediaFetchCoalescer(RemoteMediaFetchCoalescer&&) = delete;
    auto operator=(RemoteMediaFetchCoalescer&&) -> RemoteMediaFetchCoalescer& = delete;
    ~RemoteMediaFetchCoalescer() = default;

    // The lead for `key` when nobody holds it; nullopt otherwise. Never waits.
    [[nodiscard]] auto try_lead(std::string key) -> std::optional<Lead>;

    // Waits until nobody leads `key` or `deadline` passes. True when nobody
    // leads it (it may be led again by the time the caller acts on that).
    [[nodiscard]] auto wait_until_idle(std::string_view key, std::chrono::steady_clock::time_point deadline) -> bool;

    // Files being fetched, and threads waiting in wait_until_idle (diagnostics
    // and tests).
    [[nodiscard]] auto in_flight() const -> std::size_t;
    [[nodiscard]] auto waiting() const -> std::size_t;

private:
    auto release(std::string const& key) noexcept -> void;

    mutable std::mutex m_mutex;
    std::condition_variable m_released;
    std::unordered_set<std::string> m_leading;
    std::size_t m_waiting{0U};
};

} // namespace merovingian::homeserver
