// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <mutex>

namespace merovingian::homeserver
{

// ADR-0212: wakes downloads waiting for content that has not been uploaded
// yet (POST /_matrix/media/v1/create, then PUT .../upload/{serverName}/{mediaId}).
//
// A waiter reads generation() while it still holds HomeserverRuntime::mutex,
// releases that mutex, and waits for the generation to move on. An upload that
// commits in between has already moved it, so no wake-up is lost. Every
// waiter re-checks its own media ID after waking: the notifier says only that
// some upload completed.
//
// Locking: the notifier's mutex is a leaf. Never wait while holding
// HomeserverRuntime::mutex (release it first, RuntimeLockRelease), and never
// take HomeserverRuntime::mutex while holding this mutex. notify_uploaded may
// be called with the runtime mutex held. Thread-safe.
class MediaUploadNotifier final
{
public:
    MediaUploadNotifier() = default;
    MediaUploadNotifier(MediaUploadNotifier const&) = delete;
    auto operator=(MediaUploadNotifier const&) -> MediaUploadNotifier& = delete;
    MediaUploadNotifier(MediaUploadNotifier&&) = delete;
    auto operator=(MediaUploadNotifier&&) -> MediaUploadNotifier& = delete;
    ~MediaUploadNotifier() = default;

    // Moves on each time an upload completes.
    [[nodiscard]] auto generation() const -> std::uint64_t;

    // Records that an upload completed and wakes every waiter.
    auto notify_uploaded() -> void;

    // Waits until the generation differs from `seen` or `deadline` passes.
    // True when it moved on.
    [[nodiscard]] auto wait_for_upload(std::uint64_t seen, std::chrono::steady_clock::time_point deadline) -> bool;

    // Threads waiting in wait_for_upload (diagnostics and tests).
    [[nodiscard]] auto waiting() const -> std::size_t;

private:
    mutable std::mutex m_mutex;
    std::condition_variable m_uploaded;
    std::uint64_t m_generation{0U};
    std::size_t m_waiting{0U};
};

} // namespace merovingian::homeserver
