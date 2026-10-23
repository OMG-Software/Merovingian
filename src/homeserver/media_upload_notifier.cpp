// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/media_upload_notifier.hpp"

namespace merovingian::homeserver
{

auto MediaUploadNotifier::generation() const -> std::uint64_t
{
    auto const lock = std::lock_guard{m_mutex};
    return m_generation;
}

auto MediaUploadNotifier::notify_uploaded() -> void
{
    {
        auto const lock = std::lock_guard{m_mutex};
        ++m_generation;
    }
    m_uploaded.notify_all();
}

auto MediaUploadNotifier::wait_for_upload(std::uint64_t seen, std::chrono::steady_clock::time_point deadline) -> bool
{
    auto lock = std::unique_lock{m_mutex};
    ++m_waiting;
    auto const moved = m_uploaded.wait_until(lock, deadline, [this, seen] {
        return m_generation != seen;
    });
    --m_waiting;
    return moved;
}

auto MediaUploadNotifier::waiting() const -> std::size_t
{
    auto const lock = std::lock_guard{m_mutex};
    return m_waiting;
}

} // namespace merovingian::homeserver
