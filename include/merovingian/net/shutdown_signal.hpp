// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <merovingian/core/file_descriptor.hpp>

#include <atomic>

namespace merovingian::net
{

class ShutdownSignal final
{
public:
    ShutdownSignal();

    ShutdownSignal(ShutdownSignal const&) = delete;
    auto operator=(ShutdownSignal const&) -> ShutdownSignal& = delete;

    ShutdownSignal(ShutdownSignal&&) noexcept = default;
    auto operator=(ShutdownSignal&&) noexcept -> ShutdownSignal& = default;

    ~ShutdownSignal() = default;

    [[nodiscard]] auto valid() const noexcept -> bool;
    [[nodiscard]] auto read_fd() const noexcept -> int;
    [[nodiscard]] auto fired() const noexcept -> bool;

    // Safe to call from a signal handler — writes one byte to the self-pipe.
    auto fire() noexcept -> void;

private:
    core::FileDescriptor m_read{};
    core::FileDescriptor m_write{};
    std::atomic<bool> m_fired{false};
};

// Install SIGINT and SIGTERM handlers that fire the given shutdown signal.
// Returns true on success. Subsequent installs replace the previous target.
[[nodiscard]] auto install_shutdown_signal_handlers(ShutdownSignal& signal) noexcept -> bool;

// Restore default disposition for SIGINT and SIGTERM. Always safe to call.
auto uninstall_shutdown_signal_handlers() noexcept -> void;

} // namespace merovingian::net
