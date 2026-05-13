// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/net/shutdown_signal.hpp"

#include <fcntl.h>
#include <signal.h>
#include <unistd.h>

#include <array>
#include <atomic>

namespace merovingian::net
{
namespace
{

// Pointer to the currently installed shutdown target. The handler only does
// signal-safe work via the stored pointer (single byte write + atomic flag).
std::atomic<ShutdownSignal*> g_active_target{nullptr};

extern "C" void handle_shutdown_signal(int /*signal_number*/) noexcept
{
    auto* target = g_active_target.load(std::memory_order_acquire);
    if (target != nullptr)
    {
        target->fire();
    }
}

[[nodiscard]] auto open_self_pipe(core::FileDescriptor& read_end, core::FileDescriptor& write_end) noexcept -> bool
{
    auto pipe_fds = std::array<int, 2U>{-1, -1};
#if defined(__linux__)
    if (::pipe2(pipe_fds.data(), O_CLOEXEC | O_NONBLOCK) != 0)
    {
        return false;
    }
#else
    if (::pipe(pipe_fds.data()) != 0)
    {
        return false;
    }
    for (auto const pipe_fd : pipe_fds)
    {
        auto const flags = ::fcntl(pipe_fd, F_GETFL, 0);
        if (flags < 0 || ::fcntl(pipe_fd, F_SETFL, flags | O_NONBLOCK) != 0)
        {
            ::close(pipe_fds[0]);
            ::close(pipe_fds[1]);
            return false;
        }
        auto const fd_flags = ::fcntl(pipe_fd, F_GETFD, 0);
        if (fd_flags < 0 || ::fcntl(pipe_fd, F_SETFD, fd_flags | FD_CLOEXEC) != 0)
        {
            ::close(pipe_fds[0]);
            ::close(pipe_fds[1]);
            return false;
        }
    }
#endif
    read_end = core::FileDescriptor{pipe_fds[0]};
    write_end = core::FileDescriptor{pipe_fds[1]};
    return true;
}

} // namespace

ShutdownSignal::ShutdownSignal()
{
    static_cast<void>(open_self_pipe(m_read, m_write));
}

auto ShutdownSignal::valid() const noexcept -> bool
{
    return m_read.valid() && m_write.valid();
}

auto ShutdownSignal::read_fd() const noexcept -> int
{
    return m_read.get();
}

auto ShutdownSignal::fired() const noexcept -> bool
{
    return m_fired.load(std::memory_order_acquire);
}

auto ShutdownSignal::fire() noexcept -> void
{
    if (m_fired.exchange(true, std::memory_order_acq_rel))
    {
        return;
    }
    if (!m_write.valid())
    {
        return;
    }
    auto const byte = char{'x'};
    static_cast<void>(::write(m_write.get(), &byte, 1U));
}

auto install_shutdown_signal_handlers(ShutdownSignal& signal) noexcept -> bool
{
    g_active_target.store(&signal, std::memory_order_release);

    struct sigaction action {};
    action.sa_handler = &handle_shutdown_signal;
    ::sigemptyset(&action.sa_mask);
    action.sa_flags = 0;

    if (::sigaction(SIGINT, &action, nullptr) != 0)
    {
        return false;
    }
    if (::sigaction(SIGTERM, &action, nullptr) != 0)
    {
        return false;
    }
    return true;
}

auto uninstall_shutdown_signal_handlers() noexcept -> void
{
    struct sigaction action {};
    action.sa_handler = SIG_DFL;
    ::sigemptyset(&action.sa_mask);
    action.sa_flags = 0;
    static_cast<void>(::sigaction(SIGINT, &action, nullptr));
    static_cast<void>(::sigaction(SIGTERM, &action, nullptr));
    g_active_target.store(nullptr, std::memory_order_release);
}

} // namespace merovingian::net
