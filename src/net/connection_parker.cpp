// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/net/connection_parker.hpp"

#include "merovingian/core/file_descriptor.hpp"
#include "merovingian/observability/logger.hpp"
#include "merovingian/observability/observability.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdint>
#include <deque>
#include <exception>
#include <limits>
#include <mutex>
#include <string_view>
#include <system_error>
#include <tuple>
#include <unordered_map>
#include <utility>
#include <vector>

#include <fcntl.h>
#include <poll.h>
#include <unistd.h>

namespace merovingian::net
{
namespace
{

    auto log_diagnostic(std::string_view event, std::vector<observability::StructuredLogField> fields,
                        observability::LogEventSeverity severity = observability::LogEventSeverity::debug) -> void
    {
        observability::log_diagnostic("connection_parker", event, fields, severity);
    }

    // Close-on-exec, non-blocking self-pipe (the same construction as
    // ShutdownSignal): the wake-up must never block the thread that writes it,
    // and must never leak into a spawned worker process.
    [[nodiscard]] auto open_wake_pipe(core::FileDescriptor& read_end, core::FileDescriptor& write_end) noexcept -> bool
    {
        auto pipe_fds = std::array<int, 2U>{-1, -1};
#if defined(__linux__)
        if (::pipe2(pipe_fds.data(), O_CLOEXEC | O_NONBLOCK) != 0)
        {
            return false;
        }
        read_end = core::FileDescriptor{pipe_fds[0]};
        write_end = core::FileDescriptor{pipe_fds[1]};
#else
        if (::pipe(pipe_fds.data()) != 0)
        {
            return false;
        }
        read_end = core::FileDescriptor{pipe_fds[0]};
        write_end = core::FileDescriptor{pipe_fds[1]};
        for (auto const pipe_fd : pipe_fds)
        {
            auto const flags = ::fcntl(pipe_fd, F_GETFL, 0);
            if (flags < 0 || ::fcntl(pipe_fd, F_SETFL, flags | O_NONBLOCK) != 0)
            {
                return false;
            }
            auto const fd_flags = ::fcntl(pipe_fd, F_GETFD, 0);
            if (fd_flags < 0 || ::fcntl(pipe_fd, F_SETFD, fd_flags | FD_CLOEXEC) != 0)
            {
                return false;
            }
        }
#endif
        return true;
    }

    struct Entry final
    {
        std::unique_ptr<ConnectionParker::Connection> connection{};
        std::string client_key{};
        std::chrono::steady_clock::time_point deadline{};
    };

    // poll() takes whole milliseconds; round up so a deadline is never
    // re-checked a moment before it passes (which would spin).
    [[nodiscard]] auto poll_timeout_ms(std::vector<Entry> const& awaiting,
                                       std::chrono::steady_clock::time_point now) noexcept -> int
    {
        if (awaiting.empty())
        {
            return -1;
        }
        auto earliest = awaiting.front().deadline;
        for (auto const& entry : awaiting)
        {
            earliest = std::min(earliest, entry.deadline);
        }
        if (earliest <= now)
        {
            return 0;
        }
        auto const wait = std::chrono::duration_cast<std::chrono::microseconds>(earliest - now).count();
        auto const milliseconds = (wait + 999) / 1000;
        return milliseconds > std::numeric_limits<int>::max() ? std::numeric_limits<int>::max()
                                                              : static_cast<int>(milliseconds);
    }

} // namespace

// Everything the parker thread and the ActiveShares touch. Shared, so a share
// released after the ConnectionParker object is gone still has somewhere to go,
// and the thread never dereferences the ConnectionParker itself.
//
// `mutex` guards every data member below it. It is a leaf lock: nothing else
// is locked, and no connection is closed, polled or dispatched, while it is
// held. `awaiting` and `ready` are private to the parker thread and unguarded.
class ConnectionParker::State final
{
public:
    State(Limits limits, DispatchFn dispatch)
        : m_limits{limits}
        , m_dispatch{std::move(dispatch)}
    {
        m_limits.max_active = std::max<std::size_t>(1U, m_limits.max_active);
        m_limits.max_active_per_client = std::max<std::size_t>(1U, m_limits.max_active_per_client);
    }

    // Written once by start() before the thread exists; read-only after.
    core::FileDescriptor wake_read{};
    core::FileDescriptor wake_write{};

    mutable std::mutex mutex{};
    std::vector<Entry> incoming{};
    std::size_t parked_count{0U};
    std::size_t active_total{0U};
    std::unordered_map<std::string, std::size_t> active_per_client{};
    bool started{false};
    bool stopping{false};
    bool wake_pending{false};

    auto limits() const noexcept -> Limits const&
    {
        return m_limits;
    }

    // Wakes the thread. Call without the lock, after setting wake_pending
    // under it (so a burst of wakes writes one byte, not one per caller).
    auto write_wake() const noexcept -> void
    {
        auto const byte = std::uint8_t{1U};
        // Non-blocking: a full pipe already holds a pending wake-up.
        std::ignore = ::write(wake_write.get(), &byte, 1U);
    }

    auto release_share(std::string const& client_key) noexcept -> void
    {
        auto need_write = false;
        {
            auto const lock = std::lock_guard{mutex};
            if (active_total > 0U)
            {
                --active_total;
            }
            if (!client_key.empty())
            {
                if (auto const found = active_per_client.find(client_key); found != active_per_client.end())
                {
                    if (found->second <= 1U)
                    {
                        active_per_client.erase(found);
                    }
                    else
                    {
                        --found->second;
                    }
                }
            }
            if (started && !stopping && !wake_pending)
            {
                wake_pending = true;
                need_write = true;
            }
        }
        if (need_write)
        {
            write_wake();
        }
    }

    static auto run(std::shared_ptr<State> self) -> void; // SHARED_PTR: reviewed — the thread keeps State alive

private:
    auto drain_wake() const noexcept -> void
    {
        auto buffer = std::array<std::uint8_t, 64U>{};
        while (::read(wake_read.get(), buffer.data(), buffer.size()) > 0)
        {
        }
    }

    // Hands out every ready connection the caps allow, oldest first. The
    // selection happens under the lock; the callbacks run after it is dropped.
    auto dispatch_ready(std::shared_ptr<State> const& self, std::deque<Entry>& ready) -> void
    {
        auto out = std::vector<Dispatched>{};
        {
            auto const lock = std::lock_guard{mutex};
            if (stopping)
            {
                return;
            }
            for (auto it = ready.begin(); it != ready.end() && active_total < m_limits.max_active;)
            {
                if (!it->client_key.empty())
                {
                    auto const found = active_per_client.find(it->client_key);
                    auto const held = found == active_per_client.end() ? std::size_t{0U} : found->second;
                    if (held >= m_limits.max_active_per_client)
                    {
                        // Over this client's share: it stays parked, out of the
                        // poll set, until one of the client's shares is released.
                        ++it;
                        continue;
                    }
                    ++active_per_client[it->client_key];
                }
                ++active_total;
                --parked_count;
                auto key = it->client_key;
                out.push_back(Dispatched{
                    std::move(it->connection), std::move(it->client_key), ActiveShare{self, std::move(key)}
                });
                it = ready.erase(it);
            }
        }
        for (auto& dispatched : out)
        {
            try
            {
                m_dispatch(std::move(dispatched));
            }
            catch (...)
            {
                // The value was moved into the call; whatever it still owned is
                // closed and its share released as it unwound.
                log_diagnostic("dispatch.exception", {}, observability::LogEventSeverity::warning);
            }
        }
    }

    Limits m_limits;
    DispatchFn m_dispatch;
};

auto ConnectionParker::State::run(std::shared_ptr<State> self) -> void // SHARED_PTR: reviewed — see declaration
{
    auto& state = *self;
    auto awaiting = std::vector<Entry>{};
    auto ready = std::deque<Entry>{};
    auto fds = std::vector<pollfd>{};
    while (true)
    {
        // Drain BEFORE taking the queue: a wake written after this point is
        // left in the pipe for the poll below, so a connection parked (or a
        // share released) between the drain and the swap is never missed.
        state.drain_wake();
        auto arrived = std::vector<Entry>{};
        {
            auto const lock = std::lock_guard{state.mutex};
            if (state.stopping)
            {
                break;
            }
            arrived.swap(state.incoming);
            state.wake_pending = false;
        }
        for (auto& entry : arrived)
        {
            if (entry.connection->has_buffered_input())
            {
                ready.push_back(std::move(entry));
            }
            else
            {
                awaiting.push_back(std::move(entry));
            }
        }
        state.dispatch_ready(self, ready);

        fds.clear();
        fds.push_back(pollfd{state.wake_read.get(), POLLIN, 0});
        for (auto const& entry : awaiting)
        {
            fds.push_back(pollfd{entry.connection->fd(), POLLIN, 0});
        }
        auto const poll_result = ::poll(fds.data(), static_cast<nfds_t>(fds.size()),
                                        poll_timeout_ms(awaiting, std::chrono::steady_clock::now()));
        if (poll_result < 0 && errno != EINTR)
        {
            log_diagnostic("poll.failed",
                           {
                               {"errno", std::to_string(errno), false}
            },
                           observability::LogEventSeverity::warning);
            // Back off rather than spin on a persistent error; deadlines are
            // still enforced below.
            std::ignore = ::poll(nullptr, 0U, 10);
        }

        auto const now = std::chrono::steady_clock::now();
        auto still_waiting = std::vector<Entry>{};
        still_waiting.reserve(awaiting.size());
        auto removed = std::size_t{0U};
        for (auto index = std::size_t{0U}; index < awaiting.size(); ++index)
        {
            auto& entry = awaiting[index];
            auto const revents = poll_result > 0 ? fds[index + 1U].revents : short{0};
            if ((revents & POLLNVAL) != 0)
            {
                // Not a descriptor we can wait on; drop it (closes).
                ++removed;
                entry.connection.reset();
                continue;
            }
            if ((revents & POLLIN) != 0)
            {
                // Readable: a request (or the peer's orderly close, which the
                // worker reads as end of stream and closes quietly).
                ready.push_back(std::move(entry));
                continue;
            }
            if ((revents & (POLLHUP | POLLERR)) != 0)
            {
                // Gone with nothing to read: close here, no worker needed.
                ++removed;
                entry.connection.reset();
                continue;
            }
            if (entry.deadline <= now)
            {
                entry.connection->on_park_expired();
                ++removed;
                entry.connection.reset();
                continue;
            }
            still_waiting.push_back(std::move(entry));
        }
        awaiting.swap(still_waiting);
        if (removed > 0U)
        {
            auto const lock = std::lock_guard{state.mutex};
            state.parked_count -= std::min(removed, state.parked_count);
        }
    }

    // Stopping: close everything still parked, outside the lock.
    auto leftover = std::vector<Entry>{};
    {
        auto const lock = std::lock_guard{state.mutex};
        leftover.swap(state.incoming);
    }
    auto const closing = awaiting.size() + ready.size() + leftover.size();
    awaiting.clear();
    ready.clear();
    leftover.clear();
    {
        auto const lock = std::lock_guard{state.mutex};
        state.parked_count = 0U;
    }
    log_diagnostic("stopped", {
                                  {"closed", std::to_string(closing), false}
    });
}

ConnectionParker::ActiveShare::ActiveShare(std::shared_ptr<State> state, std::string client_key) noexcept
    : m_state{std::move(state)}
    , m_client_key{std::move(client_key)}
{
}

ConnectionParker::ActiveShare::ActiveShare(ActiveShare&& other) noexcept
    : m_state{std::move(other.m_state)}
    , m_client_key{std::move(other.m_client_key)}
{
}

auto ConnectionParker::ActiveShare::operator=(ActiveShare&& other) noexcept -> ActiveShare&
{
    if (this != &other)
    {
        release();
        m_state = std::move(other.m_state);
        m_client_key = std::move(other.m_client_key);
    }
    return *this;
}

ConnectionParker::ActiveShare::~ActiveShare()
{
    release();
}

auto ConnectionParker::ActiveShare::release() noexcept -> void
{
    if (m_state != nullptr)
    {
        auto const state = std::move(m_state);
        m_state = nullptr;
        state->release_share(m_client_key);
    }
}

auto ConnectionParker::ActiveShare::held() const noexcept -> bool
{
    return m_state != nullptr;
}

ConnectionParker::ConnectionParker(Limits limits, DispatchFn dispatch)
    : m_state{std::make_shared<State>(limits, std::move(dispatch))}
{
}

ConnectionParker::~ConnectionParker()
{
    request_stop();
}

auto ConnectionParker::start() -> bool
{
    {
        auto const lock = std::lock_guard{m_state->mutex};
        if (m_state->started || m_state->stopping)
        {
            return m_state->started && !m_state->stopping;
        }
    }
    if (!open_wake_pipe(m_state->wake_read, m_state->wake_write))
    {
        log_diagnostic("start.failed",
                       {
                           {"reason", "wake pipe",           false},
                           {"errno",  std::to_string(errno), false}
        },
                       observability::LogEventSeverity::error);
        return false;
    }
    try
    {
        m_thread = std::thread{&State::run, m_state};
    }
    catch (std::system_error const& error)
    {
        log_diagnostic("start.failed",
                       {
                           {"reason", "thread",     false},
                           {"what",   error.what(), false}
        },
                       observability::LogEventSeverity::error);
        return false;
    }
    {
        auto const lock = std::lock_guard{m_state->mutex};
        m_state->started = true;
    }
    log_diagnostic("started",
                   {
                       {"max_active",            std::to_string(m_state->limits().max_active),            false},
                       {"max_active_per_client", std::to_string(m_state->limits().max_active_per_client), false}
    });
    return true;
}

auto ConnectionParker::request_stop() -> void
{
    auto need_write = false;
    {
        auto const lock = std::lock_guard{m_state->mutex};
        if (!m_state->stopping)
        {
            m_state->stopping = true;
            need_write = m_state->started;
        }
    }
    if (need_write)
    {
        m_state->write_wake();
    }
    if (m_thread.joinable())
    {
        if (m_thread.get_id() == std::this_thread::get_id())
        {
            // Only reachable if the last owner of the parker was dropped from
            // inside a dispatch callback. The thread touches nothing but the
            // shared State from here on, so it may finish on its own.
            m_thread.detach();
        }
        else
        {
            m_thread.join();
        }
    }
}

auto ConnectionParker::running() const -> bool
{
    auto const lock = std::lock_guard{m_state->mutex};
    return m_state->started && !m_state->stopping;
}

auto ConnectionParker::park(std::unique_ptr<Connection> connection, std::string client_key,
                            std::chrono::steady_clock::time_point deadline) -> bool
{
    if (connection == nullptr)
    {
        return false;
    }
    // Built outside the lock so a refused or failed insertion closes the
    // connection outside it too.
    auto entry = Entry{std::move(connection), std::move(client_key), deadline};
    auto need_write = false;
    {
        auto const lock = std::lock_guard{m_state->mutex};
        if (!m_state->started || m_state->stopping)
        {
            return false;
        }
        m_state->incoming.push_back(std::move(entry));
        ++m_state->parked_count;
        if (!m_state->wake_pending)
        {
            m_state->wake_pending = true;
            need_write = true;
        }
    }
    if (need_write)
    {
        m_state->write_wake();
    }
    return true;
}

auto ConnectionParker::parked() const -> std::size_t
{
    auto const lock = std::lock_guard{m_state->mutex};
    return m_state->parked_count;
}

auto ConnectionParker::active() const -> std::size_t
{
    auto const lock = std::lock_guard{m_state->mutex};
    return m_state->active_total;
}

auto ConnectionParker::active(std::string const& client_key) const -> std::size_t
{
    auto const lock = std::lock_guard{m_state->mutex};
    auto const found = m_state->active_per_client.find(client_key);
    return found == m_state->active_per_client.end() ? 0U : found->second;
}

} // namespace merovingian::net
