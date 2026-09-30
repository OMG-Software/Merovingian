// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
// RED-PHASE STUB: holds connections and never dispatches them.

#include "merovingian/net/connection_parker.hpp"

#include <mutex>
#include <vector>

namespace merovingian::net
{

class ConnectionParker::State
{
public:
    std::mutex mutex{};
    std::vector<std::unique_ptr<Connection>> held{};
    bool started{false};
};

ConnectionParker::ActiveShare::ActiveShare(ActiveShare&& other) noexcept = default;
auto ConnectionParker::ActiveShare::operator=(ActiveShare&& other) noexcept -> ActiveShare& = default;
ConnectionParker::ActiveShare::~ActiveShare() = default;
auto ConnectionParker::ActiveShare::release() noexcept -> void
{
    m_state.reset();
}
auto ConnectionParker::ActiveShare::held() const noexcept -> bool
{
    return m_state != nullptr;
}

ConnectionParker::ConnectionParker(Limits, DispatchFn)
    : m_state{std::make_shared<State>()}
{
}
ConnectionParker::~ConnectionParker() = default;
auto ConnectionParker::start() -> bool
{
    m_state->started = true;
    return true;
}
auto ConnectionParker::request_stop() -> void
{
}
auto ConnectionParker::running() const -> bool
{
    return m_state->started;
}
auto ConnectionParker::park(std::unique_ptr<Connection> connection, std::string,
                            std::chrono::steady_clock::time_point) -> bool
{
    auto const lock = std::lock_guard{m_state->mutex};
    m_state->held.push_back(std::move(connection));
    return true;
}
auto ConnectionParker::parked() const -> std::size_t
{
    return m_state->held.size();
}
auto ConnectionParker::active() const -> std::size_t
{
    return 0U;
}
auto ConnectionParker::active(std::string const&) const -> std::size_t
{
    return 0U;
}

} // namespace merovingian::net
