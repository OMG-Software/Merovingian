// SPDX-License-Identifier: GPL-3.0-or-later

#include <merovingian/net/listener.hpp>

#include <utility>

namespace merovingian::net
{

RuntimeListeners::RuntimeListeners(std::vector<ListenerPlan> plans)
    : m_plans{std::move(plans)}
{
}

auto RuntimeListeners::plans() const noexcept -> std::vector<ListenerPlan> const&
{
    return m_plans;
}

auto RuntimeListeners::count() const noexcept -> std::size_t
{
    return m_plans.size();
}

auto RuntimeListeners::empty() const noexcept -> bool
{
    return m_plans.empty();
}

auto make_runtime_listeners(config::Config const& config) -> RuntimeListeners
{
    auto plans = std::vector<ListenerPlan>{};
    plans.reserve(2U);

    plans.push_back({ListenerRole::client, config.listeners().client.bind, config.listeners().client.tls});

    if (config.security().federation.enabled)
    {
        plans.push_back(
            {ListenerRole::federation, config.listeners().federation.bind, config.listeners().federation.tls}
        );
    }

    return RuntimeListeners{std::move(plans)};
}

auto listener_role_name(ListenerRole role) noexcept -> char const*
{
    switch (role)
    {
    case ListenerRole::client:
        return "client";
    case ListenerRole::federation:
        return "federation";
    }

    return "unknown";
}

} // namespace merovingian::net
