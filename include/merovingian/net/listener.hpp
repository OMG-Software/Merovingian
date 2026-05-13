// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/config/config.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace merovingian::net
{

enum class ListenerRole : std::uint8_t
{
    client,
    federation,
};

struct ListenerPlan final
{
    ListenerRole role{ListenerRole::client};
    std::string bind{};
    bool tls{false};
    std::string tls_certificate_file{};
    std::string tls_private_key_file{};
};

class RuntimeListeners final
{
public:
    RuntimeListeners() = default;
    explicit RuntimeListeners(std::vector<ListenerPlan> plans);

    [[nodiscard]] auto plans() const noexcept -> std::vector<ListenerPlan> const&;
    [[nodiscard]] auto count() const noexcept -> std::size_t;
    [[nodiscard]] auto empty() const noexcept -> bool;

private:
    std::vector<ListenerPlan> m_plans{};
};

[[nodiscard]] auto make_runtime_listeners(config::Config const& config) -> RuntimeListeners;
[[nodiscard]] auto listener_role_name(ListenerRole role) noexcept -> char const*;

} // namespace merovingian::net
