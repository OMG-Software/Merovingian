// SPDX-License-Identifier: GPL-3.0-or-later

#include <merovingian/config/reload_policy.hpp>

namespace merovingian::config
{

auto reload_policy_for_key(std::string_view key) noexcept -> ReloadPolicy
{
    if (key == "server.name" || key == "database.uri_file" || key == "database.role" ||
        key == "listeners.client.tls_certificate_file" || key == "listeners.client.tls_private_key_file" ||
        key == "listeners.federation.tls_certificate_file" || key == "listeners.federation.tls_private_key_file")
    {
        return ReloadPolicy::restart_required;
    }

    return ReloadPolicy::reloadable;
}

auto reload_policy_name(ReloadPolicy policy) noexcept -> char const*
{
    switch (policy)
    {
    case ReloadPolicy::reloadable:
        return "reloadable";
    case ReloadPolicy::restart_required:
        return "restart_required";
    }

    return "restart_required";
}

} // namespace merovingian::config
