// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <merovingian/config/config.hpp>

#include <cstdint>
#include <string>
#include <vector>

namespace merovingian::federation
{

struct RuntimeFederationConfig final
{
    bool enabled{false};
    std::string default_policy{};
    bool require_valid_tls{true};
    bool verify_json_signatures{true};
    std::vector<std::string> deny_ip_ranges{};
    std::uint64_t max_transaction_bytes{0U};
    std::uint32_t remote_timeout_seconds{0U};
};

[[nodiscard]] auto make_runtime_federation_config(config::Config const& config) -> RuntimeFederationConfig;
[[nodiscard]] auto federation_summary(RuntimeFederationConfig const& config) -> std::string;

} // namespace merovingian::federation
