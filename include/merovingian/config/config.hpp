// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>

namespace merovingian::config {

struct ServerConfig final {
    std::string server_name{};
    std::string public_baseurl{};
};

class Config final {
public:
    Config() = default;

    [[nodiscard]] auto server() const noexcept -> ServerConfig const&;

private:
    ServerConfig server_{};
};

} // namespace merovingian::config
