// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

namespace merovingian::http {

class Server final {
public:
    Server() = default;

    auto start() -> void;
    auto stop() noexcept -> void;
};

} // namespace merovingian::http
