// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>

namespace merovingian::config
{

struct ListenerConfig final
{
    std::string bind{};
    bool tls{false};
    bool reverse_proxy{true};
    std::string tls_certificate_file{};
    std::string tls_private_key_file{};
};

} // namespace merovingian::config
