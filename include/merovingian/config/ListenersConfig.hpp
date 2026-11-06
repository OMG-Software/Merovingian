// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/config/ListenerConfig.hpp"

#include <cstdint>

namespace merovingian::config
{

struct ListenersConfig final
{
    ListenerConfig client{"127.0.0.1:8008", false};
    ListenerConfig federation{"127.0.0.1:8009", false};
    // Maximum connections waiting for a worker thread before new connections
    // are refused (0.12.5 audit, finding 11). The accept loops queue one
    // closure per accepted connection, so without a cap a connection flood
    // grows the work queue until the process is OOM-killed. Beyond the cap the
    // listener closes the connection immediately, which sheds load in the one
    // way the client can observe and retry. 0 disables the cap and restores the
    // pre-0.12.5 unbounded behaviour.
    std::uint32_t max_queued_connections{1024U};
};

} // namespace merovingian::config
