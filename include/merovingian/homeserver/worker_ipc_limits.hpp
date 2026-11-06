// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/config/Config.hpp"

#include <cstdint>

namespace merovingian::homeserver
{

// The frame cap of the IPC channel between main and a federation worker, derived from the
// configured response and request budgets. Main sizes its end of the channel with it when it
// spawns a worker and the worker sizes its own end with it from the same --config, so both must
// call this one function: the smaller end would drop the other's oversize frames. A change to a
// size it reads takes a restart of both processes. `send_join_answer_limits` uses it as well, to
// refuse a join whose answer could not cross the channel.
[[nodiscard]] auto worker_ipc_frame_bytes(config::Config const& config) -> std::uint32_t;

} // namespace merovingian::homeserver
