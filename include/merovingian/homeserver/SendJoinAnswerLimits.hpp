// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/config/Config.hpp"

#include <cstdint>

namespace merovingian::homeserver
{

// The caps a send_join answer has to fit: `join_response_max_size` for the body, the size an
// operator accepts a join response at (and the size this server accepts when IT joins), and the
// frame cap of the channel to the federation workers.
struct SendJoinAnswerLimits final
{
    std::uint64_t max_body_bytes{0U};
    std::uint64_t max_frame_bytes{0U};
};

} // namespace merovingian::homeserver
