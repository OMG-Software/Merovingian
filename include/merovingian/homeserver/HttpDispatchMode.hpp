// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

namespace merovingian::homeserver
{

enum class HttpDispatchMode
{
    client_server,
    local_router,
    federation,
};

} // namespace merovingian::homeserver
