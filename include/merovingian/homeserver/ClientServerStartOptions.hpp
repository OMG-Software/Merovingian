// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

namespace merovingian::homeserver
{

// Startup-only options supplied by the process entry point. They are not
// configuration-file settings and cannot change after the runtime starts.
struct ClientServerStartOptions final
{
    bool debug_startup_enabled{false};
};

} // namespace merovingian::homeserver
