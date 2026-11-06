// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

namespace merovingian::platform
{

struct SignalHandlingPlan final
{
    bool install_shutdown_handlers{true};
    bool ignore_sigpipe{true};
    bool block_unexpected_signals{true};
};

} // namespace merovingian::platform
