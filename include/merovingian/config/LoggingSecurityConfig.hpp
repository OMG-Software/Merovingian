// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

namespace merovingian::config
{

struct LoggingSecurityConfig final
{
    bool redact_tokens{true};
    bool redact_event_content{true};
};

} // namespace merovingian::config
