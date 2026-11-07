// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
// Derived from SingleLog by James Chapman, BSD-3-Clause.
#pragma once

namespace merovingian::observability
{

enum class LogEventSeverity
{
    // Per-event severity. Mirrors LogLevel so the threshold check is
    // uniform across the diagnostic and audit-routing paths. The
    // `log_diagnostic` free function takes one as its fourth arg with
    // a default of `LogEventSeverity::debug`, so the 40+ existing
    // call sites continue to compile unchanged.
    trace = 100,
    debug = 200,
    info = 300,
    notice = 400,
    warning = 500,
    error = 600,
    critical = 700,
};

} // namespace merovingian::observability
