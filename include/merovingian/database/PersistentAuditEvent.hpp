// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>

namespace merovingian::database
{

struct PersistentAuditEvent final
{
    std::string category{};
    std::string event_type{};
    std::string actor{};
    std::string target{};
    std::string reason{};
    // Unix milliseconds the row was appended. 0 means "not stamped yet": `append_audit_event` stamps it, and a
    // row the table holds with 0 is never deleted by retention (ADR-0489).
    std::uint64_t created_at_ms{0U};
};

} // namespace merovingian::database
