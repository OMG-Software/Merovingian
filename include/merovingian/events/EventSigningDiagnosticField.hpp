// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>

namespace merovingian::events
{

// One key/value pair of the diagnostic emitted when an event is signed. Modelled
// here rather than as an observability::StructuredLogField so EventSigner.hpp
// does not drag the observability header (and its database/http dependencies)
// into every translation unit that signs an event.
struct EventSigningDiagnosticField final
{
    std::string key{};
    std::string value{};
};

} // namespace merovingian::events
