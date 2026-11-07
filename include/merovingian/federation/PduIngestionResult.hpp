// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/federation/PduIngestionStatus.hpp"

#include <cstdint>
#include <string>

namespace merovingian::federation
{

struct PduIngestionResult final
{
    PduIngestionStatus status{PduIngestionStatus::internal_error};
    std::string reason{};
    // Set by production sinks that allocate a stream_ordering for the event.
    // Zero when the result is not accepted or the sink does not assign one.
    std::uint64_t accepted_stream_ordering{0U};
    // Set by production sinks that allocate a sync_stream_id for the event.
    // Zero when the result is not accepted or the sink does not assign one.
    std::uint64_t accepted_sync_stream_id{0U};
};

} // namespace merovingian::federation
