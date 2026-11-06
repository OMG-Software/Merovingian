// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/federation/inbound_ingestion.hpp"

#include <cstddef>
#include <vector>

namespace merovingian::homeserver
{

struct PendingFederatedJoin final
{
    std::vector<federation::InboundPduEnvelope> pdus{};
    std::size_t json_bytes{0U};
};

} // namespace merovingian::homeserver
