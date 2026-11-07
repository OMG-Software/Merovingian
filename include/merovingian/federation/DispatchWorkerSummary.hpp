// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>

namespace merovingian::federation
{

struct DispatchWorkerSummary final
{
    std::size_t enqueued{0U};
    std::size_t delivered{0U};
    std::size_t failed{0U};
    std::size_t dropped{0U};
    std::size_t pending{0U};
    // Transactions refused at enqueue because the queue, or the destination's share of it, was
    // full. A malformed transaction or one offered during shutdown is not counted.
    std::size_t rejected{0U};
};

} // namespace merovingian::federation
