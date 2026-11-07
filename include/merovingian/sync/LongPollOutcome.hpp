// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

namespace merovingian::sync
{

struct LongPollOutcome final
{
    // A rerun completed.
    bool dispatched{false};
    // `idle` reported the client gone.
    bool client_gone{false};
};

} // namespace merovingian::sync
