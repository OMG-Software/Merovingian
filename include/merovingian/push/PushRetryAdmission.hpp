// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>

namespace merovingian::push
{

enum class PushRetryAdmission : std::uint8_t
{
    queued,
    // push_retry_max_retries retries have already been made.
    gave_up,
    // The queue, or the recipient's share of it, is full.
    queue_full,
};

} // namespace merovingian::push
