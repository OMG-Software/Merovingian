// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>

namespace merovingian::media
{

struct SandboxedMediaWorkerPlan final
{
    bool dedicated_worker{true};
    bool network_disabled{true};
    bool read_only_root{true};
    bool private_tmp{true};
    bool seccomp_required{true};
    std::uint32_t decode_timeout_seconds{10U};
    std::uint64_t memory_limit_bytes{268435456U};
};

} // namespace merovingian::media
