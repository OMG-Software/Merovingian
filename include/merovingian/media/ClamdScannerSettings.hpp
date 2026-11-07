// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>

namespace merovingian::media
{

// How the clamd scanner is reached and bounded (ADR-0565). Parsed from the `security.media.clamd_*` keys.
struct ClamdScannerSettings final
{
    // Absolute AF_UNIX socket path of clamd. Empty means malware scanning through clamd is off.
    std::string socket_path{};
    // Deadline for one file's whole exchange, including waiting for scan capacity.
    std::uint32_t timeout_ms{10000U};
    // Media above this is not sent to clamd and stays quarantined (clamd's StreamMaxLength defaults to 25 MiB).
    std::uint64_t max_scan_bytes{25U * 1024U * 1024U};
    // Scans in flight at once; a further scan waits for capacity until its deadline.
    std::uint32_t max_concurrent{4U};

    [[nodiscard]] auto enabled() const noexcept -> bool
    {
        return !socket_path.empty();
    }
};

} // namespace merovingian::media
