// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/media/ClamdScanResult.hpp"
#include "merovingian/media/ClamdScannerSettings.hpp"

#include <atomic>
#include <cstdint>
#include <string_view>

namespace merovingian::media
{

// Client for a local ClamAV daemon (ADR-0565): sends bytes with clamd's INSTREAM command over an AF_UNIX socket.
//
// `scan` blocks for up to `timeout_ms`. Never call it with `HomeserverRuntime::mutex` held; release the lock for the
// call (`homeserver::RuntimeLockRelease`). Thread-safe: concurrent scans are bounded by `max_concurrent`.
//
// Fails closed: a connect failure, timeout, ERROR or malformed reply, or a lack of scan capacity yields a verdict
// that is not `clean`. Holds no shared state beyond the in-flight count, so it is not copyable.
class ClamdScanner final
{
public:
    explicit ClamdScanner(ClamdScannerSettings settings);

    ClamdScanner(ClamdScanner const&) = delete;
    auto operator=(ClamdScanner const&) -> ClamdScanner& = delete;
    ClamdScanner(ClamdScanner&&) = delete;
    auto operator=(ClamdScanner&&) -> ClamdScanner& = delete;
    ~ClamdScanner() = default;

    [[nodiscard]] auto enabled() const noexcept -> bool;
    [[nodiscard]] auto settings() const noexcept -> ClamdScannerSettings const&;

    // Scans `bytes`. Media above `max_scan_bytes` is not sent (`oversize`). A scanner that is not enabled answers
    // `failed`: callers check `enabled()` first.
    [[nodiscard]] auto scan(std::string_view bytes) -> ClamdScanResult;

    // Scans in flight now (for tests and metrics).
    [[nodiscard]] auto in_flight() const noexcept -> std::uint32_t;

private:
    ClamdScannerSettings m_settings;
    std::atomic<std::uint32_t> m_in_flight{0U};
};

// Whether this platform lets the main process connect to a clamd AF_UNIX socket (ADR-0566). True on Linux (the
// seccomp filter allows AF_UNIX sockets and connect, and Landlock confines only the federation worker) and NetBSD.
// False on FreeBSD (Capsicum capability mode forbids connecting to a path) and OpenBSD (unveil hides the socket
// path); startup refuses a configured socket there rather than quarantining every file.
[[nodiscard]] auto clamd_supported_on_this_platform() noexcept -> bool;

} // namespace merovingian::media
