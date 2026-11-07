// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <atomic>

namespace merovingian::tests::tls_mock
{

// Observable state for run_stalling_tls_server below. `request_received` is set
// once the server has read a complete request; `released` is the test's signal
// that the server may finally answer.
struct StallingTlsServerState final
{
    std::atomic<bool> request_received{false};
    std::atomic<bool> released{false};
};

} // namespace merovingian::tests::tls_mock
