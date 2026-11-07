// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>

namespace merovingian::media
{

// Outcome of apply_decoder_hardening(). `accepted` is true only when every
// hardening control applicable on this platform succeeded (self-imposed
// resource limits everywhere, plus the platform sandbox: seccomp on Linux,
// pledge on OpenBSD, cap_enter on FreeBSD). A platform with no in-process
// sandbox (NetBSD) is never accepted: `failed_control` is then
// "no platform decoder sandbox". When false, `failed_control` names the
// control that failed, so the caller can report why before refusing to read
// untrusted input — see thumbnail_worker_main.cpp::main().
struct DecoderHardeningResult final
{
    bool accepted{false};
    std::string failed_control{};
};

} // namespace merovingian::media
