// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/media/DecoderHardeningOps.hpp"
#include "merovingian/media/DecoderHardeningResult.hpp"

#include <cstdint>
#include <functional>
#include <string>
#include <string_view>

namespace merovingian::media
{

// True where the platform has an in-process primitive that confines the
// decoder: Linux (seccomp-bpf), OpenBSD (pledge), FreeBSD (Capsicum). False
// elsewhere, notably NetBSD, where apply_decoder_hardening() refuses and the
// worker therefore never decodes. Uses the same preprocessor conditions as the
// platform ladder in apply_decoder_hardening().
[[nodiscard]] auto decoder_platform_sandbox_available() noexcept -> bool;

// True for ASan/TSan/MSan builds, which skip RLIMIT_AS and the seccomp
// filter: the sanitizer runtime reserves a large virtual address space for
// shadow memory (incompatible with a tight RLIMIT_AS) and needs syscalls the
// decoder seccomp profile denies. Never true in a production build. Exposed
// so apply_decoder_hardening() and callers agree on which steps apply
// without duplicating the detection macros.
[[nodiscard]] auto decoder_hardening_is_sanitizer_build() noexcept -> bool;

// The resource limit that caps the decoder's memory, and how a failure to set
// it is named in DecoderHardeningResult::failed_control. RLIMIT_AS where the
// platform defines it; OpenBSD has no RLIMIT_AS, so there it is RLIMIT_DATA,
// which on OpenBSD also bounds anonymous mmap (how its malloc allocates).
[[nodiscard]] auto decoder_memory_limit_resource() noexcept -> int;
[[nodiscard]] auto decoder_memory_limit_name() noexcept -> std::string_view;

// Applies the fail-closed hardening sequence the sandboxed thumbnail decoder
// worker must complete before it reads any input: self-imposed resource
// limits (address space, CPU, file size, core dumps, open files), then the
// platform sandbox — Linux seccomp-bpf decoder profile, OpenBSD
// pledge("stdio"), FreeBSD cap_enter(). A platform with no in-process
// primitive (NetBSD) is refused before anything is applied, with
// failed_control "no platform decoder sandbox": resource limits alone do not
// stop a decoder exploit reading the server's secrets, so the worker decodes
// nothing there (docs/hardening.md, ADR-0419).
//
// Every control that applies on this platform must succeed, or the sequence
// stops at the first failure and returns a rejected result naming it.
// Callers MUST NOT read stdin or decode anything when the result is
// rejected — see thumbnail_worker_main.cpp::main().
[[nodiscard]] auto apply_decoder_hardening(DecoderHardeningOps const& ops = DecoderHardeningOps{})
    -> DecoderHardeningResult;

} // namespace merovingian::media
