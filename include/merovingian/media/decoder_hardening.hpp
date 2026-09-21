// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <functional>
#include <string>

namespace merovingian::media
{

// Outcome of apply_decoder_hardening(). `accepted` is true only when every
// hardening control applicable on this platform succeeded (self-imposed
// resource limits everywhere, plus the platform sandbox: seccomp on Linux,
// pledge on OpenBSD, cap_enter on FreeBSD). When false, `failed_control`
// names the control that failed, so the caller can report why before
// refusing to read untrusted input — see thumbnail_worker_main.cpp::main().
struct DecoderHardeningResult final
{
    bool accepted{false};
    std::string failed_control{};
};

// The syscalls apply_decoder_hardening() drives, exposed as an injectable
// function table so its fail-closed sequencing is unit-testable without
// actually installing (or failing to install) a real seccomp filter, pledge
// promise set, or Capsicum capability mode in the calling process — doing
// that for real inside the unit-test binary would sandbox the test process
// itself. Default-constructs to the real platform calls (only the members
// applicable on the current platform are wired; the rest are left empty and
// are never invoked). Tests substitute individual members with safe stand-ins
// to simulate one control failing while the rest succeed.
struct DecoderHardeningOps final
{
    // setrlimit(resource, {value, value}); used for RLIMIT_AS, RLIMIT_CPU,
    // RLIMIT_FSIZE, RLIMIT_CORE, RLIMIT_NOFILE. Present on every platform.
    std::function<bool(int resource, std::uint64_t value)> set_resource_limit;
    // Linux only: prctl(PR_SET_DUMPABLE, 0, 0, 0, 0).
    std::function<bool()> disable_core_dumps;
    // Linux only: prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0).
    std::function<bool()> set_no_new_privs;
    // Linux only: merovingian::platform::apply_decoder_seccomp_filter().
    std::function<bool()> apply_seccomp_filter;
    // OpenBSD only: pledge("stdio", nullptr).
    std::function<bool()> apply_pledge;
    // FreeBSD only: cap_enter().
    std::function<bool()> apply_capsicum;

    DecoderHardeningOps();
};

// True for ASan/TSan/MSan builds, which skip RLIMIT_AS and the seccomp
// filter: the sanitizer runtime reserves a large virtual address space for
// shadow memory (incompatible with a tight RLIMIT_AS) and needs syscalls the
// decoder seccomp profile denies. Never true in a production build. Exposed
// so apply_decoder_hardening() and callers agree on which steps apply
// without duplicating the detection macros.
[[nodiscard]] auto decoder_hardening_is_sanitizer_build() noexcept -> bool;

// Applies the fail-closed hardening sequence the sandboxed thumbnail decoder
// worker must complete before it reads any input: self-imposed resource
// limits (address space, CPU, file size, core dumps, open files), then the
// platform sandbox — Linux seccomp-bpf decoder profile, OpenBSD
// pledge("stdio"), FreeBSD cap_enter(). Platforms with no further in-process
// primitive (e.g. NetBSD) apply the resource limits only; that gap is
// documented in docs/hardening.md.
//
// Every control that applies on this platform must succeed, or the sequence
// stops at the first failure and returns a rejected result naming it.
// Callers MUST NOT read stdin or decode anything when the result is
// rejected — see thumbnail_worker_main.cpp::main().
[[nodiscard]] auto apply_decoder_hardening(DecoderHardeningOps const& ops = DecoderHardeningOps{})
    -> DecoderHardeningResult;

} // namespace merovingian::media
