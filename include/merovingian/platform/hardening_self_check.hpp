// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/platform/elf_probe.hpp"
#include "merovingian/platform/seccomp_hardening.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace merovingian::platform
{

enum class HardeningStatus : std::uint8_t
{
    enabled,
    disabled,
    unknown,
};

struct HardeningCheck final
{
    std::string name{};
    HardeningStatus status{HardeningStatus::unknown};
    std::string note{};
};

class HardeningSelfCheck final
{
public:
    HardeningSelfCheck() = default;
    explicit HardeningSelfCheck(std::vector<HardeningCheck> checks);

    [[nodiscard]] auto checks() const noexcept -> std::vector<HardeningCheck> const&;
    [[nodiscard]] auto count() const noexcept -> std::size_t;
    [[nodiscard]] auto production_blockers() const -> std::vector<HardeningCheck>;
    [[nodiscard]] auto production_blocker_count() const noexcept -> std::size_t;
    [[nodiscard]] auto is_ready() const noexcept -> bool;

private:
    std::vector<HardeningCheck> m_checks{};
};

[[nodiscard]] auto run_startup_hardening_self_check() -> HardeningSelfCheck;
[[nodiscard]] auto hardening_status_name(HardeningStatus status) noexcept -> char const*;

// Map ELF probe results to individual hardening checks. Exposed for testing.
// Returns `enabled` when the probe confirmed the flag; `unknown` otherwise
// (probe could not run, binary is statically linked, or flag is absent).
// Never returns `disabled` — ELF flags are baked in at link time and cannot
// be changed at runtime, so absence is indistinguishable from an intentional
// static-binary build.
[[nodiscard]] auto linker_hardening_check_from_probe(ElfHardeningResult const& result) -> HardeningCheck;
[[nodiscard]] auto relro_check_from_probe(ElfHardeningResult const& result) -> HardeningCheck;

// Maps a SeccompProbeResult to a HardeningCheck:
//   enabled — probe ran and confirmed SECCOMP_MODE_FILTER is active.
//   unknown — probe could not confirm (filter not applied, probe failed, non-Linux).
// Never returns `disabled` — absence of the filter is indistinguishable from
// a kernel that does not support CONFIG_SECCOMP_FILTER at probe time.
// `HardeningStatus::alpha_exception` no longer exists; the server refuses to
// start unless every hardening check reports `enabled`.
[[nodiscard]] auto seccomp_check_from_probe(SeccompProbeResult const& result) -> HardeningCheck;

} // namespace merovingian::platform
