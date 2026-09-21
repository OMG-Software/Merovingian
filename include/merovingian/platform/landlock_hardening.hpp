// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace merovingian::config
{
class Config;
} // namespace merovingian::config

namespace merovingian::platform
{

// ADR-0062 part 3: the federation worker restricts its own filesystem access
// with Linux Landlock before handling any untrusted input, so that a
// compromise reached through a memory-safety bug (not merely one abusing an
// intentionally-opened file) cannot open the operator master key, TLS
// private keys, main's database URI file, or the worker's own database URI
// file directly off disk. See docs/adr/0062-...md and docs/hardening.md.

// The access class granted to one path in the worker's Landlock ruleset.
enum class LandlockAccess : std::uint8_t
{
    // READ_FILE (+ READ_DIR so directory listings and traversal succeed).
    read_only,
    // read_only rights plus EXECUTE, for shared-library directories the
    // dynamic linker / NSS / dlopen() need to map executable pages from.
    read_execute,
    // Full read/write/create/remove rights (never EXECUTE, never
    // MAKE_CHAR/MAKE_SOCK/MAKE_FIFO/MAKE_BLOCK). Used only for the SQLite
    // database directory.
    read_write,
};

// One path the worker's Landlock ruleset grants `access` on.
struct LandlockPathRule final
{
    std::string path;
    LandlockAccess access{LandlockAccess::read_only};
    // When true, failing to add this rule (including the path not existing
    // on this host) is always fatal — see apply_worker_landlock(). Set this
    // for paths the worker cannot function correctly without, such as a
    // config-derived database directory. Best-effort system-integration
    // paths whose presence varies by distribution (CA bundle candidates, NSS
    // configuration files, library directories) should be `false`: a missing
    // optional path is logged and skipped rather than refusing to start.
    bool required{true};
};

// Outcome of attempting to add one path rule to a Landlock ruleset.
enum class LandlockAddRuleOutcome : std::uint8_t
{
    success,
    // The path could not be opened (commonly: it does not exist on this
    // host). Fatal only when the owning LandlockPathRule::required is true.
    path_unavailable,
    // The path opened, but the landlock_add_rule() syscall itself failed.
    // Always fatal, independent of `required` — this indicates the ruleset
    // or kernel state is broken, not that the path is merely absent.
    failed,
};

// Result of apply_worker_landlock().
struct LandlockHardeningResult final
{
    // True when the worker may proceed: either the ruleset was applied, or
    // Landlock is unavailable on this kernel and the operator explicitly
    // opted out via federation.worker.allow_without_landlock=true.
    bool accepted{false};
    // True only when landlock_restrict_self() actually installed the
    // ruleset. False whenever `accepted` is true solely because of the
    // unavailable+opt-out path below.
    bool applied{false};
    // True when this start must be logged CRITICAL: Landlock is unavailable
    // and the operator opted out. The caller must log this on EVERY such
    // start, not just the first — mirroring ADR-0041's fail-closed seccomp
    // policy for the worker.
    bool critical_warning{false};
    std::string reason{};
};

// The three Landlock syscalls, plus the ABI-version probe, as an injectable
// function table — mirrors media::DecoderHardeningOps. Default-constructs to
// the real syscalls, issued via a raw ::syscall() rather than a libc wrapper
// (glibc did not gain landlock_create_ruleset()/landlock_add_rule()/
// landlock_restrict_self() wrappers until 2.38; the kernel/glibc pair this
// project builds and ships against must not be assumed to have them). Tests
// substitute individual members to exercise each fail-closed path without
// actually restricting the test process.
struct LandlockHardeningOps final
{
    // landlock_create_ruleset(nullptr, 0, LANDLOCK_CREATE_RULESET_VERSION).
    // Returns the ABI version (>= 1) when Landlock is available, or a value
    // < 1 when it is not (ENOSYS on kernels < 5.13, EOPNOTSUPP when Landlock
    // is disabled at boot, e.g. via the lsm= boot parameter).
    std::function<int()> query_abi_version;

    // landlock_create_ruleset(&attr, sizeof(attr), 0) with
    // attr.handled_access_fs = handled_access_fs. Returns the ruleset fd, or
    // a negative value on failure. Only called after query_abi_version() has
    // returned >= 1, so a negative return here is always a genuine error,
    // never "Landlock is unavailable".
    std::function<int(std::uint64_t handled_access_fs)> create_ruleset;

    // Opens `path` (O_PATH | O_CLOEXEC) and, on success, calls
    // landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH,
    // &{allowed_access, parent_fd}, 0), closing the opened path fd
    // afterwards regardless of outcome.
    std::function<LandlockAddRuleOutcome(int ruleset_fd, std::string const& path, std::uint64_t allowed_access)>
        add_rule;

    // prctl(PR_SET_NO_NEW_PRIVS, 1). landlock_restrict_self() fails with
    // EPERM unless no_new_privs is set (or the caller has CAP_SYS_ADMIN), so
    // this runs immediately before restrict_self; a failure is fatal.
    std::function<bool()> set_no_new_privs;

    // landlock_restrict_self(ruleset_fd, 0).
    std::function<bool(int ruleset_fd)> restrict_self;

    LandlockHardeningOps();
};

// Highest Landlock ABI version this build knows how to request rights for.
// A running kernel that reports a higher ABI is used at this capped level —
// forward compatible, never fails just because the kernel is newer than this
// build. A kernel that reports a lower ABI has its request masked down to
// exactly the rights that ABI version supports (see landlock_handled_access_fs).
inline constexpr int k_landlock_max_known_abi = 3;

// Rights masks, downgraded to whatever `abi` supports. `abi` must be >= 1.
// Dropping unsupported bits for an older-but-still-supported kernel is
// correct Landlock practice (see landlock(7), "Best-effort approach");
// refusing to run there is not — that is what the ABI < 1 "unavailable" path
// in apply_worker_landlock() is reserved for.
[[nodiscard]] auto landlock_handled_access_fs(int abi) noexcept -> std::uint64_t;
[[nodiscard]] auto landlock_read_only_access(int abi) noexcept -> std::uint64_t;
[[nodiscard]] auto landlock_read_execute_access(int abi) noexcept -> std::uint64_t;
[[nodiscard]] auto landlock_read_write_access(int abi) noexcept -> std::uint64_t;

// Returns `requested` restricted to what a path-beneath rule may grant on this
// inode. The kernel rejects (EINVAL) a rule on a non-directory whose access
// includes any directory-only right (READ_DIR, REMOVE_*, MAKE_*, REFER), so
// for a regular file only the file-level rights (EXECUTE, WRITE_FILE,
// READ_FILE, TRUNCATE) are kept. Directories keep `requested` unchanged.
[[nodiscard]] auto landlock_access_for_inode(std::uint64_t requested, bool is_directory) noexcept -> std::uint64_t;

// Builds the federation worker's path allowlist from its own config copy.
// Paths the config carries (the SQLite database directory) are read from
// `config`, never hard-coded; fixed OS-integration paths (CA trust store,
// resolver configuration, NSS/dynamic-linker library directories) are
// best-effort (LandlockPathRule::required = false). See
// docs/adr/0062-federation-worker-holds-no-secret-files-secrets-arrive-over-inherited-fds.md,
// part 3, "Allowlist derivation" for the strace evidence this list was
// derived from.
[[nodiscard]] auto build_worker_landlock_rules(config::Config const& config) -> std::vector<LandlockPathRule>;

// A Landlock rule that would grant the worker access to a configured secret.
struct LandlockSecretExposure final
{
    std::string rule_path;
    std::string secret_path;
};

// Every non-empty secret file path in `config` the worker must never be able
// to open: the master key, both TLS private keys, main's database URI file,
// the worker's own database URI file (delivered over an fd, never opened),
// and the registration token file.
[[nodiscard]] auto worker_landlock_secret_paths(config::Config const& config) -> std::vector<std::string>;

// Returns the first rule whose path is, or is an ancestor directory of, one
// of `secret_paths`, or std::nullopt when none is. A rule on a directory
// grants everything beneath it, so an exact-path comparison is not enough.
// Paths are compared by component after std::filesystem::weakly_canonical,
// so a symlink cannot hide an overlap and /etc/merov never covers
// /etc/merovingian.
[[nodiscard]] auto find_landlock_rule_covering_secret(std::vector<LandlockPathRule> const& rules,
                                                      std::vector<std::string> const& secret_paths)
    -> std::optional<LandlockSecretExposure>;

// Applies the Landlock filesystem restriction described by `rules`, or
// determines Landlock is unavailable and defers to `allow_without_landlock`:
//
//   * Landlock unavailable (ABI query < 1) + allow_without_landlock=false
//     -> rejected.
//   * Landlock unavailable + allow_without_landlock=true -> accepted,
//     applied=false, critical_warning=true. The caller MUST log CRITICAL on
//     every such start, not just the first.
//   * Any other Landlock failure (ruleset create, a required rule's
//     add_rule, or restrict_self) -> ALWAYS rejected, regardless of
//     allow_without_landlock — an operator opt-out covers "this kernel has
//     no Landlock", never "Landlock is present but broken".
//   * Success -> accepted=true, applied=true, critical_warning=false.
[[nodiscard]] auto apply_worker_landlock(std::vector<LandlockPathRule> const& rules, bool allow_without_landlock,
                                         LandlockHardeningOps const& ops = LandlockHardeningOps{})
    -> LandlockHardeningResult;

} // namespace merovingian::platform
