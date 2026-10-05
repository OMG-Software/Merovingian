// SPDX-License-Identifier: GPL-3.0-or-later

// Finding N1 part 3 (ADR-0062): the federation worker restricts its own
// filesystem access with Linux Landlock before handling any untrusted input,
// so a compromise reached through a memory-safety bug cannot open the
// operator master key, TLS private keys, or either database URI file
// directly off disk. See
// docs/adr/0062-federation-worker-holds-no-secret-files-secrets-arrive-over-inherited-fds.md,
// part 3.

#include "merovingian/config/config.hpp"
#include "merovingian/config/config_parser.hpp"
#include "merovingian/config/reload_plan.hpp"
#include "merovingian/config/reload_policy.hpp"
#include "merovingian/core/file_descriptor.hpp"
#include "merovingian/platform/landlock_hardening.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>
#include <tuple>
#include <vector>

#ifdef __linux__
#include <fcntl.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#include "../support/temp_directory.hpp"

namespace
{

using merovingian::platform::LandlockAccess;
using merovingian::platform::LandlockAddRuleOutcome;
using merovingian::platform::LandlockHardeningOps;
using merovingian::platform::LandlockPathRule;

// Builds an ops table that reports Landlock as unavailable (ABI < 1), the
// way ENOSYS (kernel < 5.13) or EOPNOTSUPP (Landlock disabled at boot) would.
[[nodiscard]] auto unavailable_ops() -> LandlockHardeningOps
{
    auto ops = LandlockHardeningOps{};
    ops.query_abi_version = []() -> int {
        return -1;
    };
    // Never reached when the ABI query itself reports unavailable, but wired
    // to fail loudly if apply_worker_landlock's control flow regresses and
    // calls it anyway.
    ops.create_ruleset = [](std::uint64_t, int) -> int {
        return -1;
    };
    ops.add_rule = [](int, std::string const&, std::uint64_t) -> LandlockAddRuleOutcome {
        return LandlockAddRuleOutcome::failed;
    };
    ops.set_no_new_privs = []() -> bool {
        return false;
    };
    ops.restrict_self = [](int) -> bool {
        return false;
    };
    return ops;
}

// Builds an ops table that reports Landlock as available at the given ABI
// and records every call made against it, so a test can assert on exactly
// which paths and rights were requested.
struct RecordingOps final
{
    int abi{k_recorded_default_abi};
    bool create_ruleset_fails{false};
    bool restrict_self_fails{false};
    bool set_no_new_privs_fails{false};
    // Path -> outcome overrides for add_rule; anything absent succeeds.
    std::vector<std::pair<std::string, LandlockAddRuleOutcome>> add_rule_overrides{};

    std::uint64_t handled_access_fs_requested{0U};
    std::vector<std::tuple<std::string, std::uint64_t>> add_rule_calls{};
    bool restrict_self_called{false};
    // Order of the no_new_privs / restrict_self calls, to assert that
    // no_new_privs is always set first (the kernel requires it).
    std::vector<std::string> privilege_calls{};

    static constexpr int k_recorded_default_abi = 3;

    [[nodiscard]] auto build() -> LandlockHardeningOps
    {
        auto ops = LandlockHardeningOps{};
        ops.query_abi_version = [this]() -> int {
            return abi;
        };
        ops.create_ruleset = [this](std::uint64_t handled_access_fs, int ruleset_abi) -> int {
            handled_access_fs_requested = handled_access_fs;
            std::ignore = ruleset_abi;
            return create_ruleset_fails ? -1 : 42;
        };
        ops.add_rule = [this](int, std::string const& path, std::uint64_t allowed_access) -> LandlockAddRuleOutcome {
            add_rule_calls.emplace_back(path, allowed_access);
            for (auto const& [override_path, outcome] : add_rule_overrides)
            {
                if (override_path == path)
                {
                    return outcome;
                }
            }
            return LandlockAddRuleOutcome::success;
        };
        ops.set_no_new_privs = [this]() -> bool {
            privilege_calls.emplace_back("set_no_new_privs");
            return !set_no_new_privs_fails;
        };
        ops.restrict_self = [this](int) -> bool {
            restrict_self_called = true;
            privilege_calls.emplace_back("restrict_self");
            return !restrict_self_fails;
        };
        return ops;
    }
};

} // namespace

// ============================================================================
// A. apply_worker_landlock — fail-closed paths, injected ops
// ============================================================================

SCENARIO("Landlock unavailable and no opt-out refuses to start", "[platform][worker_landlock]")
{
    GIVEN("Landlock reports unavailable and allow_without_landlock is false")
    {
        auto const ops = unavailable_ops();

        WHEN("the worker attempts to apply its Landlock ruleset")
        {
            auto const result = merovingian::platform::apply_worker_landlock({}, /*allow_without_landlock=*/false, ops);

            THEN("the result is rejected, not applied, and not just a warning")
            {
                REQUIRE_FALSE(result.accepted);
                REQUIRE_FALSE(result.applied);
                REQUIRE_FALSE(result.critical_warning);
                REQUIRE_FALSE(result.reason.empty());
            }
        }
    }
}

#ifndef __linux__
// Off Linux there is no Landlock at all: the worker is refused unless the
// operator opted out, and even an ops table that claims a capable kernel is
// never consulted (it is a Linux-only control; see docs/hardening.md).
SCENARIO("Off Linux the worker has no Landlock and never consults the ops", "[platform][worker_landlock]")
{
    GIVEN("ops that would report a capable kernel and succeed at every step")
    {
        auto recording = RecordingOps{};
        auto const ops = recording.build();

        WHEN("the worker applies its ruleset without the opt-out")
        {
            auto const result = merovingian::platform::apply_worker_landlock({}, /*allow_without_landlock=*/false, ops);

            THEN("it is refused, and no ruleset was attempted")
            {
                REQUIRE_FALSE(result.accepted);
                REQUIRE_FALSE(result.applied);
                REQUIRE(recording.handled_access_fs_requested == 0U);
                REQUIRE(recording.privilege_calls.empty());
            }
        }

        WHEN("the worker applies its ruleset with the opt-out")
        {
            auto const result = merovingian::platform::apply_worker_landlock({}, /*allow_without_landlock=*/true, ops);

            THEN("it proceeds unsandboxed with a critical warning, and no ruleset was attempted")
            {
                REQUIRE(result.accepted);
                REQUIRE_FALSE(result.applied);
                REQUIRE(result.critical_warning);
                REQUIRE(recording.handled_access_fs_requested == 0U);
                REQUIRE(recording.privilege_calls.empty());
            }
        }
    }
}
#endif // !__linux__

SCENARIO("Landlock unavailable with the opt-out accepts but warns critically", "[platform][worker_landlock]")
{
    GIVEN("Landlock reports unavailable and allow_without_landlock is true")
    {
        auto const ops = unavailable_ops();

        WHEN("the worker attempts to apply its Landlock ruleset")
        {
            auto const result = merovingian::platform::apply_worker_landlock({}, /*allow_without_landlock=*/true, ops);

            THEN("the worker may proceed, but without a sandbox and with a critical indicator")
            {
                REQUIRE(result.accepted);
                REQUIRE_FALSE(result.applied);
                REQUIRE(result.critical_warning);
                REQUIRE_FALSE(result.reason.empty());
            }
        }
    }
}

// The scenarios below script a Linux kernel's answers through the injected
// ops. Off Linux there is no Landlock and apply_worker_landlock never consults
// the ops, so they are Linux-only; the off-Linux contract has its own scenario.
#ifdef __linux__
SCENARIO("A Landlock ruleset-create failure is fatal even with the opt-out", "[platform][worker_landlock]")
{
    GIVEN("Landlock reports available but landlock_create_ruleset() fails")
    {
        auto recording = RecordingOps{};
        recording.create_ruleset_fails = true;
        auto const ops = recording.build();

        WHEN("the worker attempts to apply its Landlock ruleset with the opt-out set")
        {
            auto const result = merovingian::platform::apply_worker_landlock({}, /*allow_without_landlock=*/true, ops);

            THEN("the result is rejected regardless of the opt-out")
            {
                REQUIRE_FALSE(result.accepted);
                REQUIRE_FALSE(result.applied);
                REQUIRE_FALSE(result.critical_warning);
            }
        }
    }
}

SCENARIO("A Landlock add_rule failure on a required path is fatal even with the opt-out", "[platform][worker_landlock]")
{
    GIVEN("Landlock is available but a required rule fails to add")
    {
        auto recording = RecordingOps{};
        recording.add_rule_overrides.push_back({"/var/lib/merovingian", LandlockAddRuleOutcome::failed});
        auto const ops = recording.build();
        auto const rules = std::vector<LandlockPathRule>{
            {.path = "/var/lib/merovingian", .access = LandlockAccess::read_write, .required = true}
        };

        WHEN("the worker attempts to apply its Landlock ruleset with the opt-out set")
        {
            auto const result =
                merovingian::platform::apply_worker_landlock(rules, /*allow_without_landlock=*/true, ops);

            THEN("the result is rejected regardless of the opt-out")
            {
                REQUIRE_FALSE(result.accepted);
                REQUIRE_FALSE(result.applied);
            }
        }
    }
}

SCENARIO("A missing required path is fatal, but a missing best-effort path is skipped", "[platform][worker_landlock]")
{
    GIVEN("one required rule and one best-effort rule, both reporting path_unavailable")
    {
        auto recording = RecordingOps{};
        recording.add_rule_overrides.push_back(
            {"/etc/optional-does-not-exist", LandlockAddRuleOutcome::path_unavailable});
        auto const ops_best_effort_only = recording.build();

        WHEN("only the best-effort rule is missing")
        {
            auto const rules = std::vector<LandlockPathRule>{
                {.path = "/etc/optional-does-not-exist", .access = LandlockAccess::read_only, .required = false}
            };
            auto const result = merovingian::platform::apply_worker_landlock(rules, /*allow_without_landlock=*/false,
                                                                             ops_best_effort_only);

            THEN("the ruleset is still applied successfully")
            {
                REQUIRE(result.accepted);
                REQUIRE(result.applied);
            }
        }

        WHEN("the same missing path is instead required")
        {
            auto recording_required = RecordingOps{};
            recording_required.add_rule_overrides.push_back(
                {"/etc/optional-does-not-exist", LandlockAddRuleOutcome::path_unavailable});
            auto const ops_required = recording_required.build();
            auto const rules = std::vector<LandlockPathRule>{
                {.path = "/etc/optional-does-not-exist", .access = LandlockAccess::read_only, .required = true}
            };
            auto const result =
                merovingian::platform::apply_worker_landlock(rules, /*allow_without_landlock=*/true, ops_required);

            THEN("it is fatal regardless of the opt-out")
            {
                REQUIRE_FALSE(result.accepted);
            }
        }
    }
}

SCENARIO("A landlock_restrict_self failure is fatal even with the opt-out", "[platform][worker_landlock]")
{
    GIVEN("Landlock is available and every rule adds cleanly, but restrict_self fails")
    {
        auto recording = RecordingOps{};
        recording.restrict_self_fails = true;
        auto const ops = recording.build();

        WHEN("the worker attempts to apply its Landlock ruleset with the opt-out set")
        {
            auto const result = merovingian::platform::apply_worker_landlock({}, /*allow_without_landlock=*/true, ops);

            THEN("the result is rejected regardless of the opt-out")
            {
                REQUIRE_FALSE(result.accepted);
                REQUIRE_FALSE(result.applied);
                REQUIRE(recording.restrict_self_called);
            }
        }
    }
}

SCENARIO("A successful Landlock ruleset contains exactly the expected rules, never the worker's secrets",
         "[platform][worker_landlock]")
{
    GIVEN("a worker config with a master key, TLS keys, and both database URI files set")
    {
        auto config = merovingian::config::Config{};
        config.database().backend = merovingian::config::DatabaseBackend::sqlite;
        config.database().sqlite_path = "/var/lib/merovingian/merovingian.sqlite3";
        config.database().uri_file = "/etc/merovingian/db-uri";
        config.security().secrets.master_key_file = "/etc/merovingian/master.key";
        config.listeners().client.tls_certificate_file = "/etc/merovingian/tls/client.crt";
        config.listeners().client.tls_private_key_file = "/etc/merovingian/tls/client.key";
        config.listeners().federation.tls_certificate_file = "/etc/merovingian/tls/federation.crt";
        config.listeners().federation.tls_private_key_file = "/etc/merovingian/tls/federation.key";
        config.federation_worker().database_uri_file = "/etc/merovingian/fed-worker-db-uri";

        WHEN("the worker's Landlock rules are built and applied")
        {
            auto const rules = merovingian::platform::build_worker_landlock_rules(config);
            auto recording = RecordingOps{};
            auto const ops = recording.build();
            auto const result =
                merovingian::platform::apply_worker_landlock(rules, /*allow_without_landlock=*/false, ops);

            THEN("the ruleset is applied and every rule was added")
            {
                REQUIRE(result.accepted);
                REQUIRE(result.applied);
                REQUIRE(recording.add_rule_calls.size() == rules.size());
                REQUIRE(recording.restrict_self_called);
            }

            AND_THEN("the SQLite database directory is granted read-write")
            {
                auto const it = std::find_if(rules.begin(), rules.end(), [](LandlockPathRule const& rule) {
                    return rule.path == "/var/lib/merovingian";
                });
                REQUIRE(it != rules.end());
                REQUIRE(it->access == LandlockAccess::read_write);
                REQUIRE(it->required);
            }

            AND_THEN("none of the worker's secret file paths appear anywhere in the ruleset")
            {
                auto const contains_path = [&rules](std::string const& secret_path) {
                    return std::any_of(rules.begin(), rules.end(), [&secret_path](LandlockPathRule const& rule) {
                        return rule.path == secret_path;
                    });
                };
                REQUIRE_FALSE(contains_path(config.security().secrets.master_key_file));
                REQUIRE_FALSE(contains_path(config.database().uri_file));
                REQUIRE_FALSE(contains_path(config.federation_worker().database_uri_file));
                REQUIRE_FALSE(contains_path(config.listeners().client.tls_certificate_file));
                REQUIRE_FALSE(contains_path(config.listeners().client.tls_private_key_file));
                REQUIRE_FALSE(contains_path(config.listeners().federation.tls_certificate_file));
                REQUIRE_FALSE(contains_path(config.listeners().federation.tls_private_key_file));
            }
        }
    }
}

#endif // __linux__

SCENARIO("A PostgreSQL-backed worker requests no database directory rule", "[platform][worker_landlock]")
{
    GIVEN("a worker config with database.backend=postgresql")
    {
        auto config = merovingian::config::Config{};
        config.database().backend = merovingian::config::DatabaseBackend::postgresql;

        WHEN("the worker's Landlock rules are built")
        {
            auto const rules = merovingian::platform::build_worker_landlock_rules(config);

            THEN("no rule names the SQLite path -- PostgreSQL is reached over a socket, unaffected by Landlock")
            {
                REQUIRE(std::none_of(rules.begin(), rules.end(), [](LandlockPathRule const& rule) {
                    return rule.path.find("merovingian.sqlite3") != std::string::npos;
                }));
            }
        }
    }
}

SCENARIO("The Landlock rights mask is downgraded to what the reported ABI version supports",
         "[platform][worker_landlock]")
{
    GIVEN("ABI 1 (Linux 5.13, the earliest Landlock version)")
    {
        WHEN("the handled access-fs mask is built")
        {
            auto const abi1_mask = merovingian::platform::landlock_handled_access_fs(1);
            auto const abi2_mask = merovingian::platform::landlock_handled_access_fs(2);
            auto const abi3_mask = merovingian::platform::landlock_handled_access_fs(3);

            THEN("each higher ABI's mask is a strict superset of the one below it")
            {
                REQUIRE((abi1_mask & abi2_mask) == abi1_mask);
                REQUIRE((abi2_mask & abi3_mask) == abi2_mask);
                REQUIRE(abi1_mask != abi2_mask);
                REQUIRE(abi2_mask != abi3_mask);
            }
        }

        WHEN("the read-write access mask is built for each ABI")
        {
            auto const abi1_rw = merovingian::platform::landlock_read_write_access(1);
            auto const abi3_rw = merovingian::platform::landlock_read_write_access(3);

            THEN("ABI 3 additionally carries the TRUNCATE right that ABI 1 cannot request")
            {
                // TRUNCATE is bit 14 (1ULL << 14); ABI 1 predates it (added in
                // Linux 6.2 / ABI 3) and must never set it, since requesting a
                // right the reported ABI does not support fails
                // landlock_create_ruleset()/landlock_add_rule() outright rather
                // than degrading gracefully.
                constexpr auto truncate_bit = std::uint64_t{1ULL << 14U};
                REQUIRE((abi1_rw & truncate_bit) == 0U);
                REQUIRE((abi3_rw & truncate_bit) != 0U);
            }
        }
    }
}

SCENARIO("Landlock read-only access never grants write or create rights", "[platform][worker_landlock]")
{
    GIVEN("the read-only access mask")
    {
        WHEN("it is compared against the read-write mask")
        {
            auto const read_only = merovingian::platform::landlock_read_only_access(3);
            auto const read_write = merovingian::platform::landlock_read_write_access(3);

            THEN("read-only is a strict subset of read-write, and excludes WRITE_FILE")
            {
                constexpr auto write_file_bit = std::uint64_t{1ULL << 1U};
                REQUIRE((read_only & read_write) == read_only);
                REQUIRE(read_only != read_write);
                REQUIRE((read_only & write_file_bit) == 0U);
            }
        }

        WHEN("read-execute is compared against read-only")
        {
            auto const read_only = merovingian::platform::landlock_read_only_access(3);
            auto const read_execute = merovingian::platform::landlock_read_execute_access(3);

            THEN("read-execute grants exactly read-only plus EXECUTE")
            {
                constexpr auto execute_bit = std::uint64_t{1ULL << 0U};
                REQUIRE(read_execute == (read_only | execute_bit));
            }
        }
    }
}

// ============================================================================
// B. Config: parsing, validation, reload classification
// ============================================================================

SCENARIO("federation.worker.allow_without_landlock is parsed from key-value config",
         "[config][worker_landlock][parser]")
{
    GIVEN("key-value configuration enabling the opt-out")
    {
        auto const input = std::string{"federation.worker.allow_without_landlock=true\n"};

        WHEN("the config is parsed")
        {
            auto const result = merovingian::config::parse_key_value_config(input);

            THEN("the flag is applied and no findings are reported")
            {
                REQUIRE(result.config.federation_worker().allow_without_landlock);
                REQUIRE(result.findings.empty());
            }
        }
    }
}

SCENARIO("federation.worker.allow_without_landlock defaults to false", "[config][worker_landlock][parser]")
{
    GIVEN("an empty key-value configuration")
    {
        WHEN("the config is parsed")
        {
            auto const result = merovingian::config::parse_key_value_config("");

            THEN("the worker does not opt out of Landlock by default")
            {
                REQUIRE_FALSE(result.config.federation_worker().allow_without_landlock);
            }
        }
    }
}

SCENARIO("federation.worker.allow_without_landlock rejects a non-boolean value", "[config][worker_landlock][parser]")
{
    GIVEN("key-value configuration with a malformed boolean")
    {
        auto const input = std::string{"federation.worker.allow_without_landlock=maybe\n"};

        WHEN("the config is parsed")
        {
            auto const result = merovingian::config::parse_key_value_config(input);

            THEN("a finding names the offending key")
            {
                auto found = false;
                for (auto const& finding : result.findings)
                {
                    found = found || finding.field == "federation.worker.allow_without_landlock";
                }
                REQUIRE(found);
            }
        }
    }
}

SCENARIO("federation.worker.allow_without_landlock requires a restart to take effect",
         "[config][worker_landlock][reload]")
{
    GIVEN("the key's reload policy")
    {
        WHEN("it is looked up")
        {
            auto const policy = merovingian::config::reload_policy_for_key("federation.worker.allow_without_landlock");

            THEN("it is restart_required, like every other federation.worker.* key")
            {
                // Landlock is applied once at worker process startup, before
                // the event loop starts; SIGHUP cannot re-apply an
                // irreversible ruleset to an already-running worker.
                REQUIRE(policy == merovingian::config::ReloadPolicy::restart_required);
            }
        }
    }
}

SCENARIO("A live edit to federation.worker.allow_without_landlock appears in the reload plan",
         "[config][worker_landlock][reload]")
{
    GIVEN("two configs differing only in the Landlock opt-out")
    {
        auto current = merovingian::config::Config{};
        auto next = merovingian::config::Config{};
        next.federation_worker().allow_without_landlock = true;

        WHEN("a reload plan is built between them")
        {
            auto const plan = merovingian::config::build_reload_plan(current, next);

            THEN("the change is reported as restart_required, not silently dropped")
            {
                auto found = false;
                for (auto const& change : plan.changes())
                {
                    if (change.key == "federation.worker.allow_without_landlock")
                    {
                        found = true;
                        REQUIRE(change.policy == merovingian::config::ReloadPolicy::restart_required);
                    }
                }
                REQUIRE(found);
            }
        }
    }
}

// ============================================================================
// C. Real-kernel enforcement, forked so the test binary itself is never
//    restricted (Landlock is irreversible for the lifetime of the process
//    that calls landlock_restrict_self) -- mirrors the fork pattern in
//    tests/integration/test_seccomp_sqlite_flow.cpp and the NetBSD
//    libsodium-fd fork fix.
// ============================================================================

#ifdef __linux__
SCENARIO("A real Landlock ruleset denies access outside its allowlist and permits access inside it",
         "[platform][worker_landlock][linux]")
{
    GIVEN("an allowed directory and a separate, unrelated directory holding a secret file")
    {
        auto const base = merovingian::tests::temporary_directory() / "merovingian-landlock-test";
        auto const allowed_dir = base / "allowed";
        auto const denied_dir = base / "denied";
        std::filesystem::create_directories(allowed_dir);
        std::filesystem::create_directories(denied_dir);

        auto const allowed_file = allowed_dir / "allowed.txt";
        auto const denied_file = denied_dir / "secret.txt";
        {
            auto out = std::ofstream{allowed_file};
            out << "not secret";
        }
        {
            auto out = std::ofstream{denied_file};
            out << "secret";
        }

        WHEN("a forked child restricts itself to only the allowed directory and probes both files")
        {
            int pipe_fds[2] = {-1, -1};
            REQUIRE(::pipe(pipe_fds) == 0);

            auto const pid = ::fork();
            REQUIRE(pid >= 0);

            if (pid == 0)
            {
                ::close(pipe_fds[0]);

                auto const rules = std::vector<LandlockPathRule>{
                    {.path = allowed_dir.string(), .access = LandlockAccess::read_only, .required = true}
                };
                auto const result = merovingian::platform::apply_worker_landlock(rules,
                                                                                 /*allow_without_landlock=*/false);

                if (!result.accepted)
                {
                    // Skip ONLY when the kernel genuinely has no Landlock ABI.
                    // Any other refusal (e.g. restrict_self EPERM) is a real
                    // failure: treating every refusal as "unavailable" is what
                    // let the missing no_new_privs step pass as a skip.
                    auto const abi = merovingian::platform::LandlockHardeningOps{}.query_abi_version();
                    auto const msg = abi < 1
                                         ? std::string{"SKIP:"} + result.reason
                                         : std::string{"FAIL:refused on a Landlock-capable kernel: "} + result.reason;
                    std::ignore = ::write(pipe_fds[1], msg.data(), msg.size());
                    ::close(pipe_fds[1]);
                    ::_exit(0);
                }

                auto const allowed_fd = ::open(allowed_file.c_str(), O_RDONLY); // NOLINT(*-vararg)
                auto const allowed_ok = allowed_fd >= 0;
                if (allowed_fd >= 0)
                {
                    ::close(allowed_fd);
                }

                errno = 0;
                auto const denied_fd = ::open(denied_file.c_str(), O_RDONLY); // NOLINT(*-vararg)
                auto const denied_blocked = denied_fd < 0 && errno == EACCES;
                if (denied_fd >= 0)
                {
                    ::close(denied_fd);
                }

                auto const msg = (allowed_ok && denied_blocked)
                                     ? std::string{"OK"}
                                     : std::string{"FAIL:allowed_ok="} + (allowed_ok ? "1" : "0") +
                                           " denied_blocked=" + (denied_blocked ? "1" : "0");
                std::ignore = ::write(pipe_fds[1], msg.data(), msg.size());
                ::close(pipe_fds[1]);
                ::_exit(0);
            }

            ::close(pipe_fds[1]);
            auto report = std::string{};
            char buf[256];
            for (auto r = ::read(pipe_fds[0], buf, sizeof(buf)); r > 0; r = ::read(pipe_fds[0], buf, sizeof(buf)))
            {
                report.append(buf, static_cast<std::size_t>(r));
            }
            ::close(pipe_fds[0]);
            auto status = int{};
            ::waitpid(pid, &status, 0);

            auto ec = std::error_code{};
            std::filesystem::remove_all(base, ec);

            THEN("the denied path is refused and the allowed path succeeds -- or the scenario is skipped when this "
                 "kernel has no Landlock support")
            {
                REQUIRE(WIFEXITED(status));
                REQUIRE(WEXITSTATUS(status) == 0);

                if (report.starts_with("SKIP:"))
                {
                    auto const skip_message = "Landlock is unavailable on this kernel: " + report.substr(5);
                    SKIP(skip_message);
                }
                else
                {
                    INFO("child report: " << report);
                    REQUIRE(report == "OK");
                }
            }
        }
    }
}
#endif // __linux__

// Regression (0.12.13 integration failure): read-only access is
// READ_FILE | READ_DIR, but the kernel rejects a path-beneath rule on a
// non-directory with EINVAL unless its access is a subset of the file-level
// rights. Every allowlisted regular file (e.g. /etc/resolv.conf) therefore
// failed, and the worker — correctly failing closed — refused to start.
SCENARIO("Landlock rights are trimmed to file-level access for non-directories",
         "[platform][security][worker_landlock]")
{
    GIVEN("the read-only and read-write access masks for the current ABI")
    {
        auto constexpr abi = 3;
        auto const read_only = merovingian::platform::landlock_read_only_access(abi);
        auto const read_write = merovingian::platform::landlock_read_write_access(abi);

        WHEN("the rule targets a directory")
        {
            THEN("the requested access is kept unchanged")
            {
                REQUIRE(merovingian::platform::landlock_access_for_inode(read_only, true) == read_only);
                REQUIRE(merovingian::platform::landlock_access_for_inode(read_write, true) == read_write);
            }
        }

        WHEN("the rule targets a regular file")
        {
            auto const file_read_only = merovingian::platform::landlock_access_for_inode(read_only, false);
            auto const file_read_write = merovingian::platform::landlock_access_for_inode(read_write, false);

            THEN("directory-only rights are removed and file rights remain")
            {
                REQUIRE(file_read_only != 0U);
                REQUIRE((file_read_only & ~read_only) == 0U);
                REQUIRE(file_read_only != read_only);
                REQUIRE((file_read_write & ~read_write) == 0U);
                REQUIRE(file_read_write != read_write);
            }

            THEN("trimming is idempotent, so a file rule can never grant directory rights")
            {
                REQUIRE(merovingian::platform::landlock_access_for_inode(file_read_only, false) == file_read_only);
            }
        }
    }
}

#if defined(__linux__)
SCENARIO("A Landlock rule for a regular file is accepted by the running kernel",
         "[platform][security][worker_landlock]")
{
    GIVEN("a real Landlock ruleset (creating and filling one does not sandbox this process)")
    {
        auto const ops = merovingian::platform::LandlockHardeningOps{};
        auto const abi = ops.query_abi_version();
        if (abi < 1)
        {
            SKIP("kernel has no Landlock support (ABI " << abi << ")");
        }
        auto const ruleset_fd = merovingian::core::FileDescriptor{
            ops.create_ruleset(merovingian::platform::landlock_handled_access_fs(abi), abi)};
        REQUIRE(ruleset_fd.valid());

        auto const dir = merovingian::tests::temporary_directory() /
                         ("merovingian-landlock-file-rule-" + std::to_string(::getpid()));
        std::filesystem::create_directories(dir);
        auto const file_path = (dir / "regular-file").string();
        std::ofstream{file_path} << "x";

        WHEN("read-only access is requested for a regular file and for its directory")
        {
            auto const read_only = merovingian::platform::landlock_read_only_access(abi);
            auto const file_outcome = ops.add_rule(ruleset_fd.get(), file_path, read_only);
            auto const dir_outcome = ops.add_rule(ruleset_fd.get(), dir.string(), read_only);
            std::ignore = std::filesystem::remove_all(dir);

            THEN("both rules are added")
            {
                REQUIRE(file_outcome == LandlockAddRuleOutcome::success);
                REQUIRE(dir_outcome == LandlockAddRuleOutcome::success);
            }
        }
    }
}
#endif // __linux__

#ifdef __linux__
// Regression (0.12.13 integration failure): landlock_restrict_self() returns
// EPERM unless the caller has no_new_privs set or CAP_SYS_ADMIN. The worker
// applied Landlock before its seccomp step set PR_SET_NO_NEW_PRIVS, so an
// unprivileged worker could never restrict itself and refused to start.
SCENARIO("no_new_privs is set before Landlock restricts the worker", "[platform][security][worker_landlock]")
{
    GIVEN("Landlock is available")
    {
        auto recording = RecordingOps{};
        auto const ops = recording.build();

        WHEN("the worker applies its ruleset")
        {
            auto const result = merovingian::platform::apply_worker_landlock({}, /*allow_without_landlock=*/false, ops);

            THEN("no_new_privs is set, then the ruleset is enforced")
            {
                REQUIRE(result.accepted);
                REQUIRE(result.applied);
                REQUIRE(recording.privilege_calls == std::vector<std::string>{"set_no_new_privs", "restrict_self"});
            }
        }
    }
}

SCENARIO("A failure to set no_new_privs is fatal even with the Landlock opt-out",
         "[platform][security][worker_landlock]")
{
    GIVEN("Landlock is available but PR_SET_NO_NEW_PRIVS fails")
    {
        auto recording = RecordingOps{};
        recording.set_no_new_privs_fails = true;
        auto const ops = recording.build();

        WHEN("the worker applies its ruleset with allow_without_landlock=true")
        {
            auto const result = merovingian::platform::apply_worker_landlock({}, /*allow_without_landlock=*/true, ops);

            THEN("the worker is refused and the ruleset is never enforced")
            {
                REQUIRE_FALSE(result.accepted);
                REQUIRE_FALSE(result.applied);
                REQUIRE_FALSE(recording.restrict_self_called);
                REQUIRE(result.reason.find("NO_NEW_PRIVS") != std::string::npos);
            }
        }
    }
}

SCENARIO("Landlock ABI 6 signal scope is requested when the kernel supports it",
         "[platform][security][worker_landlock][linux]")
{
    GIVEN("a Landlock ABI of 6 or newer")
    {
        auto const ops = merovingian::platform::LandlockHardeningOps{};
        auto const abi = ops.query_abi_version();
        if (abi < 6)
        {
            SKIP("kernel Landlock ABI " << abi << " is older than ABI 6");
        }

        WHEN("a ruleset is created for the worker")
        {
            auto const ruleset_fd = merovingian::core::FileDescriptor{
                ops.create_ruleset(merovingian::platform::landlock_handled_access_fs(abi), abi)};

            THEN("the ruleset is created successfully with signal scoping enabled")
            {
                REQUIRE(ruleset_fd.valid());
            }
        }
    }
}

#endif // __linux__

// ============================================================================
// Secret-exposure guard: no Landlock rule may cover a configured secret.
// A rule on a directory grants everything beneath it, so an exact-path check
// is not enough — e.g. the SQLite read-write grant on the database directory
// would silently expose a master key an operator placed beside the database.
// ============================================================================

SCENARIO("A Landlock rule on a directory holding a configured secret is detected",
         "[platform][security][worker_landlock]")
{
    GIVEN("an operator who put the master key next to the SQLite database")
    {
        auto config = merovingian::config::Config{};
        config.database().backend = merovingian::config::DatabaseBackend::sqlite;
        config.database().sqlite_path = "/srv/merovingian/merovingian.sqlite3";
        config.security().secrets.master_key_file = "/srv/merovingian/master.key";

        WHEN("the worker's rules are checked against its secret paths")
        {
            auto const rules = merovingian::platform::build_worker_landlock_rules(config);
            auto const exposure = merovingian::platform::find_landlock_rule_covering_secret(
                rules, merovingian::platform::worker_landlock_secret_paths(config));

            THEN("the exposure is reported, naming the rule and the secret")
            {
                REQUIRE(exposure.has_value());
                REQUIRE(exposure->rule_path == "/srv/merovingian");
                REQUIRE(exposure->secret_path == "/srv/merovingian/master.key");
            }
        }
    }
}

SCENARIO("The shipped secret layout is not covered by any worker Landlock rule",
         "[platform][security][worker_landlock]")
{
    GIVEN("secrets under /etc/merovingian and the database under /var/lib/merovingian")
    {
        auto config = merovingian::config::Config{};
        config.database().backend = merovingian::config::DatabaseBackend::sqlite;
        config.database().sqlite_path = "/var/lib/merovingian/merovingian.sqlite3";
        config.database().uri_file = "/etc/merovingian/db-uri";
        config.security().secrets.master_key_file = "/etc/merovingian/master-key";
        config.security().registration.token_file = "/etc/merovingian/registration-token";
        config.listeners().client.tls_private_key_file = "/etc/merovingian/client.key";
        config.listeners().federation.tls_private_key_file = "/etc/merovingian/federation.key";
        config.federation_worker().database_uri_file = "/etc/merovingian/fed-worker-db-uri";

        WHEN("the worker's rules are checked against its secret paths")
        {
            auto const rules = merovingian::platform::build_worker_landlock_rules(config);
            auto const secrets = merovingian::platform::worker_landlock_secret_paths(config);

            THEN("every configured secret is listed and none is covered")
            {
                REQUIRE(secrets.size() == 6U);
                REQUIRE_FALSE(merovingian::platform::find_landlock_rule_covering_secret(rules, secrets).has_value());
            }
        }
    }
}

SCENARIO("CA trust grants never cover the conventional private-key directories",
         "[platform][security][worker_landlock]")
{
    GIVEN("TLS private keys kept where Debian and RHEL conventionally put them")
    {
        auto const rules = merovingian::platform::build_worker_landlock_rules(merovingian::config::Config{});
        auto const keys = std::vector<std::string>{"/etc/ssl/private/server.key", "/etc/pki/tls/private/server.key"};

        WHEN("the worker's rules are checked against those key paths")
        {
            auto const exposure = merovingian::platform::find_landlock_rule_covering_secret(rules, keys);

            THEN("no rule covers them")
            {
                INFO("covering rule: " << (exposure ? exposure->rule_path : std::string{"none"}));
                REQUIRE_FALSE(exposure.has_value());
            }
        }
    }
}

SCENARIO("Rule coverage is decided by path component, not string prefix", "[platform][security][worker_landlock]")
{
    GIVEN("a rule on /etc/merov and a secret under /etc/merovingian")
    {
        auto const rules = std::vector<LandlockPathRule>{
            {.path = "/etc/merov", .access = LandlockAccess::read_only, .required = false}
        };

        WHEN("coverage is checked")
        {
            THEN("a sibling directory sharing a name prefix is not covered")
            {
                REQUIRE_FALSE(
                    merovingian::platform::find_landlock_rule_covering_secret(rules, {"/etc/merovingian/master-key"})
                        .has_value());
            }
            AND_THEN("the directory itself and anything beneath it are covered")
            {
                REQUIRE(merovingian::platform::find_landlock_rule_covering_secret(rules, {"/etc/merov"}).has_value());
                REQUIRE(merovingian::platform::find_landlock_rule_covering_secret(rules, {"/etc/merov/a/b.key"})
                            .has_value());
            }
        }
    }
}
