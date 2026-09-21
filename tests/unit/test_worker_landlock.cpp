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
    ops.create_ruleset = [](std::uint64_t) -> int {
        return -1;
    };
    ops.add_rule = [](int, std::string const&, std::uint64_t) -> LandlockAddRuleOutcome {
        return LandlockAddRuleOutcome::failed;
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
    // Path -> outcome overrides for add_rule; anything absent succeeds.
    std::vector<std::pair<std::string, LandlockAddRuleOutcome>> add_rule_overrides{};

    std::uint64_t handled_access_fs_requested{0U};
    std::vector<std::tuple<std::string, std::uint64_t>> add_rule_calls{};
    bool restrict_self_called{false};

    static constexpr int k_recorded_default_abi = 3;

    [[nodiscard]] auto build() -> LandlockHardeningOps
    {
        auto ops = LandlockHardeningOps{};
        ops.query_abi_version = [this]() -> int {
            return abi;
        };
        ops.create_ruleset = [this](std::uint64_t handled_access_fs) -> int {
            handled_access_fs_requested = handled_access_fs;
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
        ops.restrict_self = [this](int) -> bool {
            restrict_self_called = true;
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
                    // Landlock is unavailable on this kernel -- report SKIP so
                    // the parent can mark the scenario skipped rather than
                    // failed.
                    auto const msg = std::string{"SKIP:"} + result.reason;
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
