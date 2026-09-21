// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/media/decoder_hardening.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>

#include <sys/resource.h>

#if defined(__linux__)
#include <sys/prctl.h>
#endif

namespace
{

// Every member is a safe, side-effect-free stand-in: unlike the default-
// constructed merovingian::media::DecoderHardeningOps (which wires the real
// setrlimit/prctl/seccomp/pledge/cap_enter calls), none of these touches
// process state. That matters here specifically: a "succeeding" seccomp or
// pledge call is NOT a no-op — it really installs a fail-closed sandbox in
// the calling process, which is this test binary. Since every SCENARIO in
// this file shares one merovingian-unit-tests process, actually invoking the
// decoder's seccomp filter would kill that process on the next syscall a
// later test needs (sockets, file opens, ...). These scenarios therefore
// verify the fail-closed *sequencing and naming*, never the real syscalls
// themselves — that is covered by running the worker binary itself.
[[nodiscard]] auto all_succeeding_ops() -> merovingian::media::DecoderHardeningOps
{
    auto ops = merovingian::media::DecoderHardeningOps{};
    ops.set_resource_limit = [](int /*resource*/, std::uint64_t /*value*/) {
        return true;
    };
    ops.disable_core_dumps = [] {
        return true;
    };
    ops.set_no_new_privs = [] {
        return true;
    };
    ops.apply_seccomp_filter = [] {
        return true;
    };
    ops.apply_pledge = [] {
        return true;
    };
    ops.apply_capsicum = [] {
        return true;
    };
    return ops;
}

} // namespace

SCENARIO("decoder hardening accepts when every applicable control succeeds", "[media][thumbnail_hardening]")
{
    GIVEN("hardening ops where every control reports success")
    {
        auto const ops = all_succeeding_ops();

        WHEN("the decoder worker hardens")
        {
            auto const result = merovingian::media::apply_decoder_hardening(ops);

            THEN("hardening is accepted and no control is named as failed")
            {
                REQUIRE(result.accepted);
                REQUIRE(result.failed_control.empty());
            }
        }
    }
}

SCENARIO("decoder hardening fails closed when RLIMIT_AS cannot be set", "[media][thumbnail_hardening]")
{
    GIVEN("hardening ops where setrlimit fails only for RLIMIT_AS")
    {
        auto ops = all_succeeding_ops();
        ops.set_resource_limit = [](int resource, std::uint64_t /*value*/) {
            return resource != RLIMIT_AS;
        };

        WHEN("the decoder worker hardens")
        {
            auto const result = merovingian::media::apply_decoder_hardening(ops);

            THEN("hardening is not accepted and RLIMIT_AS is named as the failed control")
            {
                REQUIRE_FALSE(result.accepted);
                REQUIRE(result.failed_control == "setrlimit(RLIMIT_AS)");
            }
        }
    }
}

SCENARIO("decoder hardening fails closed when RLIMIT_CPU cannot be set", "[media][thumbnail_hardening]")
{
    GIVEN("hardening ops where setrlimit fails only for RLIMIT_CPU")
    {
        auto ops = all_succeeding_ops();
        ops.set_resource_limit = [](int resource, std::uint64_t /*value*/) {
            return resource != RLIMIT_CPU;
        };

        WHEN("the decoder worker hardens")
        {
            auto const result = merovingian::media::apply_decoder_hardening(ops);

            THEN("hardening is not accepted and RLIMIT_CPU is named as the failed control")
            {
                REQUIRE_FALSE(result.accepted);
                REQUIRE(result.failed_control == "setrlimit(RLIMIT_CPU)");
            }
        }
    }
}

SCENARIO("decoder hardening fails closed when RLIMIT_FSIZE cannot be set", "[media][thumbnail_hardening]")
{
    GIVEN("hardening ops where setrlimit fails only for RLIMIT_FSIZE")
    {
        auto ops = all_succeeding_ops();
        ops.set_resource_limit = [](int resource, std::uint64_t /*value*/) {
            return resource != RLIMIT_FSIZE;
        };

        WHEN("the decoder worker hardens")
        {
            auto const result = merovingian::media::apply_decoder_hardening(ops);

            THEN("hardening is not accepted and RLIMIT_FSIZE is named as the failed control")
            {
                REQUIRE_FALSE(result.accepted);
                REQUIRE(result.failed_control == "setrlimit(RLIMIT_FSIZE)");
            }
        }
    }
}

SCENARIO("decoder hardening fails closed when RLIMIT_CORE cannot be set", "[media][thumbnail_hardening]")
{
    GIVEN("hardening ops where setrlimit fails only for RLIMIT_CORE")
    {
        auto ops = all_succeeding_ops();
        ops.set_resource_limit = [](int resource, std::uint64_t /*value*/) {
            return resource != RLIMIT_CORE;
        };

        WHEN("the decoder worker hardens")
        {
            auto const result = merovingian::media::apply_decoder_hardening(ops);

            THEN("hardening is not accepted and RLIMIT_CORE is named as the failed control")
            {
                REQUIRE_FALSE(result.accepted);
                REQUIRE(result.failed_control == "setrlimit(RLIMIT_CORE)");
            }
        }
    }
}

SCENARIO("decoder hardening fails closed when RLIMIT_NOFILE cannot be set", "[media][thumbnail_hardening]")
{
    GIVEN("hardening ops where setrlimit fails only for RLIMIT_NOFILE")
    {
        auto ops = all_succeeding_ops();
        ops.set_resource_limit = [](int resource, std::uint64_t /*value*/) {
            return resource != RLIMIT_NOFILE;
        };

        WHEN("the decoder worker hardens")
        {
            auto const result = merovingian::media::apply_decoder_hardening(ops);

            THEN("hardening is not accepted and RLIMIT_NOFILE is named as the failed control")
            {
                REQUIRE_FALSE(result.accepted);
                REQUIRE(result.failed_control == "setrlimit(RLIMIT_NOFILE)");
            }
        }
    }
}

#if defined(__linux__)

SCENARIO("decoder hardening fails closed when PR_SET_DUMPABLE cannot be applied", "[media][thumbnail_hardening]")
{
    GIVEN("hardening ops where disabling core dumps via prctl fails")
    {
        auto ops = all_succeeding_ops();
        ops.disable_core_dumps = [] {
            return false;
        };

        WHEN("the decoder worker hardens")
        {
            auto const result = merovingian::media::apply_decoder_hardening(ops);

            THEN("hardening is not accepted and PR_SET_DUMPABLE is named as the failed control")
            {
                REQUIRE_FALSE(result.accepted);
                REQUIRE(result.failed_control == "prctl(PR_SET_DUMPABLE)");
            }
        }
    }
}

SCENARIO("decoder hardening fails closed when PR_SET_NO_NEW_PRIVS cannot be applied", "[media][thumbnail_hardening]")
{
    GIVEN("hardening ops where prctl(PR_SET_NO_NEW_PRIVS) fails")
    {
        auto ops = all_succeeding_ops();
        ops.set_no_new_privs = [] {
            return false;
        };

        WHEN("the decoder worker hardens")
        {
            auto const result = merovingian::media::apply_decoder_hardening(ops);

            THEN("hardening is not accepted and PR_SET_NO_NEW_PRIVS is named as the failed control")
            {
                REQUIRE_FALSE(result.accepted);
                REQUIRE(result.failed_control == "prctl(PR_SET_NO_NEW_PRIVS)");
            }
        }
    }
}

SCENARIO("decoder hardening fails closed when the decoder seccomp filter cannot be installed",
         "[media][thumbnail_hardening]")
{
    GIVEN("hardening ops where installing the decoder seccomp filter fails")
    {
        auto ops = all_succeeding_ops();
        ops.apply_seccomp_filter = [] {
            return false;
        };

        WHEN("the decoder worker hardens")
        {
            auto const result = merovingian::media::apply_decoder_hardening(ops);

            THEN("hardening is not accepted and the seccomp filter is named as the failed control")
            {
                REQUIRE_FALSE(result.accepted);
                REQUIRE(result.failed_control == "apply_decoder_seccomp_filter");
            }
        }
    }
}

#elif defined(__OpenBSD__)

SCENARIO("decoder hardening fails closed when pledge cannot be applied", "[media][thumbnail_hardening]")
{
    GIVEN("hardening ops where pledge(\"stdio\") fails")
    {
        auto ops = all_succeeding_ops();
        ops.apply_pledge = [] {
            return false;
        };

        WHEN("the decoder worker hardens")
        {
            auto const result = merovingian::media::apply_decoder_hardening(ops);

            THEN("hardening is not accepted and pledge is named as the failed control")
            {
                REQUIRE_FALSE(result.accepted);
                REQUIRE(result.failed_control == "pledge");
            }
        }
    }
}

#elif defined(__FreeBSD__)

SCENARIO("decoder hardening fails closed when cap_enter cannot be applied", "[media][thumbnail_hardening]")
{
    GIVEN("hardening ops where cap_enter() fails")
    {
        auto ops = all_succeeding_ops();
        ops.apply_capsicum = [] {
            return false;
        };

        WHEN("the decoder worker hardens")
        {
            auto const result = merovingian::media::apply_decoder_hardening(ops);

            THEN("hardening is not accepted and cap_enter is named as the failed control")
            {
                REQUIRE_FALSE(result.accepted);
                REQUIRE(result.failed_control == "cap_enter");
            }
        }
    }
}

#endif

SCENARIO("decoder hardening reports whether the build is a sanitizer build without side effects",
         "[media][thumbnail_hardening]")
{
    GIVEN("the current build")
    {
        WHEN("the sanitizer-build probe is queried")
        {
            auto const first = merovingian::media::decoder_hardening_is_sanitizer_build();
            auto const second = merovingian::media::decoder_hardening_is_sanitizer_build();

            THEN("it is a stable, pure query")
            {
                REQUIRE(first == second);
            }
        }
    }
}
