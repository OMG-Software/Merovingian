// SPDX-License-Identifier: GPL-3.0-or-later

#include <merovingian/platform/hardening_self_check.hpp>

#include <catch2/catch_test_macros.hpp>

#include <string>

TEST_CASE("Startup hardening self-check reports stable baseline checks", "[platform][hardening]")
{
    // Given
    auto constexpr expected_count = 13U;

    // When
    auto const self_check = merovingian::platform::run_startup_hardening_self_check();

    // Then
    REQUIRE(self_check.count() == expected_count);
    REQUIRE(self_check.checks()[0].name == "compiler hardening");
    REQUIRE(self_check.checks()[1].name == "linker hardening");
    REQUIRE(self_check.checks()[2].name == "PIE");
    REQUIRE(self_check.checks()[3].name == "RELRO");
    REQUIRE(self_check.checks()[4].name == "stack protector");
    REQUIRE(self_check.checks()[5].name == "FORTIFY_SOURCE");
    REQUIRE(self_check.checks()[6].name == "seccomp");
    REQUIRE(self_check.checks()[7].name == "pledge/unveil");
    REQUIRE(self_check.checks()[8].name == "capsicum");
    REQUIRE(self_check.checks()[9].name == "privilege drop");
    REQUIRE(self_check.checks()[10].name == "filesystem restrictions");
    REQUIRE(self_check.checks()[11].name == "core dump policy");
    REQUIRE(self_check.checks()[12].name == "secret redaction policy");
}

TEST_CASE("Unimplemented runtime hardening checks remain unknown", "[platform][hardening]")
{
    // Given
    auto constexpr unknown = merovingian::platform::HardeningStatus::unknown;

    // When
    auto const self_check = merovingian::platform::run_startup_hardening_self_check();

    // Then
    REQUIRE(self_check.checks()[6].status == unknown);
    REQUIRE(self_check.checks()[7].status == unknown);
    REQUIRE(self_check.checks()[8].status == unknown);
    REQUIRE(self_check.checks()[9].status == unknown);
    REQUIRE(self_check.checks()[10].status == unknown);
    REQUIRE(self_check.checks()[11].status == unknown);
}

TEST_CASE("Secret redaction policy self-check is enabled", "[platform][hardening]")
{
    // Given
    auto constexpr enabled = merovingian::platform::HardeningStatus::enabled;

    // When
    auto const self_check = merovingian::platform::run_startup_hardening_self_check();

    // Then
    REQUIRE(self_check.checks()[12].name == "secret redaction policy");
    REQUIRE(self_check.checks()[12].status == enabled);
}

TEST_CASE("Hardening status names are stable for startup logs", "[platform][hardening]")
{
    // Given
    auto constexpr enabled = merovingian::platform::HardeningStatus::enabled;
    auto constexpr disabled = merovingian::platform::HardeningStatus::disabled;
    auto constexpr unknown = merovingian::platform::HardeningStatus::unknown;

    // When
    auto const enabled_name = std::string{merovingian::platform::hardening_status_name(enabled)};
    auto const disabled_name = std::string{merovingian::platform::hardening_status_name(disabled)};
    auto const unknown_name = std::string{merovingian::platform::hardening_status_name(unknown)};

    // Then
    REQUIRE(enabled_name == "enabled");
    REQUIRE(disabled_name == "disabled");
    REQUIRE(unknown_name == "unknown");
}
