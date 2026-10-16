// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#include <catch2/catch_test_macros.hpp>

#include <array>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>

namespace
{
auto source(std::string const& relative) -> std::string
{
    auto stream = std::ifstream{std::filesystem::path{MEROVINGIAN_TEST_SOURCE_ROOT} / relative};
    REQUIRE(stream.good());
    return {std::istreambuf_iterator<char>{stream}, std::istreambuf_iterator<char>{}};
}
} // namespace
SCENARIO("Executables establish a private file creation mask before initialization", "[platform][iso6_defaults]")
{
    GIVEN("all production executable entry points")
    {
        WHEN("their startup ordering is inspected")
        {
            THEN("every main sets umask 0077 before initializing services")
            {
                for (auto const* path :
                     std::array{"src/main.cpp", "src/db_migrate.cpp", "src/federation_worker/main.cpp",
                                "src/media/thumbnail_worker_main.cpp"})
                {
                    auto const text = source(path);
                    auto const main = text.find("auto main(");
                    REQUIRE(main != std::string::npos);
                    auto const body = text.substr(text.find('{', main), 180);
                    auto const private_mask = body.find("::umask(0077)") != std::string::npos;
                    REQUIRE(private_mask);
                }
            }
        }
    }
}
SCENARIO("Packages write registration tokens under a private mask", "[platform][iso6_defaults]")
{
    GIVEN("all package token generators and the systemd service")
    {
        WHEN("their creation policies are inspected")
        {
            THEN("the token write is already private before chmod and systemd enforces the same mask")
            {
                for (auto const* path :
                     std::array{"packaging/deb/postinst", "packaging/freebsd/+MANIFEST", "packaging/openbsd/+INSTALL",
                                "packaging/rpm/merovingian.spec", "packaging/rhel/merovingian.spec",
                                "packaging/opensuse/merovingian.spec"})
                {
                    auto const text = source(path);
                    auto const generate = text.find("openssl rand -base64 48");
                    REQUIRE(generate != std::string::npos);
                    auto const mask = text.rfind("umask 077", generate);
                    auto const private_before_write = mask != std::string::npos;
                    REQUIRE(private_before_write);
                }
                auto const private_service =
                    source("packaging/systemd/merovingian.service").find("UMask=0077") != std::string::npos;
                REQUIRE(private_service);
            }
        }
    }
}
SCENARIO("The systemd unit confines address families and kernel interfaces", "[platform][iso8]")
{
    GIVEN("the packaged systemd service")
    {
        auto const unit = source("packaging/systemd/merovingian.service");

        WHEN("its [Service] sandbox directives are inspected")
        {
            THEN("only the address families the server and its workers use are admitted")
            {
                REQUIRE(unit.find("\nRestrictAddressFamilies=AF_UNIX AF_INET AF_INET6\n") != std::string::npos);
            }
            AND_THEN("kernel tunables, modules, logs, control groups and namespaces are protected")
            {
                for (auto const* directive :
                     std::array{"\nProtectKernelTunables=true\n", "\nProtectKernelModules=true\n",
                                "\nProtectKernelLogs=true\n", "\nProtectControlGroups=true\n",
                                "\nRestrictNamespaces=true\n", "\nUMask=0077\n"})
                {
                    CAPTURE(directive);
                    REQUIRE(unit.find(directive) != std::string::npos);
                }
            }
        }
    }
}
