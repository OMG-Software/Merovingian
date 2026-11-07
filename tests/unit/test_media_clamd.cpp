// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// The clamd INSTREAM client (G15, ADR-0565) against a fake clamd on a temporary AF_UNIX socket. The fake records
// what it was sent on its own thread; every assertion runs here, on the test thread.

#include "../support/FakeClamdServer.hpp"
#include "../support/temp_directory.hpp"
#include "merovingian/media/ClamdScanResult.hpp"
#include "merovingian/media/ClamdScanner.hpp"
#include "merovingian/media/ClamdScannerSettings.hpp"
#include "merovingian/media/ClamdVerdict.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include <unistd.h>

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <thread>

namespace
{

using merovingian::media::ClamdScanner;
using merovingian::media::ClamdScannerSettings;
using merovingian::media::ClamdVerdict;
using merovingian::tests::FakeClamdServer;

[[nodiscard]] auto socket_path(std::string const& name) -> std::string
{
    return (merovingian::tests::temporary_directory() / ("mvg-clamd-" + name + "-" + std::to_string(::getpid())))
        .string();
}

[[nodiscard]] auto settings_for(std::string const& path, std::uint32_t timeout_ms = 2000U) -> ClamdScannerSettings
{
    auto settings = ClamdScannerSettings{};
    settings.socket_path = path;
    settings.timeout_ms = timeout_ms;
    settings.max_scan_bytes = 1024U * 1024U;
    settings.max_concurrent = 2U;
    return settings;
}

// clamd ends its reply with a NUL when asked with the z prefix.
[[nodiscard]] auto nul_terminated(std::string text) -> std::string
{
    text.push_back('\0');
    return text;
}

} // namespace

SCENARIO("clamd answering OK means the media is clean", "[g15][media][clamd]")
{
    GIVEN("a clamd that answers stream: OK")
    {
        auto const path = socket_path("ok");
        auto const server = FakeClamdServer{path, nul_terminated("stream: OK")};
        REQUIRE(server.ok());
        auto scanner = ClamdScanner{settings_for(path)};
        // Larger than one 64 KiB chunk, so the chunk framing is exercised, with bytes that look like framing.
        auto const payload = std::string(150000U, 'a') + std::string{"\0\1|\n", 4U};

        WHEN("the media is scanned")
        {
            auto const result = scanner.scan(payload);

            THEN("it is clean and clamd received exactly the media bytes")
            {
                REQUIRE(result.verdict == ClamdVerdict::clean);
                REQUIRE(result.detail.empty());
                auto const streams = server.received_streams();
                REQUIRE(streams.size() == 1U);
                REQUIRE(streams.front() == payload);
                REQUIRE(scanner.in_flight() == 0U);
            }
        }
    }
}

SCENARIO("clamd reporting a signature means the media is infected", "[g15][media][clamd]")
{
    GIVEN("a clamd that finds Win.Test.EICAR_HDB-1")
    {
        auto const path = socket_path("found");
        auto const server = FakeClamdServer{path, nul_terminated("stream: Win.Test.EICAR_HDB-1 FOUND")};
        REQUIRE(server.ok());
        auto scanner = ClamdScanner{settings_for(path)};

        WHEN("media is scanned")
        {
            auto const result = scanner.scan("payload");

            THEN("it is infected and the signature name is reported")
            {
                REQUIRE(result.verdict == ClamdVerdict::infected);
                REQUIRE(result.detail == "Win.Test.EICAR_HDB-1");
                REQUIRE_FALSE(result.is_clean());
            }
        }
    }
}

SCENARIO("a clamd error or malformed reply is never clean", "[g15][media][clamd]")
{
    GIVEN("replies that are not stream: OK or stream: <name> FOUND")
    {
        auto const reply =
            GENERATE(nul_terminated("INSTREAM size limit exceeded. ERROR"), nul_terminated("stream: some error ERROR"),
                     nul_terminated("garbage"), nul_terminated("stream: OK FOUNDX"), nul_terminated("stream:  FOUND"),
                     nul_terminated("OK"), nul_terminated("stream: OKAY"));
        auto const path = socket_path("bad");
        auto const server = FakeClamdServer{path, reply};
        REQUIRE(server.ok());
        auto scanner = ClamdScanner{settings_for(path)};

        WHEN("media is scanned")
        {
            auto const result = scanner.scan("payload");

            THEN("the scan failed")
            {
                REQUIRE(result.verdict == ClamdVerdict::failed);
                REQUIRE_FALSE(result.is_clean());
            }
        }
    }

    GIVEN("a reply that never ends with the NUL terminator")
    {
        auto const path = socket_path("nonul");
        auto const server = FakeClamdServer{path, std::string{"stream: OK"}};
        REQUIRE(server.ok());
        auto scanner = ClamdScanner{settings_for(path, 500U)};

        WHEN("media is scanned")
        {
            auto const result = scanner.scan("payload");

            THEN("the scan failed, not clean")
            {
                REQUIRE(result.verdict == ClamdVerdict::failed);
            }
        }
    }

    GIVEN("a reply longer than the bound")
    {
        auto const path = socket_path("long");
        auto const server = FakeClamdServer{path, nul_terminated(std::string(2000U, 'x'))};
        REQUIRE(server.ok());
        auto scanner = ClamdScanner{settings_for(path)};

        WHEN("media is scanned")
        {
            auto const result = scanner.scan("payload");

            THEN("the scan failed")
            {
                REQUIRE(result.verdict == ClamdVerdict::failed);
            }
        }
    }
}

SCENARIO("a clamd that never answers times out as a failure", "[g15][media][clamd]")
{
    GIVEN("a clamd that reads the stream and stays silent, and a 300 ms deadline")
    {
        auto const path = socket_path("silent");
        auto const server = FakeClamdServer{path, std::nullopt};
        REQUIRE(server.ok());
        auto scanner = ClamdScanner{settings_for(path, 300U)};

        WHEN("media is scanned")
        {
            auto const started = std::chrono::steady_clock::now();
            auto const result = scanner.scan("payload");
            auto const waited = std::chrono::steady_clock::now() - started;

            THEN("the scan failed after about the deadline, not hanging")
            {
                REQUIRE(result.verdict == ClamdVerdict::failed);
                REQUIRE(waited >= std::chrono::milliseconds{250});
                REQUIRE(waited < std::chrono::seconds{3});
                REQUIRE(scanner.in_flight() == 0U);
            }
        }
    }
}

SCENARIO("a clamd that cannot be reached is a failed scan", "[g15][media][clamd]")
{
    GIVEN("a socket path with nothing there")
    {
        auto scanner = ClamdScanner{settings_for(socket_path("absent"))};

        WHEN("media is scanned")
        {
            auto const result = scanner.scan("payload");

            THEN("the scan failed")
            {
                REQUIRE(result.verdict == ClamdVerdict::failed);
                REQUIRE_FALSE(result.detail.empty());
            }
        }
    }

    GIVEN("a socket path that exists but is not a socket")
    {
        auto const path = socket_path("file");
        {
            auto const out = std::ofstream{path};
        }
        auto scanner = ClamdScanner{settings_for(path)};

        WHEN("media is scanned")
        {
            auto const result = scanner.scan("payload");
            std::filesystem::remove(path);

            THEN("the connection is refused and the scan failed")
            {
                REQUIRE(result.verdict == ClamdVerdict::failed);
            }
        }
    }
}

SCENARIO("media above max_scan_bytes is not sent to clamd", "[g15][media][clamd]")
{
    GIVEN("a clamd that would answer OK and a 1 KiB scan limit")
    {
        auto const path = socket_path("big");
        auto const server = FakeClamdServer{path, nul_terminated("stream: OK")};
        REQUIRE(server.ok());
        auto settings = settings_for(path);
        settings.max_scan_bytes = 1024U;
        auto scanner = ClamdScanner{settings};

        WHEN("1025 bytes and then exactly 1024 bytes are scanned")
        {
            auto const result = scanner.scan(std::string(1025U, 'z'));
            auto const exact = scanner.scan(std::string(1024U, 'z'));

            THEN("the first is oversize and never reached clamd, while exactly the limit is scanned")
            {
                REQUIRE(result.verdict == ClamdVerdict::oversize);
                REQUIRE_FALSE(result.is_clean());
                REQUIRE(exact.verdict == ClamdVerdict::clean);
                REQUIRE(server.connections() == 1U);
            }
        }
    }
}

SCENARIO("a scanner with no socket path is off and never clean", "[g15][media][clamd]")
{
    GIVEN("default settings")
    {
        auto scanner = ClamdScanner{ClamdScannerSettings{}};

        WHEN("it is asked to scan")
        {
            auto const result = scanner.scan("payload");

            THEN("it reports disabled and a failed verdict")
            {
                REQUIRE_FALSE(scanner.enabled());
                REQUIRE(result.verdict == ClamdVerdict::failed);
            }
        }
    }
}

SCENARIO("scans beyond the concurrency bound wait for capacity until their deadline", "[g15][media][clamd]")
{
    GIVEN("a silent clamd, a limit of one scan at a time and a 400 ms deadline")
    {
        auto const path = socket_path("cap");
        auto const server = FakeClamdServer{path, std::nullopt};
        REQUIRE(server.ok());
        auto settings = settings_for(path, 400U);
        settings.max_concurrent = 1U;
        auto scanner = ClamdScanner{settings};
        auto first = merovingian::media::ClamdScanResult{};
        auto first_scan = std::thread{[&scanner, &first] {
            first = scanner.scan("one");
        }};
        auto const give_up = std::chrono::steady_clock::now() + std::chrono::seconds{2};
        while (scanner.in_flight() == 0U && std::chrono::steady_clock::now() < give_up)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds{2});
        }

        WHEN("a second scan arrives while the first holds the only place")
        {
            auto const second = scanner.scan("two");
            first_scan.join();

            THEN("the second failed for lack of capacity without reaching clamd, and the first timed out")
            {
                REQUIRE(second.verdict == ClamdVerdict::failed);
                REQUIRE(second.detail.find("capacity") != std::string::npos);
                REQUIRE(first.verdict == ClamdVerdict::failed);
                REQUIRE(server.connections() == 1U);
                REQUIRE(scanner.in_flight() == 0U);
            }
        }
    }
}

SCENARIO("clamd is supported on the platforms whose sandbox allows the socket", "[g15][media][clamd][platform]")
{
    GIVEN("this build's platform")
    {
        WHEN("support is asked")
        {
            auto const supported = merovingian::media::clamd_supported_on_this_platform();

            THEN("the answer matches the platform")
            {
#if defined(__FreeBSD__) || defined(__OpenBSD__)
                REQUIRE_FALSE(supported);
#else
                REQUIRE(supported);
#endif
            }
        }
    }
}
