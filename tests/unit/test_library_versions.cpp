// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// The library versions each executable logs at startup: what is running, how it was linked, and
// what it was built against (0.12.45). A dynamically linked library can change under the binary
// with an OS update; a statically linked one changes only with a rebuild.

#include "merovingian/canonicaljson/library_versions.hpp"
#include "merovingian/core/library_version.hpp"
#include "merovingian/database/library_versions.hpp"
#include "merovingian/homeserver/library_versions.hpp"
#include "merovingian/media/thumbnailer.hpp"

#include <catch2/catch_test_macros.hpp>

#include <set>
#include <string>
#include <utility>
#include <vector>

namespace
{

using merovingian::core::LibraryVersion;
using merovingian::core::Linkage;

// Defined in this test binary, so it is linked into it whatever the build.
int const object_in_this_binary = 42;

[[nodiscard]] auto library(std::string name, Linkage linkage, std::string runtime_version, std::string build_version,
                           std::string shared_object = {}) -> LibraryVersion
{
    return LibraryVersion{std::move(name), linkage, std::move(runtime_version), std::move(build_version),
                          std::move(shared_object)};
}

} // namespace

SCENARIO("An address inside the running executable is reported as statically linked", "[core][library-versions]")
{
    GIVEN("an object defined in this test binary")
    {
        auto const* const address = &object_in_this_binary;

        WHEN("the library holding it is described")
        {
            auto const described = merovingian::core::describe_library("fixture", "1.2.3", "1.2.3", address);

            THEN("it is static, names no shared object, and keeps the versions it was given")
            {
                REQUIRE(described.name == "fixture");
                REQUIRE(described.linkage == Linkage::static_linked);
                REQUIRE(described.shared_object.empty());
                REQUIRE(described.runtime_version == "1.2.3");
                REQUIRE(described.build_version == "1.2.3");
            }
        }
    }
}

SCENARIO("Every library the server links reports what is running and how it is linked", "[core][library-versions]")
{
    GIVEN("the libraries linked into this binary through the server's modules")
    {
        WHEN("their versions are collected")
        {
            auto const libraries = merovingian::homeserver::linked_library_versions();

            THEN("each of the server's libraries appears exactly once")
            {
                auto names = std::multiset<std::string>{};
                for (auto const& entry : libraries)
                {
                    names.insert(entry.name);
                }
                REQUIRE(names ==
                        std::multiset<std::string>{"OpenSSL", "SQLite", "libcurl", "libpq", "libsodium", "yyjson"});
            }

            THEN("each reports its running version, and a dynamic one the shared object it was loaded from")
            {
                for (auto const& entry : libraries)
                {
                    CAPTURE(entry.name, entry.runtime_version, entry.build_version, entry.shared_object);
                    REQUIRE_FALSE(entry.runtime_version.empty());
                    REQUIRE_FALSE(entry.build_version.empty());
                    if (entry.linkage == Linkage::dynamic)
                    {
                        REQUIRE_FALSE(entry.shared_object.empty());
                    }
                    else
                    {
                        REQUIRE(entry.shared_object.empty());
                    }
                }
            }

            THEN("a statically linked library runs exactly the version it was built from")
            {
                for (auto const& entry : libraries)
                {
                    CAPTURE(entry.name, entry.runtime_version, entry.build_version);
                    if (entry.linkage == Linkage::static_linked && entry.name != "libpq")
                    {
                        // libpq's build version is the pkg-config version Meson found, not a header
                        // macro compiled from the same source, so it is not held to this.
                        REQUIRE(entry.runtime_version == entry.build_version);
                    }
                }
            }
        }
    }
}

SCENARIO("A library's startup log line says how it is linked and what it was built against", "[core][library-versions]")
{
    GIVEN("libraries linked in each way")
    {
        WHEN("each is rendered for the log")
        {
            auto const static_line = merovingian::core::library_version_log_line(
                library("SQLite", Linkage::static_linked, "3.54.1", "3.54.1"));
            auto const dynamic_line = merovingian::core::library_version_log_line(
                library("libsodium", Linkage::dynamic, "1.0.18", "1.0.18", "/usr/lib/libsodium.so.23"));
            auto const drifted_line = merovingian::core::library_version_log_line(
                library("libcurl", Linkage::dynamic, "8.9.1", "8.5.0", "/usr/lib/libcurl.so.4"));
            auto const unreported_line = merovingian::core::library_version_log_line(
                library("libjpeg-turbo", Linkage::dynamic, "", "3.0.2", "/usr/lib/libturbojpeg.so.0"));

            THEN("a static library names its version and its linkage only")
            {
                REQUIRE(static_line == "SQLite 3.54.1 (static)");
            }

            THEN("a dynamic library also names the shared object it runs from and the version it was built against")
            {
                REQUIRE(dynamic_line == "libsodium 1.0.18 (dynamic, /usr/lib/libsodium.so.23; built against 1.0.18)");
                REQUIRE(drifted_line == "libcurl 8.9.1 (dynamic, /usr/lib/libcurl.so.4; built against 8.5.0)");
            }

            THEN("a library with no runtime version call says so rather than guessing")
            {
                REQUIRE(unreported_line == "libjpeg-turbo version not reported (dynamic, /usr/lib/libturbojpeg.so.0; "
                                           "built against 3.0.2)");
            }
        }
    }
}

SCENARIO("libpq and yyjson version numbers are rendered as their releases are named", "[core][library-versions]")
{
    GIVEN("the numeric versions libpq and yyjson report")
    {
        WHEN("they are formatted")
        {
            THEN("libpq 10 and later is major.minor, and earlier releases major.minor.patch")
            {
                REQUIRE(merovingian::database::format_libpq_version(180001) == "18.1");
                REQUIRE(merovingian::database::format_libpq_version(100023) == "10.23");
                REQUIRE(merovingian::database::format_libpq_version(90624) == "9.6.24");
            }

            THEN("an unusable libpq version is not rendered")
            {
                REQUIRE(merovingian::database::format_libpq_version(0).empty());
                REQUIRE(merovingian::database::format_libpq_version(-1).empty());
            }

            THEN("yyjson's packed hexadecimal version is major.minor.patch")
            {
                REQUIRE(merovingian::canonicaljson::format_yyjson_version(0x000D00U) == "0.13.0");
                REQUIRE(merovingian::canonicaljson::format_yyjson_version(0x010203U) == "1.2.3");
            }
        }
    }
}

// The worker's report crosses a pipe into the server's log, so every field must arrive as sent, and
// no byte a library or the loader chose may split a field or start a log line of its own.
SCENARIO("The thumbnail worker's library report survives its wire format", "[media][library-versions]")
{
    GIVEN("the thumbnail worker's two libraries")
    {
        auto const libraries = std::vector<LibraryVersion>{
            library("libpng", Linkage::dynamic, "1.6.43", "1.6.43", "/usr/lib/libpng16.so.16"),
            library("libjpeg-turbo", Linkage::static_linked, "", "3.0.2"),
        };

        WHEN("they are framed and parsed back")
        {
            auto const parsed =
                merovingian::media::parse_library_report(merovingian::media::frame_library_report(libraries));

            THEN("every field comes back unchanged")
            {
                REQUIRE(parsed.has_value());
                REQUIRE(parsed->size() == 2U);
                REQUIRE((*parsed)[0] == libraries[0]);
                REQUIRE((*parsed)[1] == libraries[1]);
            }
        }

        WHEN("a field holds a tab, a newline or another control character")
        {
            auto hostile = libraries;
            hostile[0].runtime_version = "1.6\t43";
            hostile[1].shared_object = "/tmp/a\nInjected log line";
            auto const parsed =
                merovingian::media::parse_library_report(merovingian::media::frame_library_report(hostile));

            THEN("the framing keeps one field per field, and nothing reaches the log as a second line")
            {
                REQUIRE(parsed.has_value());
                REQUIRE(parsed->size() == 2U);
                REQUIRE((*parsed)[0].runtime_version == "1.6?43");
                REQUIRE((*parsed)[1].shared_object == "/tmp/a?Injected log line");
            }
        }
    }
}

// The server treats the worker's answer as untrusted input: anything the framing would never produce
// is refused whole rather than logged in part.
SCENARIO("The server refuses a library report the thumbnail worker would never send", "[media][library-versions]")
{
    GIVEN("frames a worker should never send")
    {
        auto const valid = merovingian::media::frame_library_report(
            std::vector<LibraryVersion>{library("libpng", Linkage::dynamic, "1.6.43", "1.6.43", "/usr/lib/libpng.so")});

        WHEN("each is parsed")
        {
            auto truncated = valid;
            truncated.pop_back();
            auto trailing = valid + "x";
            auto wrong_magic = valid;
            wrong_magic[0] = 'X';
            auto bad_linkage = valid;
            bad_linkage.replace(bad_linkage.find("dynamic"), 7U, "shared!");
            auto raw_control = valid;
            raw_control.replace(raw_control.find("1.6.43"), 1U, "\x1b");

            THEN("each is refused")
            {
                REQUIRE_FALSE(merovingian::media::parse_library_report("").has_value());
                REQUIRE_FALSE(merovingian::media::parse_library_report(truncated).has_value());
                REQUIRE_FALSE(merovingian::media::parse_library_report(trailing).has_value());
                REQUIRE_FALSE(merovingian::media::parse_library_report(wrong_magic).has_value());
                REQUIRE_FALSE(merovingian::media::parse_library_report(bad_linkage).has_value());
                REQUIRE_FALSE(merovingian::media::parse_library_report(raw_control).has_value());
            }
        }

        WHEN("a report names more libraries than a worker links")
        {
            auto const many = std::vector<LibraryVersion>(merovingian::media::max_library_report_entries + 1U,
                                                          library("libpng", Linkage::dynamic, "1", "1", "/x"));
            auto const parsed =
                merovingian::media::parse_library_report(merovingian::media::frame_library_report(many));

            THEN("it is refused")
            {
                REQUIRE_FALSE(parsed.has_value());
            }
        }
    }
}

// The worker reads one frame from stdin and must never mistake a report request for an image to
// decode, or a thumbnail job for a report request.
SCENARIO("A library report request is told apart from a thumbnail job", "[media][library-versions]")
{
    GIVEN("a library report request")
    {
        auto const request = merovingian::media::frame_library_report_request();

        WHEN("the worker classifies it and a thumbnail request")
        {
            auto const thumbnail = merovingian::media::frame_thumbnail_request(
                merovingian::media::ThumbnailWorkerRequest{.format = merovingian::media::ThumbnailSourceFormat::png,
                                                           .method = merovingian::media::ThumbnailMethod::scale,
                                                           .target_width = 1U,
                                                           .target_height = 1U,
                                                           .max_pixels = 1U,
                                                           .source_bytes = "x"});

            THEN("only the report request is one, and it is not mistaken for a thumbnail job")
            {
                REQUIRE(merovingian::media::is_library_report_request(request));
                REQUIRE_FALSE(merovingian::media::parse_thumbnail_request(request).has_value());
                REQUIRE(thumbnail.has_value());
                REQUIRE_FALSE(merovingian::media::is_library_report_request(*thumbnail));
                REQUIRE_FALSE(merovingian::media::is_library_report_request(request + "x"));
            }
        }
    }
}
