// SPDX-License-Identifier: GPL-3.0-or-later

// ISO-7 (29 Sep 2026 audit): a secret is validated and read through one opened
// descriptor, never checked by path and then opened again. These scenarios cover
// the two places that still reopened: the master-key derived-key caches (whose
// file identity and material came from two opens) and the TLS private key
// (checked at startup, then loaded by OpenSSL from the path).

#include "../support/TempDirectory.hpp"
#include "../support/TlsMockServer.hpp"
#include "merovingian/crypto/MasterKey.hpp"
#include "merovingian/homeserver/Tls.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>
#include <system_error>
#include <tuple>
#include <utility>

#include <sys/stat.h>

namespace
{

[[nodiscard]] auto unique_path(std::string_view stem) -> std::filesystem::path
{
    static auto counter = std::uint64_t{0U};
    return merovingian::tests::temporary_directory() /
           (std::string{stem} + "-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) +
            "-" + std::to_string(counter++));
}

auto write_owner_read_only(std::filesystem::path const& path, std::string_view content) -> void
{
    {
        auto stream = std::ofstream{path, std::ios::binary};
        stream.write(content.data(), static_cast<std::streamsize>(content.size()));
    }
    std::filesystem::permissions(path, std::filesystem::perms::owner_read);
}

class RemoveOnExit final
{
public:
    explicit RemoveOnExit(std::filesystem::path path)
        : path_{std::move(path)}
    {
    }
    RemoveOnExit(RemoveOnExit const&) = delete;
    auto operator=(RemoveOnExit const&) -> RemoveOnExit& = delete;
    RemoveOnExit(RemoveOnExit&&) = delete;
    auto operator=(RemoveOnExit&&) -> RemoveOnExit& = delete;
    ~RemoveOnExit()
    {
        auto ignored = std::error_code{};
        std::filesystem::remove(path_, ignored);
    }

private:
    std::filesystem::path path_{};
};

} // namespace

SCENARIO("ISO-7 a master key file's identity and material come from one opened file", "[iso7][crypto][master_key]")
{
    GIVEN("a master key file opened once, then replaced by rename with a different key")
    {
        auto const path = unique_path("merovingian-iso7-master");
        auto const cleanup = RemoveOnExit{path};
        auto const first = std::string(32U, 'a');
        write_owner_read_only(path, first);
        auto const opened = merovingian::crypto::open_master_key_file(path.string());
        REQUIRE(opened.has_value());
        REQUIRE_FALSE(opened->identity.empty());

        auto const replacement = unique_path("merovingian-iso7-master-new");
        write_owner_read_only(replacement, std::string(32U, 'b'));
        std::filesystem::rename(replacement, path);

        WHEN("the material is read from the opened file")
        {
            auto const material = merovingian::crypto::load_master_key_material(*opened);

            THEN("it is the bytes of the file the identity describes, not the replacement")
            {
                REQUIRE(material.has_value());
                CHECK(std::ranges::equal(material->bytes(), first, [](auto byte, char expected) {
                    return byte == static_cast<unsigned char>(expected);
                }));
                CHECK(merovingian::crypto::master_key_file_identity(path.string()) != opened->identity);
            }
        }
    }
}

SCENARIO("ISO-7 the TLS private key is validated and read through one descriptor", "[iso7][tls]")
{
    GIVEN("a certificate and its private key")
    {
        auto const certificate = merovingian::tests::tls_mock::write_test_tls_certificate();
        auto const key = std::filesystem::path{certificate.private_key_file};

        WHEN("the key is owner-read-only (0400)")
        {
            std::filesystem::permissions(key, std::filesystem::perms::owner_read);
            auto const result =
                merovingian::homeserver::make_tls_server_context(certificate.certificate_file, key.string());

            THEN("the context is created")
            {
                CHECK(result.ok());
            }
        }

        WHEN("the key is readable by its group (0640)")
        {
            std::filesystem::permissions(key, std::filesystem::perms::owner_read | std::filesystem::perms::owner_write |
                                                  std::filesystem::perms::group_read);
            auto const result =
                merovingian::homeserver::make_tls_server_context(certificate.certificate_file, key.string());

            THEN("loading fails")
            {
                CHECK_FALSE(result.ok());
            }
        }

        WHEN("the key path is a symlink to an owner-read-only key")
        {
            std::filesystem::permissions(key, std::filesystem::perms::owner_read);
            auto const link = key.parent_path() / "server-link.key";
            std::filesystem::create_symlink(key, link);
            auto const result =
                merovingian::homeserver::make_tls_server_context(certificate.certificate_file, link.string());

            THEN("loading fails")
            {
                CHECK_FALSE(result.ok());
            }
        }
    }
}

SCENARIO("ISO-7 the test certificate helper never creates a file others can open", "[iso7][tls][test_support]")
{
    GIVEN("a process umask that would leave a created file readable and writable by everyone")
    {
        // umask is process-wide: restore it on every exit so later scenarios keep the runner's mask.
        struct UmaskRestore final
        {
            ::mode_t previous{::umask(0)};
            UmaskRestore() = default;
            ~UmaskRestore()
            {
                std::ignore = ::umask(previous);
            }
            UmaskRestore(UmaskRestore const&) = delete;
            auto operator=(UmaskRestore const&) -> UmaskRestore& = delete;
            UmaskRestore(UmaskRestore&&) = delete;
            auto operator=(UmaskRestore&&) -> UmaskRestore& = delete;
        };
        auto const restore = UmaskRestore{};

        WHEN("the helper writes a certificate and its private key")
        {
            auto const certificate = merovingian::tests::tls_mock::write_test_tls_certificate();
            auto const group_or_other = std::filesystem::perms::group_all | std::filesystem::perms::others_all;

            THEN("neither file grants its group or other users any access")
            {
                auto const certificate_perms =
                    std::filesystem::status(certificate.certificate_file).permissions() & group_or_other;
                auto const key_perms =
                    std::filesystem::status(certificate.private_key_file).permissions() & group_or_other;
                CHECK(certificate_perms == std::filesystem::perms::none);
                CHECK(key_perms == std::filesystem::perms::none);
            }
        }
    }
}
