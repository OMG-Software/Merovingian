// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// CRY-4 and ISO-7 (29 Sep 2026 audit), PR #509 review: the access-token HMAC
// keys are on every authenticated request's path. They are derived once per
// master key file and shared, so a request costs one open and fstat rather
// than a fresh pair of locked key copies, and they are only ever derived from
// the file whose identity they are cached under.

#include "../support/temp_directory.hpp"
#include "merovingian/crypto/secure_key_bytes.hpp"
#include "merovingian/crypto/token_key.hpp"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

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

SCENARIO("Token HMAC keys are derived once per master key file and then shared", "[crypto][cry4][token_key]")
{
    GIVEN("a valid owner-only master key file")
    {
        auto const path = unique_path("merovingian-cry4-token-keys");
        auto const cleanup = RemoveOnExit{path};
        write_owner_read_only(path, std::string(32U, 'k'));

        WHEN("the keys are looked up twice while the file is unchanged")
        {
            auto const first = merovingian::crypto::cached_token_hmac_keys(path.string());
            auto const second = merovingian::crypto::cached_token_hmac_keys(path.string());

            THEN("both lookups share one derived key pair rather than copying it")
            {
                REQUIRE(first != nullptr);
                REQUIRE(first->v3.has_value());
                REQUIRE(first->v4.has_value());
                CHECK(second.get() == first.get());
                CHECK_FALSE(first->v3->bytes == first->v4->bytes);
            }
        }

        WHEN("the file is replaced by a different key")
        {
            auto const before = merovingian::crypto::cached_token_hmac_keys(path.string());
            REQUIRE(before != nullptr);
            auto const replacement = unique_path("merovingian-cry4-token-keys-next");
            write_owner_read_only(replacement, std::string(32U, 'r'));
            std::filesystem::rename(replacement, path);
            auto const after = merovingian::crypto::cached_token_hmac_keys(path.string());

            THEN("the next lookup derives the replacement's keys")
            {
                REQUIRE(after != nullptr);
                REQUIRE(after->v4.has_value());
                CHECK(after.get() != before.get());
                CHECK_FALSE(after->v4->bytes == before->v4->bytes);
            }
        }

        WHEN("the file is removed")
        {
            REQUIRE(merovingian::crypto::cached_token_hmac_keys(path.string()) != nullptr);
            std::filesystem::remove(path);

            THEN("no keys are served from the cache for a file that is gone")
            {
                CHECK(merovingian::crypto::cached_token_hmac_keys(path.string()) == nullptr);
            }
        }
    }

    GIVEN("no master key file is configured")
    {
        WHEN("the keys are looked up")
        {
            auto const keys = merovingian::crypto::cached_token_hmac_keys("");

            THEN("there are none")
            {
                CHECK(keys == nullptr);
            }
        }
    }

    GIVEN("a master key file that is group-readable")
    {
        auto const path = unique_path("merovingian-cry4-token-keys-open");
        auto const cleanup = RemoveOnExit{path};
        write_owner_read_only(path, std::string(32U, 'g'));
        std::filesystem::permissions(path, std::filesystem::perms::group_read, std::filesystem::perm_options::add);

        WHEN("the keys are looked up")
        {
            auto const keys = merovingian::crypto::cached_token_hmac_keys(path.string());

            THEN("there are none")
            {
                CHECK(keys == nullptr);
            }
        }
    }
}

SCENARIO("A moved-from secure key cannot be copied into an all-zero key", "[crypto][cry4][token_key]")
{
    GIVEN("a key whose bytes have been moved into another key")
    {
        auto source = merovingian::crypto::SecureKeyBytes{};
        source.fill(0x5AU);
        auto const moved = std::move(source);
        REQUIRE(moved.size() == 32U);

        WHEN("the moved-from key is copied")
        {
            THEN("the copy is refused rather than yielding a valid all-zero key")
            {
                // NOLINTNEXTLINE(bugprone-use-after-move): the moved-from state is what is under test.
                CHECK_THROWS_AS(merovingian::crypto::SecureKeyBytes{source}, std::logic_error);
            }
        }
    }
}
