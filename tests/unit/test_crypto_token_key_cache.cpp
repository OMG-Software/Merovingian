// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// CRY-4 and ISO-7 (29 Sep 2026 audit), PR #509 review: the access-token HMAC
// keys are on every authenticated request's path. They are derived once per
// master key file and shared, so a request costs one open and fstat rather
// than a fresh pair of locked key copies, and they are only ever derived from
// the file whose identity they are cached under.

#include "../support/TempDirectory.hpp"
#include "merovingian/crypto/SecureKeyBytes.hpp"
#include "merovingian/crypto/TokenHmacKeys.hpp"
#include "merovingian/crypto/TokenKey.hpp"

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

            THEN("the cache holds the two access-token keys and no other key")
            {
                // ADR-0779, amendment of 2026-11-16: every cached key is a locked page held for the life of the
                // process, and locked memory is a per-process budget (64 KiB by default on FreeBSD). A third key here
                // once cost the server its registration token. This binding compiles only while TokenHmacKeys has
                // exactly two members; a key for another purpose is derived on demand instead.
                REQUIRE(first != nullptr);
                auto const& [v3, v4] = *first;
                CHECK(v3.has_value());
                CHECK(v4.has_value());
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

// ADR-0779, amendment of 2026-11-16: the OAuth 2.0 client ID key is derived from the master key file per client
// registration and never cached, so it holds no locked page while no registration runs.
SCENARIO("The OAuth client ID key is derived on demand from the master key file",
         "[crypto][token_key][oauth_client_id_key]")
{
    GIVEN("two valid owner-only master key files with different keys")
    {
        auto const path = unique_path("merovingian-oauth-client-id-key");
        auto const cleanup = RemoveOnExit{path};
        write_owner_read_only(path, std::string(32U, 'c'));
        auto const other_path = unique_path("merovingian-oauth-client-id-key-other");
        auto const other_cleanup = RemoveOnExit{other_path};
        write_owner_read_only(other_path, std::string(32U, 'd'));

        WHEN("the key is derived twice from one file and once from the other")
        {
            auto const first = merovingian::crypto::derive_oauth_client_id_key_from_file(path.string());
            auto const again = merovingian::crypto::derive_oauth_client_id_key_from_file(path.string());
            auto const other = merovingian::crypto::derive_oauth_client_id_key_from_file(other_path.string());

            THEN("one file always gives the same key, and another file a different one")
            {
                REQUIRE(first.has_value());
                REQUIRE(again.has_value());
                REQUIRE(other.has_value());
                CHECK(first->bytes == again->bytes);
                CHECK_FALSE(first->bytes == other->bytes);
            }
        }

        WHEN("the key and both access-token keys are derived from the same file")
        {
            auto const client_id_key = merovingian::crypto::derive_oauth_client_id_key_from_file(path.string());
            auto const token_keys = merovingian::crypto::cached_token_hmac_keys(path.string());

            THEN("the client ID key is neither access-token key")
            {
                REQUIRE(client_id_key.has_value());
                REQUIRE(token_keys != nullptr);
                REQUIRE(token_keys->v3.has_value());
                REQUIRE(token_keys->v4.has_value());
                CHECK_FALSE(client_id_key->bytes == token_keys->v3->bytes);
                CHECK_FALSE(client_id_key->bytes == token_keys->v4->bytes);
            }
        }
    }

    GIVEN("a path with no file behind it")
    {
        auto const path = unique_path("merovingian-oauth-client-id-key-missing");

        WHEN("the key is derived")
        {
            auto const key = merovingian::crypto::derive_oauth_client_id_key_from_file(path.string());

            THEN("there is none")
            {
                CHECK_FALSE(key.has_value());
            }
        }
    }

    GIVEN("no master key file is configured")
    {
        WHEN("the key is derived")
        {
            auto const key = merovingian::crypto::derive_oauth_client_id_key_from_file("");

            THEN("there is none")
            {
                CHECK_FALSE(key.has_value());
            }
        }
    }

    GIVEN("a master key file that is group-readable")
    {
        auto const path = unique_path("merovingian-oauth-client-id-key-open");
        auto const cleanup = RemoveOnExit{path};
        write_owner_read_only(path, std::string(32U, 'g'));
        std::filesystem::permissions(path, std::filesystem::perms::group_read, std::filesystem::perm_options::add);

        WHEN("the key is derived")
        {
            auto const key = merovingian::crypto::derive_oauth_client_id_key_from_file(path.string());

            THEN("there is none")
            {
                CHECK_FALSE(key.has_value());
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
