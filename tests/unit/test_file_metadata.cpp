// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/platform/file_metadata.hpp"

#include <catch2/catch_test_macros.hpp>

SCENARIO("Config file permission policy accepts regular non-executable files", "[platform][file-metadata]")
{
    GIVEN("regular config file metadata with readable owner and group permissions")
    {
        auto metadata = merovingian::platform::FileMetadata{};
        metadata.kind = merovingian::platform::FileKind::regular;
        metadata.mode.owner_read = true;
        metadata.mode.owner_write = true;
        metadata.mode.group_read = true;

        WHEN("the config file permission policy is evaluated")
        {
            auto const secure = merovingian::platform::is_secure_config_file(metadata);

            THEN("the metadata is accepted")
            {
                REQUIRE(secure);
            }
        }
    }
}

SCENARIO("Config file permission policy rejects unsafe file kinds and modes", "[platform][file-metadata]")
{
    GIVEN("unsafe config file metadata variants")
    {
        auto group_writable = merovingian::platform::FileMetadata{};
        group_writable.kind = merovingian::platform::FileKind::regular;
        group_writable.mode.group_write = true;

        auto other_writable = merovingian::platform::FileMetadata{};
        other_writable.kind = merovingian::platform::FileKind::regular;
        other_writable.mode.other_write = true;

        auto executable = merovingian::platform::FileMetadata{};
        executable.kind = merovingian::platform::FileKind::regular;
        executable.mode.owner_execute = true;

        auto symlink = merovingian::platform::FileMetadata{};
        symlink.kind = merovingian::platform::FileKind::symlink;

        WHEN("the config file permission policy is evaluated")
        {
            auto const group_writable_secure = merovingian::platform::is_secure_config_file(group_writable);
            auto const other_writable_secure = merovingian::platform::is_secure_config_file(other_writable);
            auto const executable_secure = merovingian::platform::is_secure_config_file(executable);
            auto const symlink_secure = merovingian::platform::is_secure_config_file(symlink);

            THEN("all unsafe variants are rejected")
            {
                REQUIRE_FALSE(group_writable_secure);
                REQUIRE_FALSE(other_writable_secure);
                REQUIRE_FALSE(executable_secure);
                REQUIRE_FALSE(symlink_secure);
            }
        }
    }
}

SCENARIO("Secret file permission policy requires owner-only non-executable access", "[platform][file-metadata]")
{
    GIVEN("secret file metadata variants")
    {
        auto secure_secret = merovingian::platform::FileMetadata{};
        secure_secret.kind = merovingian::platform::FileKind::regular;
        secure_secret.mode.owner_read = true;
        secure_secret.mode.owner_write = true;

        auto group_readable = secure_secret;
        group_readable.mode.group_read = true;

        auto other_readable = secure_secret;
        other_readable.mode.other_read = true;

        auto executable = secure_secret;
        executable.mode.owner_execute = true;

        WHEN("the secret file permission policy is evaluated")
        {
            auto const secure_secret_valid = merovingian::platform::is_secure_secret_file(secure_secret);
            auto const group_readable_valid = merovingian::platform::is_secure_secret_file(group_readable);
            auto const other_readable_valid = merovingian::platform::is_secure_secret_file(other_readable);
            auto const executable_valid = merovingian::platform::is_secure_secret_file(executable);

            THEN("only the owner-only non-executable metadata is accepted")
            {
                REQUIRE(secure_secret_valid);
                REQUIRE_FALSE(group_readable_valid);
                REQUIRE_FALSE(other_readable_valid);
                REQUIRE_FALSE(executable_valid);
            }
        }
    }
}
