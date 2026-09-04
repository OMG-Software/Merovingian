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
        // Owner-read only. owner_write was set here until 0.12.5, when the
        // check was tightened to match the owner-read-only rule
        // docs/hardening.md has always documented (audit finding 22).
        secure_secret.mode.owner_read = true;

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

// --- 0.12.5 security audit, finding 22 ---------------------------------------
//
// docs/hardening.md has always described secret files as owner-read-only, but
// is_secure_secret_file() never checked owner_write, so a 0600 file passed. The
// write bit matters because the service account is also the account a
// compromised worker runs as: leaving the master key writable lets an attacker
// with code execution substitute a key of their choosing.

SCENARIO("A secret file must be owner-read-only, not merely owner-only", "[platform][file_metadata][security]")
{
    GIVEN("file metadata differing only in the owner-write bit")
    {
        auto read_only = merovingian::platform::FileMetadata{};
        read_only.kind = merovingian::platform::FileKind::regular;
        read_only.mode.owner_read = true;

        auto owner_writable = read_only;
        owner_writable.mode.owner_write = true;

        WHEN("each is checked as a secret file")
        {
            auto const read_only_valid = merovingian::platform::is_secure_secret_file(read_only);
            auto const owner_writable_valid = merovingian::platform::is_secure_secret_file(owner_writable);

            THEN("only the owner-read-only file is accepted")
            {
                REQUIRE(read_only_valid);
                REQUIRE_FALSE(owner_writable_valid);
            }
        }
    }

    GIVEN("a config file with the owner-write bit set")
    {
        auto config_file = merovingian::platform::FileMetadata{};
        config_file.kind = merovingian::platform::FileKind::regular;
        config_file.mode.owner_read = true;
        config_file.mode.owner_write = true;

        WHEN("it is checked as a config file")
        {
            auto const valid = merovingian::platform::is_secure_config_file(config_file);

            THEN("it is still accepted: the stricter rule applies to secrets, not to config")
            {
                REQUIRE(valid);
            }
        }
    }
}
