// SPDX-License-Identifier: GPL-3.0-or-later

#include <merovingian/platform/file_metadata.hpp>

#include <catch2/catch_test_macros.hpp>

TEST_CASE("Config file permission policy accepts regular non-executable files", "[platform][file-metadata]")
{
    // Given
    auto metadata = merovingian::platform::FileMetadata{};
    metadata.kind = merovingian::platform::FileKind::regular;
    metadata.mode.owner_read = true;
    metadata.mode.owner_write = true;
    metadata.mode.group_read = true;

    // When / Then
    REQUIRE(merovingian::platform::is_secure_config_file(metadata));
}

TEST_CASE("Config file permission policy rejects unsafe file kinds and modes", "[platform][file-metadata]")
{
    // Given
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

    // When / Then
    REQUIRE_FALSE(merovingian::platform::is_secure_config_file(group_writable));
    REQUIRE_FALSE(merovingian::platform::is_secure_config_file(other_writable));
    REQUIRE_FALSE(merovingian::platform::is_secure_config_file(executable));
    REQUIRE_FALSE(merovingian::platform::is_secure_config_file(symlink));
}

TEST_CASE("Secret file permission policy requires owner-only non-executable access", "[platform][file-metadata]")
{
    // Given
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

    // When / Then
    REQUIRE(merovingian::platform::is_secure_secret_file(secure_secret));
    REQUIRE_FALSE(merovingian::platform::is_secure_secret_file(group_readable));
    REQUIRE_FALSE(merovingian::platform::is_secure_secret_file(other_readable));
    REQUIRE_FALSE(merovingian::platform::is_secure_secret_file(executable));
}
