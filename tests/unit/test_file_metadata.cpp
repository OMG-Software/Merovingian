// SPDX-License-Identifier: GPL-3.0-or-later

#include <merovingian/core/file_metadata.hpp>

#include <catch2/catch_test_macros.hpp>

TEST_CASE("Config file permission policy accepts regular non-executable files", "[core][file-metadata]")
{
    // Given
    auto metadata = merovingian::core::FileMetadata{};
    metadata.kind = merovingian::core::FileKind::regular;
    metadata.mode.owner_read = true;
    metadata.mode.owner_write = true;
    metadata.mode.group_read = true;

    // When / Then
    REQUIRE(merovingian::core::is_secure_config_file(metadata));
}

TEST_CASE("Config file permission policy rejects unsafe file kinds and modes", "[core][file-metadata]")
{
    // Given
    auto group_writable = merovingian::core::FileMetadata{};
    group_writable.kind = merovingian::core::FileKind::regular;
    group_writable.mode.group_write = true;

    auto other_writable = merovingian::core::FileMetadata{};
    other_writable.kind = merovingian::core::FileKind::regular;
    other_writable.mode.other_write = true;

    auto executable = merovingian::core::FileMetadata{};
    executable.kind = merovingian::core::FileKind::regular;
    executable.mode.owner_execute = true;

    auto symlink = merovingian::core::FileMetadata{};
    symlink.kind = merovingian::core::FileKind::symlink;

    // When / Then
    REQUIRE_FALSE(merovingian::core::is_secure_config_file(group_writable));
    REQUIRE_FALSE(merovingian::core::is_secure_config_file(other_writable));
    REQUIRE_FALSE(merovingian::core::is_secure_config_file(executable));
    REQUIRE_FALSE(merovingian::core::is_secure_config_file(symlink));
}

TEST_CASE("Secret file permission policy requires owner-only non-executable access", "[core][file-metadata]")
{
    // Given
    auto secure_secret = merovingian::core::FileMetadata{};
    secure_secret.kind = merovingian::core::FileKind::regular;
    secure_secret.mode.owner_read = true;
    secure_secret.mode.owner_write = true;

    auto group_readable = secure_secret;
    group_readable.mode.group_read = true;

    auto other_readable = secure_secret;
    other_readable.mode.other_read = true;

    auto executable = secure_secret;
    executable.mode.owner_execute = true;

    // When / Then
    REQUIRE(merovingian::core::is_secure_secret_file(secure_secret));
    REQUIRE_FALSE(merovingian::core::is_secure_secret_file(group_readable));
    REQUIRE_FALSE(merovingian::core::is_secure_secret_file(other_readable));
    REQUIRE_FALSE(merovingian::core::is_secure_secret_file(executable));
}
