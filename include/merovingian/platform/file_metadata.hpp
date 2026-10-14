// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/core/file_descriptor.hpp"
#include "merovingian/core/secret_buffer.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace merovingian::platform
{

enum class FileKind : std::uint8_t
{
    missing,
    regular,
    directory,
    symlink,
    other,
};

struct PosixFileMode final
{
    bool owner_read{false};
    bool owner_write{false};
    bool owner_execute{false};
    bool group_read{false};
    bool group_write{false};
    bool group_execute{false};
    bool other_read{false};
    bool other_write{false};
    bool other_execute{false};
};

struct FileMetadata final
{
    FileKind kind{FileKind::missing};
    PosixFileMode mode{};
};

struct FileMetadataResult final
{
    std::optional<FileMetadata> metadata{};
    std::string error{};
};

// Validate the opened object, not a path inspected before opening. The caller
// may read or identify the same descriptor without reopening a replaceable path.
[[nodiscard]] auto open_secure_secret_file(std::string_view path) -> std::optional<core::FileDescriptor>;
[[nodiscard]] auto read_secure_secret_file(core::FileDescriptor const& file,
                                           std::size_t max_bytes) -> std::optional<core::SecretBuffer>;
[[nodiscard]] auto read_secure_secret_file(std::string_view path,
                                           std::size_t max_bytes) -> std::optional<core::SecretBuffer>;
// Bounded text-file variant: first line only, CRLF stripped, empty/NUL refused.
[[nodiscard]] auto read_secure_secret_line(std::string_view path,
                                           std::size_t max_bytes) -> std::optional<core::SecretBuffer>;

[[nodiscard]] auto read_posix_file_metadata(std::string const& path) -> FileMetadataResult;
[[nodiscard]] auto is_secure_config_file(FileMetadata const& metadata) noexcept -> bool;
[[nodiscard]] auto is_secure_secret_file(FileMetadata const& metadata) noexcept -> bool;

} // namespace merovingian::platform
