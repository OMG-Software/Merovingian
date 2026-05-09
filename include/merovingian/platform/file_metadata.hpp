// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <optional>
#include <string>

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

[[nodiscard]] auto read_posix_file_metadata(std::string const& path) -> FileMetadataResult;
[[nodiscard]] auto is_secure_config_file(FileMetadata const& metadata) noexcept -> bool;
[[nodiscard]] auto is_secure_secret_file(FileMetadata const& metadata) noexcept -> bool;

} // namespace merovingian::platform
