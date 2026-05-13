// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/platform/file_metadata.hpp"

#include <cerrno>
#include <cstring>
#include <string>
#include <sys/stat.h>

namespace merovingian::platform
{
namespace
{

[[nodiscard]] auto to_file_kind(mode_t mode) noexcept -> FileKind
{
    if (S_ISREG(mode))
    {
        return FileKind::regular;
    }

    if (S_ISDIR(mode))
    {
        return FileKind::directory;
    }

    if (S_ISLNK(mode))
    {
        return FileKind::symlink;
    }

    return FileKind::other;
}

[[nodiscard]] auto to_file_mode(mode_t mode) noexcept -> PosixFileMode
{
    return {
        (mode & S_IRUSR) != 0,
        (mode & S_IWUSR) != 0,
        (mode & S_IXUSR) != 0,
        (mode & S_IRGRP) != 0,
        (mode & S_IWGRP) != 0,
        (mode & S_IXGRP) != 0,
        (mode & S_IROTH) != 0,
        (mode & S_IWOTH) != 0,
        (mode & S_IXOTH) != 0,
    };
}

[[nodiscard]] auto has_execute_bit(PosixFileMode const& mode) noexcept -> bool
{
    return mode.owner_execute || mode.group_execute || mode.other_execute;
}

} // namespace

auto read_posix_file_metadata(std::string const& path) -> FileMetadataResult
{
    struct stat stat_buffer{};
    if (::lstat(path.c_str(), &stat_buffer) != 0)
    {
        if (errno == ENOENT)
        {
            return {FileMetadata{FileKind::missing, {}}, {}};
        }

        return {{}, std::strerror(errno)};
    }

    return {FileMetadata{to_file_kind(stat_buffer.st_mode), to_file_mode(stat_buffer.st_mode)}, {}};
}

auto is_secure_config_file(FileMetadata const& metadata) noexcept -> bool
{
    return metadata.kind == FileKind::regular && !metadata.mode.group_write && !metadata.mode.other_write
        && !has_execute_bit(metadata.mode);
}

auto is_secure_secret_file(FileMetadata const& metadata) noexcept -> bool
{
    return metadata.kind == FileKind::regular && !metadata.mode.group_read && !metadata.mode.group_write
        && !metadata.mode.group_execute && !metadata.mode.other_read && !metadata.mode.other_write
        && !metadata.mode.other_execute && !has_execute_bit(metadata.mode);
}

} // namespace merovingian::platform
