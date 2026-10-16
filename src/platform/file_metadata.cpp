// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/platform/file_metadata.hpp"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <new>
#include <string>
#include <utility>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

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
            (mode & S_IRUSR) != 0, (mode & S_IWUSR) != 0, (mode & S_IXUSR) != 0,
            (mode & S_IRGRP) != 0, (mode & S_IWGRP) != 0, (mode & S_IXGRP) != 0,
            (mode & S_IROTH) != 0, (mode & S_IWOTH) != 0, (mode & S_IXOTH) != 0,
        };
    }

    [[nodiscard]] auto has_execute_bit(PosixFileMode const& mode) noexcept -> bool
    {
        return mode.owner_execute || mode.group_execute || mode.other_execute;
    }

} // namespace

auto open_secure_secret_file(std::string_view path) -> std::optional<core::FileDescriptor>
{
    if (path.empty() || path.find('\0') != std::string_view::npos)
    {
        errno = EINVAL;
        return std::nullopt;
    }
    auto file = core::FileDescriptor{::open(std::string{path}.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)};
    if (!file.valid())
    {
        return std::nullopt;
    }
    struct stat info
    {
    };
    if (::fstat(file.get(), &info) != 0 || !S_ISREG(info.st_mode) || info.st_uid != ::geteuid() ||
        (info.st_mode & 07777) != 0400)
    {
        errno = EACCES;
        return std::nullopt;
    }
    return file;
}

auto read_secure_secret_file(core::FileDescriptor const& file,
                             std::size_t max_bytes) -> std::optional<core::SecretBuffer>
try
{
    struct stat info
    {
    };
    if (!file.valid() || ::fstat(file.get(), &info) != 0 || !S_ISREG(info.st_mode) || info.st_uid != ::geteuid() ||
        (info.st_mode & 07777) != 0400 || info.st_size <= 0 || static_cast<std::uintmax_t>(info.st_size) > max_bytes)
    {
        return std::nullopt;
    }
    auto secret = core::SecretBuffer{static_cast<std::size_t>(info.st_size)};
    if (!secret.is_locked())
    {
        return std::nullopt;
    }
    auto total = std::size_t{0U};
    while (total < secret.bytes().size())
    {
        auto const count = ::read(file.get(), secret.bytes().data() + total, secret.bytes().size() - total);
        if (count < 0 && errno == EINTR)
        {
            continue;
        }
        if (count <= 0)
        {
            return std::nullopt;
        }
        total += static_cast<std::size_t>(count);
    }
    // A growing file must not be silently truncated at its original stat size.
    auto extra = core::SecretBuffer{1U};
    if (!extra.is_locked())
    {
        return std::nullopt;
    }
    auto count = ssize_t{};
    do
    {
        count = ::read(file.get(), extra.bytes().data(), 1U);
    } while (count < 0 && errno == EINTR);
    if (count != 0)
    {
        return std::nullopt;
    }
    return secret;
}
catch (std::bad_alloc const&)
{
    return std::nullopt;
}

auto read_secure_secret_file(std::string_view path, std::size_t max_bytes) -> std::optional<core::SecretBuffer>
{
    auto const file = open_secure_secret_file(path);
    if (!file)
    {
        return std::nullopt;
    }
    return read_secure_secret_file(*file, max_bytes);
}

auto read_secure_secret_line(std::string_view path, std::size_t max_bytes) -> std::optional<core::SecretBuffer>
try
{
    auto file = read_secure_secret_file(path, max_bytes);
    if (!file)
    {
        return std::nullopt;
    }
    auto line = file->bytes();
    auto const newline = std::find(line.begin(), line.end(), static_cast<std::uint8_t>('\n'));
    line = line.first(static_cast<std::size_t>(newline - line.begin()));
    while (!line.empty() && line.back() == '\r')
    {
        line = line.first(line.size() - 1U);
    }
    if (line.empty() || std::find(line.begin(), line.end(), 0U) != line.end())
    {
        return std::nullopt;
    }
    auto secret = core::SecretBuffer{line};
    if (!secret.is_locked())
    {
        return std::nullopt;
    }
    return secret;
}
catch (std::bad_alloc const&)
{
    return std::nullopt;
}

auto read_posix_file_metadata(std::string const& path) -> FileMetadataResult
{
    struct stat stat_buffer{};
    if (::lstat(path.c_str(), &stat_buffer) != 0)
    {
        if (errno == ENOENT)
        {
            return {
                FileMetadata{FileKind::missing, {}},
                {}
            };
        }

        return {{}, std::strerror(errno)};
    }

    return {
        FileMetadata{to_file_kind(stat_buffer.st_mode), to_file_mode(stat_buffer.st_mode)},
        {}
    };
}

auto is_secure_config_file(FileMetadata const& metadata) noexcept -> bool
{
    return metadata.kind == FileKind::regular && !metadata.mode.group_write && !metadata.mode.other_write &&
           !has_execute_bit(metadata.mode);
}

auto is_secure_secret_file(FileMetadata const& metadata) noexcept -> bool
{
    // Owner-read-only, as docs/hardening.md has always specified. 0.12.5 audit,
    // finding 22: owner_write was not checked, so a 0600 secret was accepted
    // despite the documented rule. The write bit matters because the service
    // account is also the account a compromised worker runs as: leaving it
    // writable lets an attacker who reaches code execution substitute a master
    // key of their choosing and then decrypt or re-sign at will. 0400 costs an
    // operator nothing — the file is never written after provisioning.
    return metadata.kind == FileKind::regular && metadata.mode.owner_read && !metadata.mode.owner_write &&
           !metadata.mode.group_read && !metadata.mode.group_write && !metadata.mode.group_execute &&
           !metadata.mode.other_read && !metadata.mode.other_write && !metadata.mode.other_execute &&
           !has_execute_bit(metadata.mode);
}

} // namespace merovingian::platform
