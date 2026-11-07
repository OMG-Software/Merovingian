// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/platform/FileMetadata.hpp"

#include <optional>
#include <string>

namespace merovingian::platform
{

struct FileMetadataResult final
{
    std::optional<FileMetadata> metadata{};
    std::string error{};
};

} // namespace merovingian::platform
