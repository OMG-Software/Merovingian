// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/core/Error.hpp"
#include "merovingian/core/LibraryVersion.hpp"

#include <optional>
#include <vector>

namespace merovingian::media
{

// The worker's library report, or why there is none. Not std::expected: this project's toolchain
// does not build <expected> cleanly (see AppserviceRegistrationParseResult).
struct ThumbnailWorkerLibraries final
{
    std::optional<std::vector<core::LibraryVersion>> libraries{};
    core::Error error{};
};

} // namespace merovingian::media
