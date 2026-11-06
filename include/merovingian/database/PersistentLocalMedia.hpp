// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>

namespace merovingian::database
{

struct PersistentLocalMedia final
{
    std::string media_id{};
    std::string owner_user_id{};
    std::string content_type{};
    std::uint64_t size_bytes{0U};
    std::string hash_algorithm{};
    std::string digest{};
    bool quarantined{false};
    bool removed{false};
    // See media::LocalMediaRecord::legacy_endpoint_visible.
    bool legacy_endpoint_visible{true};
    // Migration 026 (ADR-0211): the `filename` the upload was made with (or the remote
    // server's Content-Disposition filename), empty when none was given.
    std::string upload_name{};
};

} // namespace merovingian::database
