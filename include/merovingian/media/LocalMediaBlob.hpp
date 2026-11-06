// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>

namespace merovingian::media
{

// ADR-0119: a blob's metadata. Its bytes live only in the database and are
// read per request (database::read_media_blob); there is deliberately no
// bytes member, so nothing can come to rely on them being in memory.
struct LocalMediaBlob final
{
    std::string storage_id{};
    std::string hash_algorithm{};
    std::string digest{};
    std::uint64_t size_bytes{0U};
    std::uint64_t ref_count{0U};
};

} // namespace merovingian::media
