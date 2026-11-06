// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>

namespace merovingian::database
{

// A blob's reference count after a change, and whether its bytes are cleared
// because nothing references it any more.
struct PersistentBlobReferenceCount final
{
    std::string storage_id{};
    std::uint64_t ref_count{0U};
};

} // namespace merovingian::database
