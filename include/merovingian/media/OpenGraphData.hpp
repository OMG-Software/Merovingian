// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>
#include <utility>
#include <vector>

namespace merovingian::media
{

struct OpenGraphData final
{
    // `og:*` properties in document order; the first value of a key wins.
    // Keys are lower-cased. Values are entity-decoded, valid UTF-8, without
    // control characters, trimmed, and at most max_open_graph_value_bytes.
    std::vector<std::pair<std::string, std::string>> properties{};
    // The document's first <title>, cleaned the same way; empty when none.
    std::string title{};
};

} // namespace merovingian::media
