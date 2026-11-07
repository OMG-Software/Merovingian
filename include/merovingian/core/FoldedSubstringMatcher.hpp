// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

namespace merovingian::core
{

// The longest search term, in bytes, that POST /search, POST /publicRooms and POST /user_directory/search
// accept (ADR-0330). The Matrix v1.19 spec gives `search_term` and `generic_search_term` no length limit; a
// longer one is refused with `400 M_TOO_LARGE`, never truncated, because a truncated term returns wrong
// results.
inline constexpr std::size_t max_search_term_bytes = 1024U;

// Finds a term inside byte strings, ignoring ASCII case, in time linear in the text it is given however
// the term and the text are chosen (Knuth-Morris-Pratt over case-folded bytes). std::string_view::find and
// std::search are O(text * term) in the worst case, and these searches run on text a client chose, with
// the runtime lock held (ADR-0330).
//
// Folding is ASCII only: 'A'-'Z' become 'a'-'z' and every other byte compares as itself, so UTF-8 text is
// compared byte for byte. A matcher is built once per request for the term and reused for every text.
class FoldedSubstringMatcher final
{
public:
    explicit FoldedSubstringMatcher(std::string_view term);

    // True when `text` holds the term in any case. An empty term is held by every text.
    [[nodiscard]] auto contains(std::string_view text) -> bool;

    // The number of non-overlapping occurrences of the term in `text`, left to right; 0 for an empty term.
    [[nodiscard]] auto count_non_overlapping(std::string_view text) -> std::size_t;

    // The comparison steps taken over every text so far: one per byte of text consumed plus one per
    // fall-back along the failure table. Never more than twice the bytes of text searched, which is what
    // makes the search linear; building the matcher is not counted.
    [[nodiscard]] auto steps() const noexcept -> std::size_t
    {
        return steps_;
    }

private:
    // The term, folded to lower case.
    std::string folded_;
    // failure_[i]: the length of the longest proper prefix of folded_[0..i] that is also its suffix.
    std::vector<std::size_t> failure_;
    std::size_t steps_{0U};
};

} // namespace merovingian::core
