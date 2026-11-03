// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/core/folded_substring.hpp"

#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

namespace merovingian::core
{
namespace
{

    [[nodiscard]] constexpr auto fold(char byte) noexcept -> char
    {
        return (byte >= 'A' && byte <= 'Z') ? static_cast<char>(byte - 'A' + 'a') : byte;
    }

} // namespace

FoldedSubstringMatcher::FoldedSubstringMatcher(std::string_view term)
{
    folded_.reserve(term.size());
    for (auto const byte : term)
    {
        folded_.push_back(fold(byte));
    }
    failure_.assign(folded_.size(), 0U);
    auto matched = std::size_t{0U};
    for (auto i = std::size_t{1U}; i < folded_.size(); ++i)
    {
        while (matched > 0U && folded_[matched] != folded_[i])
        {
            matched = failure_[matched - 1U];
        }
        if (folded_[matched] == folded_[i])
        {
            ++matched;
        }
        failure_[i] = matched;
    }
}

auto FoldedSubstringMatcher::contains(std::string_view text) -> bool
{
    if (folded_.empty())
    {
        return true;
    }
    auto matched = std::size_t{0U};
    for (auto const byte : text)
    {
        auto const folded_byte = fold(byte);
        ++steps_;
        // `matched` is always below the term's length here: a full match returns at once.
        while (matched > 0U && folded_[matched] != folded_byte)
        {
            matched = failure_[matched - 1U];
            ++steps_;
        }
        if (folded_[matched] == folded_byte)
        {
            ++matched;
        }
        if (matched == folded_.size())
        {
            return true;
        }
    }
    return false;
}

auto FoldedSubstringMatcher::count_non_overlapping(std::string_view text) -> std::size_t
{
    if (folded_.empty())
    {
        return 0U;
    }
    auto count = std::size_t{0U};
    auto matched = std::size_t{0U};
    for (auto const byte : text)
    {
        auto const folded_byte = fold(byte);
        ++steps_;
        while (matched > 0U && folded_[matched] != folded_byte)
        {
            matched = failure_[matched - 1U];
            ++steps_;
        }
        if (folded_[matched] == folded_byte)
        {
            ++matched;
        }
        if (matched == folded_.size())
        {
            ++count;
            matched = 0U; // the next occurrence starts after this one
        }
    }
    return count;
}

} // namespace merovingian::core
