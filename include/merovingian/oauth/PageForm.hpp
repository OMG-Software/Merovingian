// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/oauth/HtmlName.hpp"
#include "merovingian/oauth/HtmlText.hpp"
#include "merovingian/oauth/PagePath.hpp"
#include "merovingian/oauth/SubmitButton.hpp"
#include "merovingian/oauth/TextInput.hpp"

#include <cstddef>
#include <string>
#include <utility>
#include <vector>

namespace merovingian::oauth
{

// A form a page posts to a fixed path on this server (`method="post"`): hidden fields, then labelled inputs, then
// one or two submit buttons (ADR-0772). Every part is HtmlText or a compile-time name, so nothing unescaped can
// reach the markup.
class PageForm final
{
public:
    // The most submit buttons: approve and deny.
    static constexpr std::size_t max_buttons = 2U;

    explicit PageForm(PagePath action);

    // A hidden field, such as the pending authorisation ID or the form token.
    auto hidden(HtmlName name, HtmlText value) -> void;
    // A labelled input. False, and nothing added, when a concealed input carries a value.
    [[nodiscard]] auto input(TextInput input) -> bool;
    // A submit button. False, and nothing added, for a third button or one whose name and value pair repeats an
    // earlier button's.
    [[nodiscard]] auto button(SubmitButton button) -> bool;

    // Whether the form has a button, without which Page::form refuses it.
    [[nodiscard]] auto has_button() const noexcept -> bool;
    // The form's markup.
    [[nodiscard]] auto html() const -> std::string;

private:
    PagePath m_action;
    std::vector<std::pair<HtmlName, HtmlText>> m_hidden{};
    std::vector<TextInput> m_inputs{};
    std::vector<SubmitButton> m_buttons{};
};

} // namespace merovingian::oauth
