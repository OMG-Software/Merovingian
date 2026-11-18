// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/oauth/PageForm.hpp"

#include <algorithm>

namespace merovingian::oauth
{

PageForm::PageForm(PagePath action)
    : m_action{action}
{
}

auto PageForm::hidden(HtmlName name, HtmlText value) -> void
{
    m_hidden.emplace_back(name, std::move(value));
}

auto PageForm::input(TextInput input) -> bool
{
    if (input.concealed && input.value.has_value())
    {
        return false;
    }
    m_inputs.push_back(std::move(input));
    return true;
}

auto PageForm::button(SubmitButton button) -> bool
{
    if (m_buttons.size() >= max_buttons)
    {
        return false;
    }
    auto const repeats = std::ranges::any_of(m_buttons, [&button](SubmitButton const& earlier) {
        return earlier.name.view() == button.name.view() && earlier.value.view() == button.value.view();
    });
    if (repeats)
    {
        return false;
    }
    m_buttons.push_back(std::move(button));
    return true;
}

auto PageForm::has_button() const noexcept -> bool
{
    return !m_buttons.empty();
}

auto PageForm::html() const -> std::string
{
    auto html = std::string{"<form method=\"post\" action=\""};
    html.append(m_action.view());
    html.append("\">\n");
    for (auto const& [name, value] : m_hidden)
    {
        html.append("<input type=\"hidden\" name=\"");
        html.append(name.view());
        html.append("\" value=\"");
        html.append(value.html());
        html.append("\">\n");
    }
    for (auto const& input : m_inputs)
    {
        html.append("<label for=\"field-");
        html.append(input.name.view());
        html.append("\">");
        html.append(input.label.html());
        html.append("</label>\n<input type=\"");
        html.append(input.concealed ? "password" : "text");
        html.append("\" id=\"field-");
        html.append(input.name.view());
        html.append("\" name=\"");
        html.append(input.name.view());
        html.append("\" autocomplete=\"");
        html.append(input.autocomplete.view());
        html.append("\"");
        if (input.value.has_value())
        {
            html.append(" value=\"");
            html.append(input.value->html());
            html.append("\"");
        }
        html.append(" required>\n");
    }
    html.append("<div class=\"buttons\">\n");
    for (auto const& button : m_buttons)
    {
        html.append("<button type=\"submit\" name=\"");
        html.append(button.name.view());
        html.append("\" value=\"");
        html.append(button.value.view());
        html.append("\">");
        html.append(button.label.html());
        html.append("</button>\n");
    }
    html.append("</div>\n</form>\n");
    return html;
}

} // namespace merovingian::oauth
