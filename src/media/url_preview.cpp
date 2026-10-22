// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/media/url_preview.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <string>
#include <string_view>
#include <utility>

namespace merovingian::media
{
namespace
{

    [[nodiscard]] auto lower(char c) noexcept -> char
    {
        return c >= 'A' && c <= 'Z' ? static_cast<char>(c - 'A' + 'a') : c;
    }

    [[nodiscard]] auto lowered(std::string_view text) -> std::string
    {
        auto out = std::string{text};
        std::ranges::transform(out, out.begin(), lower);
        return out;
    }

    [[nodiscard]] auto starts_with_ci(std::string_view text, std::string_view prefix_lower) noexcept -> bool
    {
        if (text.size() < prefix_lower.size())
        {
            return false;
        }
        for (auto index = std::size_t{0U}; index < prefix_lower.size(); ++index)
        {
            if (lower(text[index]) != prefix_lower[index])
            {
                return false;
            }
        }
        return true;
    }

    // Forward search for a short lower-case needle, case-insensitively. The
    // needles are a few bytes long, so this stays linear in the input.
    [[nodiscard]] auto find_ci(std::string_view text, std::string_view needle_lower, std::size_t from) noexcept
        -> std::size_t
    {
        if (needle_lower.empty() || text.size() < needle_lower.size())
        {
            return std::string_view::npos;
        }
        for (auto index = from; index + needle_lower.size() <= text.size(); ++index)
        {
            if (starts_with_ci(text.substr(index), needle_lower))
            {
                return index;
            }
        }
        return std::string_view::npos;
    }

    [[nodiscard]] auto is_space(char c) noexcept -> bool
    {
        return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f';
    }

    [[nodiscard]] auto is_name_char(char c) noexcept -> bool
    {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == ':' ||
               c == '_';
    }

    auto append_utf8(std::string& out, std::uint32_t code_point) -> void
    {
        if (code_point < 0x80U)
        {
            out += static_cast<char>(code_point);
        }
        else if (code_point < 0x800U)
        {
            out += static_cast<char>(0xC0U | (code_point >> 6U));
            out += static_cast<char>(0x80U | (code_point & 0x3FU));
        }
        else if (code_point < 0x10000U)
        {
            out += static_cast<char>(0xE0U | (code_point >> 12U));
            out += static_cast<char>(0x80U | ((code_point >> 6U) & 0x3FU));
            out += static_cast<char>(0x80U | (code_point & 0x3FU));
        }
        else
        {
            out += static_cast<char>(0xF0U | (code_point >> 18U));
            out += static_cast<char>(0x80U | ((code_point >> 12U) & 0x3FU));
            out += static_cast<char>(0x80U | ((code_point >> 6U) & 0x3FU));
            out += static_cast<char>(0x80U | (code_point & 0x3FU));
        }
    }

    // One character reference starting at text[0] == '&'. Returns the bytes
    // consumed (0 when it is not a reference this decoder knows).
    [[nodiscard]] auto decode_reference(std::string_view text, std::string& out) -> std::size_t
    {
        constexpr auto max_reference = std::size_t{10U};
        auto const end = text.substr(0U, std::min(text.size(), max_reference)).find(';');
        if (end == std::string_view::npos || end < 2U)
        {
            return 0U;
        }
        auto const name = text.substr(1U, end - 1U);
        if (name.front() == '#')
        {
            auto const hex = name.size() > 1U && (name[1] == 'x' || name[1] == 'X');
            auto const digits = name.substr(hex ? 2U : 1U);
            if (digits.empty())
            {
                return 0U;
            }
            auto value = std::uint32_t{0U};
            for (auto const c : digits)
            {
                auto digit = 0U;
                if (c >= '0' && c <= '9')
                {
                    digit = static_cast<unsigned>(c - '0');
                }
                else if (hex && lower(c) >= 'a' && lower(c) <= 'f')
                {
                    digit = static_cast<unsigned>(lower(c) - 'a' + 10);
                }
                else
                {
                    return 0U;
                }
                value = value * (hex ? 16U : 10U) + digit;
                if (value > 0x10FFFFU)
                {
                    return 0U;
                }
            }
            if (value == 0U || (value >= 0xD800U && value <= 0xDFFFU))
            {
                return 0U;
            }
            append_utf8(out, value);
            return end + 1U;
        }
        auto const known = lowered(name);
        if (known == "amp")
        {
            out += '&';
        }
        else if (known == "lt")
        {
            out += '<';
        }
        else if (known == "gt")
        {
            out += '>';
        }
        else if (known == "quot")
        {
            out += '"';
        }
        else if (known == "apos")
        {
            out += '\'';
        }
        else if (known == "nbsp")
        {
            out += ' ';
        }
        else
        {
            return 0U;
        }
        return end + 1U;
    }

    [[nodiscard]] auto utf8_valid(std::string_view text) noexcept -> bool
    {
        auto index = std::size_t{0U};
        while (index < text.size())
        {
            auto const lead = static_cast<unsigned char>(text[index]);
            auto length = std::size_t{1U};
            auto minimum = std::uint32_t{0U};
            auto code_point = std::uint32_t{lead};
            if (lead >= 0x80U)
            {
                if ((lead & 0xE0U) == 0xC0U)
                {
                    length = 2U;
                    minimum = 0x80U;
                    code_point = lead & 0x1FU;
                }
                else if ((lead & 0xF0U) == 0xE0U)
                {
                    length = 3U;
                    minimum = 0x800U;
                    code_point = lead & 0x0FU;
                }
                else if ((lead & 0xF8U) == 0xF0U)
                {
                    length = 4U;
                    minimum = 0x10000U;
                    code_point = lead & 0x07U;
                }
                else
                {
                    return false;
                }
                if (index + length > text.size())
                {
                    return false;
                }
                for (auto offset = std::size_t{1U}; offset < length; ++offset)
                {
                    auto const continuation = static_cast<unsigned char>(text[index + offset]);
                    if ((continuation & 0xC0U) != 0x80U)
                    {
                        return false;
                    }
                    code_point = (code_point << 6U) | (continuation & 0x3FU);
                }
                if (code_point < minimum || code_point > 0x10FFFFU || (code_point >= 0xD800U && code_point <= 0xDFFFU))
                {
                    return false;
                }
            }
            index += length;
        }
        return true;
    }

    // Entity-decodes `raw`, turns control characters and runs of whitespace
    // into one space, trims, and cuts the result to `max_bytes` on a UTF-8
    // boundary. Returns empty when the text is not valid UTF-8. Only the
    // first 4 * max_bytes bytes of `raw` are read.
    [[nodiscard]] auto clean_text(std::string_view raw, std::size_t max_bytes) -> std::string
    {
        raw = raw.substr(0U, std::min(raw.size(), max_bytes * 4U));
        auto decoded = std::string{};
        decoded.reserve(raw.size());
        for (auto index = std::size_t{0U}; index < raw.size();)
        {
            if (raw[index] == '&')
            {
                if (auto const consumed = decode_reference(raw.substr(index), decoded); consumed > 0U)
                {
                    index += consumed;
                    continue;
                }
            }
            decoded += raw[index];
            ++index;
        }
        auto out = std::string{};
        out.reserve(decoded.size());
        auto pending_space = false;
        for (auto const c : decoded)
        {
            auto const byte = static_cast<unsigned char>(c);
            if (byte < 0x20U || byte == 0x7FU || c == ' ')
            {
                pending_space = !out.empty();
                continue;
            }
            if (pending_space)
            {
                out += ' ';
                pending_space = false;
            }
            out += c;
        }
        if (out.size() > max_bytes)
        {
            auto cut = max_bytes;
            while (cut > 0U && (static_cast<unsigned char>(out[cut]) & 0xC0U) == 0x80U)
            {
                --cut;
            }
            out.resize(cut);
        }
        return utf8_valid(out) ? out : std::string{};
    }

    // The position of the '>' that closes a tag whose attributes start at
    // `from`, skipping quoted values; npos when the tag is not closed.
    [[nodiscard]] auto find_tag_end(std::string_view html, std::size_t from) noexcept -> std::size_t
    {
        auto quote = '\0';
        for (auto index = from; index < html.size(); ++index)
        {
            auto const c = html[index];
            if (quote != '\0')
            {
                if (c == quote)
                {
                    quote = '\0';
                }
                continue;
            }
            if (c == '"' || c == '\'')
            {
                quote = c;
            }
            else if (c == '>')
            {
                return index;
            }
        }
        return std::string_view::npos;
    }

    struct MetaAttributes final
    {
        std::string property{};
        std::string name{};
        std::string_view content{};
        bool has_content{false};
    };

    [[nodiscard]] auto parse_meta_attributes(std::string_view attributes) -> MetaAttributes
    {
        auto meta = MetaAttributes{};
        auto index = std::size_t{0U};
        while (index < attributes.size())
        {
            while (index < attributes.size() && (is_space(attributes[index]) || attributes[index] == '/'))
            {
                ++index;
            }
            auto const name_start = index;
            while (index < attributes.size() && !is_space(attributes[index]) && attributes[index] != '=' &&
                   attributes[index] != '/')
            {
                ++index;
            }
            auto const attribute = lowered(attributes.substr(name_start, index - name_start));
            while (index < attributes.size() && is_space(attributes[index]))
            {
                ++index;
            }
            auto value = std::string_view{};
            if (index < attributes.size() && attributes[index] == '=')
            {
                ++index;
                while (index < attributes.size() && is_space(attributes[index]))
                {
                    ++index;
                }
                if (index < attributes.size() && (attributes[index] == '"' || attributes[index] == '\''))
                {
                    auto const quote = attributes[index];
                    auto const close = attributes.find(quote, index + 1U);
                    auto const value_end = close == std::string_view::npos ? attributes.size() : close;
                    value = attributes.substr(index + 1U, value_end - index - 1U);
                    index = value_end == attributes.size() ? value_end : value_end + 1U;
                }
                else
                {
                    auto const value_start = index;
                    while (index < attributes.size() && !is_space(attributes[index]))
                    {
                        ++index;
                    }
                    value = attributes.substr(value_start, index - value_start);
                }
            }
            if (attribute.empty())
            {
                ++index;
                continue;
            }
            if (attribute == "property")
            {
                meta.property = lowered(value.substr(0U, std::min(value.size(), max_open_graph_key_bytes + 1U)));
            }
            else if (attribute == "name")
            {
                meta.name = lowered(value.substr(0U, std::min(value.size(), max_open_graph_key_bytes + 1U)));
            }
            else if (attribute == "content")
            {
                meta.content = value;
                meta.has_content = true;
            }
        }
        return meta;
    }

    [[nodiscard]] auto origin_of(std::string_view url) -> std::string_view
    {
        auto const scheme_end = url.find("://");
        if (scheme_end == std::string_view::npos)
        {
            return {};
        }
        auto const authority_end = url.find_first_of("/?#", scheme_end + 3U);
        return url.substr(0U, authority_end == std::string_view::npos ? url.size() : authority_end);
    }

} // namespace

auto extract_open_graph(std::string_view html) -> OpenGraphData
{
    auto data = OpenGraphData{};
    auto total_bytes = std::size_t{0U};
    auto position = std::size_t{0U};
    while (position < html.size())
    {
        auto const open = html.find('<', position);
        if (open == std::string_view::npos)
        {
            break;
        }
        if (html.substr(open, 4U) == "<!--")
        {
            auto const close = html.find("-->", open + 4U);
            if (close == std::string_view::npos)
            {
                break;
            }
            position = close + 3U;
            continue;
        }
        auto name_end = open + 1U;
        while (name_end < html.size() && is_name_char(html[name_end]))
        {
            ++name_end;
        }
        if (name_end == open + 1U)
        {
            position = open + 1U;
            continue;
        }
        auto const tag = lowered(html.substr(open + 1U, name_end - open - 1U));
        auto const tag_end = find_tag_end(html, name_end);
        if (tag_end == std::string_view::npos)
        {
            break;
        }
        position = tag_end + 1U;
        if (tag == "script" || tag == "style")
        {
            // Their contents are not markup: a <meta> inside a script is text.
            auto const close = find_ci(html, tag == "script" ? "</script" : "</style", position);
            if (close == std::string_view::npos)
            {
                break;
            }
            position = close + 2U + tag.size();
            continue;
        }
        if (tag == "title")
        {
            auto const close = find_ci(html, "</title", position);
            if (close == std::string_view::npos)
            {
                break;
            }
            if (data.title.empty())
            {
                data.title = clean_text(html.substr(position, close - position), max_open_graph_value_bytes);
            }
            position = close + 7U;
            continue;
        }
        if (tag != "meta" || data.properties.size() >= max_open_graph_properties)
        {
            continue;
        }
        auto const meta = parse_meta_attributes(html.substr(name_end, tag_end - name_end));
        auto const& key = meta.property.empty() ? meta.name : meta.property;
        if (!meta.has_content || key.size() <= 3U || key.size() > max_open_graph_key_bytes || !key.starts_with("og:") ||
            !std::ranges::all_of(key, is_name_char))
        {
            continue;
        }
        if (std::ranges::any_of(data.properties, [&key](auto const& property) {
                return property.first == key;
            }))
        {
            continue;
        }
        auto value = clean_text(meta.content, max_open_graph_value_bytes);
        if (value.empty() || total_bytes + key.size() + value.size() > max_open_graph_total_bytes)
        {
            continue;
        }
        total_bytes += key.size() + value.size();
        data.properties.emplace_back(key, std::move(value));
    }
    return data;
}

auto content_type_is_html(std::string_view content_type) noexcept -> bool
{
    auto const semicolon = content_type.find(';');
    auto essence = content_type.substr(0U, semicolon);
    while (!essence.empty() && is_space(essence.back()))
    {
        essence.remove_suffix(1U);
    }
    while (!essence.empty() && is_space(essence.front()))
    {
        essence.remove_prefix(1U);
    }
    return (essence.size() == 9U && starts_with_ci(essence, "text/html")) ||
           (essence.size() == 21U && starts_with_ci(essence, "application/xhtml+xml"));
}

auto resolve_preview_reference(std::string_view base_url, std::string_view reference) -> std::string
{
    while (!reference.empty() && is_space(reference.front()))
    {
        reference.remove_prefix(1U);
    }
    while (!reference.empty() && is_space(reference.back()))
    {
        reference.remove_suffix(1U);
    }
    // A fragment is never sent to the server.
    reference = reference.substr(0U, reference.find('#'));
    if (reference.empty() || reference.size() > max_preview_url_bytes)
    {
        return {};
    }
    if (starts_with_ci(reference, "https://") || starts_with_ci(reference, "http://"))
    {
        return std::string{reference};
    }
    auto const origin = origin_of(base_url);
    if (origin.empty())
    {
        return {};
    }
    if (reference.starts_with("//"))
    {
        auto const scheme_end = base_url.find(':');
        return std::string{base_url.substr(0U, scheme_end + 1U)} + std::string{reference};
    }
    if (reference.starts_with('/'))
    {
        auto resolved = std::string{origin} + std::string{reference};
        return resolved.size() > max_preview_url_bytes ? std::string{} : resolved;
    }
    return {};
}

auto UrlPreviewCache::find(std::string const& url, std::uint64_t now_ms) -> std::optional<Entry>
{
    auto const found = m_index.find(url);
    if (found == m_index.end())
    {
        return std::nullopt;
    }
    if (found->second->second.expires_at_ms <= now_ms)
    {
        m_entries.erase(found->second);
        m_index.erase(found);
        return std::nullopt;
    }
    m_entries.splice(m_entries.end(), m_entries, found->second);
    return found->second->second;
}

auto UrlPreviewCache::store(std::string const& url, Entry entry, std::size_t max_entries) -> void
{
    if (max_entries == 0U)
    {
        return;
    }
    if (auto const found = m_index.find(url); found != m_index.end())
    {
        m_entries.erase(found->second);
        m_index.erase(found);
    }
    while (m_entries.size() >= max_entries)
    {
        m_index.erase(m_entries.front().first);
        m_entries.pop_front();
    }
    m_entries.emplace_back(url, std::move(entry));
    m_index.emplace(url, std::prev(m_entries.end()));
}

auto UrlPreviewCache::size() const noexcept -> std::size_t
{
    return m_entries.size();
}

} // namespace merovingian::media
