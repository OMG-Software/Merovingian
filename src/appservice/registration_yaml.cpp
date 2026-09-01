// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/appservice/registration.hpp"

#include <array>
#include <cstring>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace merovingian::appservice
{
namespace
{
    struct NamespacePattern final
    {
        std::string regex{};
        bool exclusive{false};
    };

    struct Registration final
    {
        std::string id{};
        // std::nullopt when the file says `url: null` — the AS receives no
        // homeserver traffic and ping reports M_URL_NOT_SET.
        std::optional<std::string> url{};
        core::SecretBuffer as_token{};
        core::SecretBuffer hs_token{};
        std::string sender_localpart{};
        std::vector<NamespacePattern> users{};
        std::vector<NamespacePattern> aliases{};
        std::vector<NamespacePattern> rooms{};
        std::vector<std::string> protocols{};
        bool rate_limited{true};
        bool receive_ephemeral{false};
    };

    struct RegistrationFinding final
    {
        std::string field{};
        std::string message{};
    };

    // Input bounds (fail closed): a registration file is operator-authored
    // configuration, so anything larger or deeper than what real bridges
    // ship is a finding, not a resource-exhaustion opportunity.
    constexpr std::size_t kMaxFileBytes = 256U * 1024U;
    constexpr std::size_t kMaxLineBytes = 4U * 1024U;
    constexpr std::size_t kMaxNamespaceEntries = 64U;
    constexpr std::size_t kMaxProtocols = 32U;

    // One logical line after comment/blank stripping.
    struct Line final
    {
        std::size_t indent{0U};
        std::string_view text{};
    };

    [[nodiscard]] auto find_comment_start(std::string_view line) noexcept -> std::size_t
    {
        // '#' starts a comment only outside quotes and at a token boundary.
        auto in_single = false;
        auto in_double = false;
        for (auto index = std::size_t{0U}; index < line.size(); ++index)
        {
            auto const character = line[index];
            if (in_single)
            {
                if (character == '\'')
                {
                    if (index + 1U < line.size() && line[index + 1U] == '\'')
                    {
                        ++index; // YAML's '' escape for a literal '
                        continue;
                    }
                    in_single = false;
                }
                continue;
            }
            if (in_double)
            {
                if (character == '\\')
                {
                    ++index; // skip the escaped character
                    continue;
                }
                if (character == '"')
                {
                    in_double = false;
                }
                continue;
            }
            if (character == '\'')
            {
                in_single = true;
                continue;
            }
            if (character == '"')
            {
                in_double = true;
                continue;
            }
            if (character == '#' && (index == 0U || line[index - 1U] == ' ' || line[index - 1U] == '\t'))
            {
                return index;
            }
        }
        return std::string_view::npos;
    }

    [[nodiscard]] auto trim(std::string_view value) noexcept -> std::string_view
    {
        while (!value.empty() && (value.front() == ' '))
        {
            value.remove_prefix(1U);
        }
        while (!value.empty() && (value.back() == ' ' || value.back() == '\r'))
        {
            value.remove_suffix(1U);
        }
        return value;
    }

    [[nodiscard]] auto indent_of(std::string_view line) noexcept -> std::size_t
    {
        auto indent = std::size_t{0U};
        while (indent < line.size() && line[indent] == ' ')
        {
            ++indent;
        }
        return indent;
    }

    // Splits a `key: value` / `key:` line into key and unquoted-value text.
    // Returns false when the line has no `key:` shape at all.
    [[nodiscard]] auto split_key(std::string_view text, std::string_view& key, std::string_view& value) -> bool
    {
        auto const colon = text.find(':');
        if (colon == std::string_view::npos)
        {
            return false;
        }
        key = trim(text.substr(0U, colon));
        value = trim(text.substr(colon + 1U));
        return !key.empty();
    }

    // A plain scalar must not begin a YAML feature we reject outright
    // (anchor, alias, tag, block scalar, flow collection, directive).
    [[nodiscard]] auto scalar_uses_rejected_feature(std::string_view raw) noexcept -> bool
    {
        if (raw.empty())
        {
            return false;
        }
        switch (raw.front())
        {
        case '&': // anchor
        case '*': // alias
        case '!': // tag
        case '|': // literal block scalar
        case '>': // folded block scalar
        case '[': // flow sequence
        case '{': // flow mapping
        case '%': // directive
            return true;
        default:
            return false;
        }
    }

    // Parses one scalar value. Quoted scalars keep everything inside the
    // quotes (with '' / \" / \\ escapes); plain scalars are taken verbatim.
    [[nodiscard]] auto parse_scalar(std::string_view raw, std::string_view field,
                                    std::vector<RegistrationFinding>& findings) -> std::optional<std::string>
    {
        if (scalar_uses_rejected_feature(raw))
        {
            findings.push_back({std::string{field}, "value uses a YAML feature outside the registration subset"});
            return std::nullopt;
        }
        if (raw.size() >= 2U && raw.front() == '\'')
        {
            if (raw.back() != '\'')
            {
                findings.push_back({std::string{field}, "unterminated single-quoted scalar"});
                return std::nullopt;
            }
            auto value = std::string{};
            for (auto index = std::size_t{1U}; index + 1U < raw.size(); ++index)
            {
                if (raw[index] == '\'' && index + 1U < raw.size() - 1U && raw[index + 1U] == '\'')
                {
                    value.push_back('\'');
                    ++index;
                    continue;
                }
                value.push_back(raw[index]);
            }
            return value;
        }
        if (raw.size() >= 2U && raw.front() == '"')
        {
            if (raw.back() != '"')
            {
                findings.push_back({std::string{field}, "unterminated double-quoted scalar"});
                return std::nullopt;
            }
            auto value = std::string{};
            for (auto index = std::size_t{1U}; index + 1U < raw.size(); ++index)
            {
                if (raw[index] == '\\' && index + 1U < raw.size() - 1U &&
                    (raw[index + 1U] == '"' || raw[index + 1U] == '\\'))
                {
                    value.push_back(raw[index + 1U]);
                    ++index;
                    continue;
                }
                value.push_back(raw[index]);
            }
            return value;
        }
        if (raw.front() == '"' || raw.front() == '\'')
        {
            findings.push_back({std::string{field}, "unterminated quoted scalar"});
            return std::nullopt;
        }
        return std::string{raw};
    }

    [[nodiscard]] auto parse_bool(std::string_view raw, std::string_view field,
                                  std::vector<RegistrationFinding>& findings) -> std::optional<bool>
    {
        // Deliberately true/false only: YAML 1.1 spellings (yes/no/on/off)
        // disagree between parsers, so accepting them is a muddling hazard.
        if (raw == "true")
        {
            return true;
        }
        if (raw == "false")
        {
            return false;
        }
        findings.push_back({std::string{field}, "expected the boolean true or false"});
        return std::nullopt;
    }

    [[nodiscard]] auto make_secret(std::string const& value) -> core::SecretBuffer
    {
        auto const bytes =
            std::span<std::uint8_t const>{reinterpret_cast<std::uint8_t const*>(value.data()), value.size()};
        return core::SecretBuffer{bytes};
    }

    class RegistrationParser final
    {
    public:
        RegistrationParser(std::vector<Line> const& lines, std::vector<RegistrationFinding>& findings) noexcept
            : m_lines{lines}
            , m_findings{findings} {};

        [[nodiscard]] auto parse() -> std::optional<Registration>
        {
            auto registration = Registration{};
            while (m_pos < m_lines.size())
            {
                auto const& line = m_lines.at(m_pos);
                if (line.indent != 0U)
                {
                    add("<file>", "unexpected indentation at top level");
                    ++m_pos;
                    continue;
                }
                auto key = std::string_view{};
                auto value = std::string_view{};
                if (!split_key(line.text, key, value))
                {
                    add("<file>", "expected a 'key: value' or 'key:' line");
                    ++m_pos;
                    continue;
                }
                ++m_pos;
                if (key == "id")
                {
                    assign_scalar(registration.id, value, key);
                }
                else if (key == "url")
                {
                    parse_url(registration, value);
                }
                else if (key == "as_token")
                {
                    parse_token(registration.as_token, value, key, true);
                }
                else if (key == "hs_token")
                {
                    parse_token(registration.hs_token, value, key, true);
                }
                else if (key == "sender_localpart")
                {
                    assign_scalar(registration.sender_localpart, value, key);
                }
                else if (key == "rate_limited")
                {
                    assign_bool(registration.rate_limited, value, key);
                }
                else if (key == "receive_ephemeral")
                {
                    assign_bool(registration.receive_ephemeral, value, key);
                }
                else if (key == "protocols")
                {
                    // A block-list key must have no inline value: a value here
                    // is a flow collection like `[irc, other]`, which the
                    // subset rejects outright.
                    if (!value.empty())
                    {
                        add(key, "expected a block list, not an inline value");
                        continue;
                    }
                    parse_protocols(registration, line.indent);
                }
                else if (key == "namespaces")
                {
                    if (!value.empty())
                    {
                        add(key, "expected a block mapping, not an inline value");
                        continue;
                    }
                    parse_namespaces(registration, line.indent);
                }
                else
                {
                    add(key, "unknown registration key");
                    skip_children(line.indent);
                }
            }
            if (registration.id.empty())
            {
                add("id", "registration id is required");
            }
            if (registration.as_token.bytes().empty())
            {
                add("as_token", "as_token is required");
            }
            if (registration.hs_token.bytes().empty())
            {
                add("hs_token", "hs_token is required");
            }
            if (registration.sender_localpart.empty())
            {
                add("sender_localpart", "sender_localpart is required");
            }
            if (registration.users.empty() && registration.aliases.empty() && registration.rooms.empty())
            {
                add("namespaces", "at least one namespace entry is required");
            }
            if (!m_findings.empty())
            {
                return std::nullopt;
            }
            return registration;
        }

    private:
        void add(std::string_view field, std::string_view message)
        {
            m_findings.push_back({std::string{field}, std::string{message}});
        }

        void assign_scalar(std::string& target, std::string_view value, std::string_view field)
        {
            if (value.empty())
            {
                add(field, "expected a scalar value");
                return;
            }
            if (scalar_uses_rejected_feature(value))
            {
                add(field, "value uses a YAML feature outside the registration subset");
                return;
            }
            if (auto const scalar = parse_scalar(value, field, m_findings))
            {
                target = *scalar;
            }
        }

        void assign_bool(bool& target, std::string_view value, std::string_view field)
        {
            if (value.empty())
            {
                add(field, "expected a boolean value");
                return;
            }
            if (auto const parsed = parse_bool(value, field, m_findings))
            {
                target = *parsed;
            }
        }

        void parse_token(core::SecretBuffer& target, std::string_view value, std::string_view field, bool required)
        {
            if (value.empty())
            {
                if (required)
                {
                    add(field, "expected a token value");
                }
                return;
            }
            if (scalar_uses_rejected_feature(value))
            {
                add(field, "value uses a YAML feature outside the registration subset");
                return;
            }
            if (auto const scalar = parse_scalar(value, field, m_findings))
            {
                target = make_secret(*scalar);
            }
        }

        void parse_url(Registration& registration, std::string_view value)
        {
            if (value == "null" || value == "~")
            {
                registration.url = std::nullopt;
                return;
            }
            if (value.empty())
            {
                add("url", "expected a URL or null");
                return;
            }
            if (scalar_uses_rejected_feature(value))
            {
                add("url", "value uses a YAML feature outside the registration subset");
                return;
            }
            if (auto const scalar = parse_scalar(value, "url", m_findings))
            {
                registration.url = *scalar;
            }
        }

        void parse_protocols(Registration& registration, std::size_t parent_indent)
        {
            auto count = std::size_t{0U};
            while (m_pos < m_lines.size() && m_lines.at(m_pos).indent > parent_indent)
            {
                auto const& line = m_lines.at(m_pos);
                if (!line.text.starts_with("- "))
                {
                    add("protocols", "expected a '- value' list entry");
                    skip_children(line.indent);
                    ++m_pos;
                    continue;
                }
                ++m_pos;
                if (++count > kMaxProtocols)
                {
                    add("protocols", "too many protocol entries (max 32)");
                    continue;
                }
                auto const value = trim(line.text.substr(2U));
                if (scalar_uses_rejected_feature(value))
                {
                    add("protocols", "value uses a YAML feature outside the registration subset");
                    continue;
                }
                if (auto const scalar = parse_scalar(value, "protocols", m_findings))
                {
                    registration.protocols.push_back(*scalar);
                }
            }
        }

        void parse_namespaces(Registration& registration, std::size_t parent_indent)
        {
            while (m_pos < m_lines.size() && m_lines.at(m_pos).indent > parent_indent)
            {
                auto const& line = m_lines.at(m_pos);
                auto key = std::string_view{};
                auto value = std::string_view{};
                if (!split_key(line.text, key, value))
                {
                    add("namespaces", "expected a namespace key (users, aliases or rooms)");
                    ++m_pos;
                    continue;
                }
                if (!value.empty())
                {
                    // The spec's own registration example writes an absent
                    // namespace as `rooms: []`, so rejecting every inline value
                    // here rejects the canonical document. Accept exactly the
                    // empty flow sequence — it carries no entries to parse, so
                    // supporting it costs nothing — and keep rejecting every
                    // other inline value, including non-empty flow sequences
                    // this bounded subset genuinely cannot parse.
                    if (trim(value) != "[]")
                    {
                        add("namespaces",
                            "expected a namespace key (users, aliases or rooms) with an indented list, or `[]`");
                        ++m_pos;
                        continue;
                    }
                    if (namespace_list(registration, key) == nullptr)
                    {
                        add("namespaces", "unknown namespace key (expected users, aliases or rooms)");
                    }
                    // An explicitly empty list: the vector already starts empty.
                    ++m_pos;
                    continue;
                }
                auto* const list = namespace_list(registration, key);
                ++m_pos;
                if (list == nullptr)
                {
                    skip_children(line.indent);
                    continue;
                }
                parse_namespace_list(*list, line.indent, std::string{key});
            }
        }

        void parse_namespace_list(std::vector<NamespacePattern>& list, std::size_t parent_indent,
                                  std::string const& field)
        {
            while (m_pos < m_lines.size() && m_lines.at(m_pos).indent > parent_indent)
            {
                auto const& line = m_lines.at(m_pos);
                if (!line.text.starts_with("- "))
                {
                    add(field, "expected a '- key: value' namespace entry");
                    skip_children(line.indent);
                    ++m_pos;
                    continue;
                }
                if (list.size() >= kMaxNamespaceEntries)
                {
                    add(field, "too many namespace entries (max 64)");
                    ++m_pos;
                    continue;
                }
                auto& entry = list.emplace_back();
                parse_namespace_entry(entry, line.text.substr(2U), line.indent, field);
            }
        }

        // Parses one entry: first key inline after the '-', remaining keys on
        // deeper-indented lines.
        void parse_namespace_entry(NamespacePattern& entry, std::string_view inline_text, std::size_t list_indent,
                                   std::string const& field)
        {
            auto seen_exclusive = false;
            auto seen_regex = false;
            auto first_key = std::string_view{};
            auto first_value = std::string_view{};
            if (!split_key(trim(inline_text), first_key, first_value))
            {
                add(field, "malformed namespace entry");
                ++m_pos;
                return;
            }
            parse_namespace_entry_key(entry, first_key, first_value, field, seen_exclusive, seen_regex);
            ++m_pos;
            while (m_pos < m_lines.size() && m_lines.at(m_pos).indent > list_indent)
            {
                auto const& line = m_lines.at(m_pos);
                auto key = std::string_view{};
                auto value = std::string_view{};
                if (!split_key(line.text, key, value))
                {
                    add(field, "malformed namespace entry line");
                    ++m_pos;
                    continue;
                }
                parse_namespace_entry_key(entry, key, value, field, seen_exclusive, seen_regex);
                ++m_pos;
            }
            if (!seen_exclusive)
            {
                add(field, "namespace entry is missing exclusive");
            }
            if (!seen_regex)
            {
                add(field, "namespace entry is missing regex");
            }
        }

        void parse_namespace_entry_key(NamespacePattern& entry, std::string_view key, std::string_view value,
                                       std::string const& field, bool& seen_exclusive, bool& seen_regex)
        {
            if (value.empty())
            {
                add(field, "expected a value after the namespace key");
                return;
            }
            if (key == "exclusive")
            {
                seen_exclusive = true;
                if (auto const parsed = parse_bool(value, field + ".exclusive", m_findings))
                {
                    entry.exclusive = *parsed;
                }
                return;
            }
            if (key == "regex")
            {
                seen_regex = true;
                if (scalar_uses_rejected_feature(value))
                {
                    add(field + ".regex", "value uses a YAML feature outside the registration subset");
                    return;
                }
                if (auto const scalar = parse_scalar(value, field + ".regex", m_findings))
                {
                    entry.regex = *scalar;
                }
                return;
            }
            add(field, "unknown namespace key");
        }

        [[nodiscard]] auto namespace_list(Registration& registration, std::string_view key)
            -> std::vector<NamespacePattern>*
        {
            if (key == "users")
            {
                return &registration.users;
            }
            if (key == "aliases")
            {
                return &registration.aliases;
            }
            if (key == "rooms")
            {
                return &registration.rooms;
            }
            add("namespaces", "unknown namespace (expected users, aliases or rooms)");
            return nullptr;
        }

        void skip_children(std::size_t parent_indent)
        {
            while (m_pos < m_lines.size() && m_lines.at(m_pos).indent > parent_indent)
            {
                ++m_pos;
            }
        }

        std::vector<Line> const& m_lines;
        std::vector<RegistrationFinding>& m_findings;
        std::size_t m_pos{0U};
    };

    // Bridges the parser's local record onto the module's public
    // AppserviceRegistration: identical fields, except that the public type
    // groups the three namespace lists inside a Namespaces member and orders
    // Namespace as {exclusive, regex}.
    [[nodiscard]] auto to_public(Registration&& parsed) -> AppserviceRegistration
    {
        auto const convert = [](std::vector<NamespacePattern> const& from) {
            auto to = std::vector<Namespace>{};
            to.reserve(from.size());
            for (auto const& entry : from)
            {
                to.push_back(Namespace{entry.exclusive, entry.regex});
            }
            return to;
        };

        auto out = AppserviceRegistration{};
        out.id = std::move(parsed.id);
        out.url = std::move(parsed.url);
        out.as_token = std::move(parsed.as_token);
        out.hs_token = std::move(parsed.hs_token);
        out.sender_localpart = std::move(parsed.sender_localpart);
        out.namespaces.users = convert(parsed.users);
        out.namespaces.aliases = convert(parsed.aliases);
        out.namespaces.rooms = convert(parsed.rooms);
        out.protocols = std::move(parsed.protocols);
        out.rate_limited = parsed.rate_limited;
        out.receive_ephemeral = parsed.receive_ephemeral;
        return out;
    }

} // namespace

auto parse_registration_document(std::string_view contents, std::vector<RegistrationFinding>& findings)
    -> std::optional<Registration>
{
    if (contents.size() > kMaxFileBytes)
    {
        findings.push_back({"<file>", "registration file exceeds 256 KiB"});
        return std::nullopt;
    }
    auto lines = std::vector<Line>{};
    for (auto cursor = std::size_t{0U}; cursor < contents.size();)
    {
        auto next = contents.find('\n', cursor);
        if (next == std::string_view::npos)
        {
            next = contents.size();
        }
        auto raw = contents.substr(cursor, next - cursor);
        cursor = next + 1U;
        if (raw.size() > kMaxLineBytes)
        {
            findings.push_back({"<file>", "line exceeds 4 KiB"});
            return std::nullopt;
        }
        if (raw.find('\t') != std::string_view::npos)
        {
            findings.push_back({"<file>", "tabs are not valid indentation in the registration subset"});
            return std::nullopt;
        }
        auto const without_comment = raw.substr(0U, find_comment_start(raw));
        auto const text = trim(without_comment.substr(indent_of(without_comment)));
        if (text.empty())
        {
            continue;
        }
        if (text == "---" || text == "...")
        {
            findings.push_back({"<file>", "YAML document markers are not part of the registration subset"});
            return std::nullopt;
        }
        lines.push_back(Line{indent_of(without_comment), text});
    }
    if (lines.empty())
    {
        findings.push_back({"<file>", "registration file is empty"});
        return std::nullopt;
    }
    auto parser = RegistrationParser{lines, findings};
    return parser.parse();
}

auto parse_registration_yaml(std::string_view contents) -> AppserviceRegistrationParseResult
{
    auto findings = std::vector<RegistrationFinding>{};
    auto parsed = parse_registration_document(contents, findings);
    if (!parsed.has_value())
    {
        // The public result carries one error; report the first finding, which
        // is the earliest problem in the document and the one an operator
        // should fix first. Later findings are usually cascades of it.
        auto message = std::string{"registration file is not valid"};
        if (!findings.empty())
        {
            message = findings.front().field + ": " + findings.front().message;
        }
        return {
            std::nullopt, core::Error{core::ErrorCode::parse_failure, message}
        };
    }
    return {to_public(std::move(*parsed)), core::Error{}};
}

} // namespace merovingian::appservice
