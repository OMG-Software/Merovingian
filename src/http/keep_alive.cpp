// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/http/keep_alive.hpp"

#include <string>

namespace merovingian::http
{
namespace
{

    [[nodiscard]] auto is_optional_whitespace(char value) noexcept -> bool
    {
        return value == ' ' || value == '\t';
    }

    [[nodiscard]] auto ascii_lowercase(char value) noexcept -> char
    {
        return (value >= 'A' && value <= 'Z') ? static_cast<char>(value - 'A' + 'a') : value;
    }

} // namespace

auto keep_alive_policy_is_valid(KeepAlivePolicy const& policy) noexcept -> bool
{
    // The idle window must be strictly positive (0 would degenerate to
    // close-after-response, which the `enabled=false` switch already
    // expresses) and bounded so a misconfiguration cannot park connections
    // for minutes. The parked-connection cap must leave room for at least
    // one connection and stay within a sane upper bound.
    return policy.idle_timeout_seconds > 0U && policy.idle_timeout_seconds <= 300U && policy.max_connections > 0U &&
           policy.max_connections <= 4096U;
}

auto keep_alive_policy_summary(KeepAlivePolicy const& policy) -> std::string
{
    auto summary = std::string{"HTTP keep-alive policy: enabled="};
    summary.append(policy.enabled ? "true" : "false");
    summary.append(" idle_timeout_seconds=");
    summary.append(std::to_string(policy.idle_timeout_seconds));
    summary.append(" max_connections=");
    summary.append(std::to_string(policy.max_connections));
    return summary;
}

auto connection_header_has_token(std::string_view connection_header, std::string_view token) noexcept -> bool
{
    // Walk the comma-separated token list (RFC 9110 §7.6.1), comparing each
    // trimmed element case-insensitively against `token`.
    auto begin = std::size_t{0U};
    while (begin <= connection_header.size())
    {
        auto end = connection_header.find(',', begin);
        if (end == std::string_view::npos)
        {
            end = connection_header.size();
        }
        while (begin < end && is_optional_whitespace(connection_header[begin]))
        {
            ++begin;
        }
        while (end > begin && is_optional_whitespace(connection_header[end - 1U]))
        {
            --end;
        }
        auto const element = connection_header.substr(begin, end - begin);
        if (element.size() == token.size())
        {
            auto match = true;
            for (auto index = std::size_t{0U}; index < token.size(); ++index)
            {
                if (ascii_lowercase(element[index]) != ascii_lowercase(token[index]))
                {
                    match = false;
                    break;
                }
            }
            if (match)
            {
                return true;
            }
        }
        if (end == connection_header.size())
        {
            break;
        }
        begin = end + 1U;
    }
    return false;
}

auto connection_preference_for_request(HttpVersion version, std::string_view connection_header) noexcept
    -> ConnectionPreference
{
    switch (version)
    {
    case HttpVersion::http_1_1:
        // HTTP/1.1 persistent connections are the default; only an explicit
        // close token opts out.
        return connection_header_has_token(connection_header, "close") ? ConnectionPreference::close
                                                                       : ConnectionPreference::keep_alive;
    case HttpVersion::http_1_0:
        // HTTP/1.1 persistence is not the default in HTTP/1.0: keep the
        // connection open only when the client explicitly asked.
        return connection_header_has_token(connection_header, "keep-alive") ? ConnectionPreference::keep_alive
                                                                            : ConnectionPreference::close;
    }
    return ConnectionPreference::close;
}

auto connection_preference_for_response(HttpVersion version, std::string_view connection_header,
                                        KeepAlivePolicy const& policy, std::uint32_t parked_connections) noexcept
    -> ConnectionPreference
{
    // The operator policy and the parked-connection cap override a client's
    // preference for persistence; a client asking to close always wins.
    auto const requested = connection_preference_for_request(version, connection_header);
    if (requested == ConnectionPreference::close)
    {
        return ConnectionPreference::close;
    }
    if (!policy.enabled || !keep_alive_policy_is_valid(policy))
    {
        return ConnectionPreference::close;
    }
    if (parked_connections >= policy.max_connections)
    {
        return ConnectionPreference::close;
    }
    return ConnectionPreference::keep_alive;
}

} // namespace merovingian::http