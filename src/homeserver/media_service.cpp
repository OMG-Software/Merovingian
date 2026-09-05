// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/media_service.hpp"

#include "merovingian/core/query_params.hpp"
#include "merovingian/crypto/ed25519.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/federation/outbound_transaction.hpp"
#include "merovingian/federation/server_discovery.hpp"
#include "merovingian/homeserver/auth_service.hpp"
#include "merovingian/homeserver/local_services.hpp"
#include "merovingian/homeserver/request_lock.hpp"
#include "merovingian/homeserver/room_service.hpp"
#include "merovingian/http/outbound_client.hpp"
#include "merovingian/media/repository.hpp"
#include "merovingian/observability/logger.hpp"
#include "merovingian/observability/observability.hpp"
#include "merovingian/trust_safety/policy_engine.hpp"

#include <cctype>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

namespace merovingian::homeserver
{
namespace
{

    auto log_diagnostic(std::string_view event, std::vector<observability::StructuredLogField> fields,
                        observability::LogEventSeverity severity = observability::LogEventSeverity::debug) -> void
    {
        observability::log_diagnostic("media_service", event, fields, severity);
    }

    [[nodiscard]] auto admin_result_to_operation(media::LocalMediaAdminResult const& result) -> OperationResult
    {
        return make_operation_result(result.ok, result.media_id + "|" + media::local_media_state_name(result.state),
                                     result.reason, result.status);
    }

    auto persist_blob_for_media(HomeserverRuntime& runtime, std::string_view media_id) -> void
    {
        auto const* record = media::find_local_media_record(runtime.media_repository, media_id);
        if (record == nullptr)
        {
            return;
        }
        auto const* blob = media::find_local_media_blob(runtime.media_repository, record->storage_id);
        if (blob == nullptr)
        {
            return;
        }
        std::ignore = database::store_media_blob(
            runtime.database.persistent_store,
            {blob->storage_id, blob->hash_algorithm, blob->digest, blob->size_bytes, blob->bytes, blob->ref_count});
    }

    [[nodiscard]] auto media_policy_decision(HomeserverRuntime& runtime, std::string_view media_id)
        -> trust_safety::PolicyDecision
    {
        auto const local_rule = find_policy_rule(runtime, "media", media_id);
        auto const held_for_review = local_rule.has_value() && local_rule->action == "quarantine";
        auto const blocked_by_local_policy =
            local_rule.has_value() && local_rule->action != "allow" && local_rule->action != "quarantine";
        return trust_safety::evaluate_media_policy(
            {std::string{media_id}, held_for_review, blocked_by_local_policy,
             resolve_policy_server_hook(runtime, trust_safety::PolicySurface::media, media_id)});
    }

    [[nodiscard]] auto equal_ci(std::string_view a, std::string_view b) noexcept -> bool
    {
        if (a.size() != b.size())
        {
            return false;
        }
        for (std::size_t i = 0U; i < a.size(); ++i)
        {
            if (std::tolower(static_cast<unsigned char>(a[i])) != std::tolower(static_cast<unsigned char>(b[i])))
            {
                return false;
            }
        }
        return true;
    }

    [[nodiscard]] auto trim(std::string_view value) noexcept -> std::string_view
    {
        while (!value.empty() && (value.front() == ' ' || value.front() == '\t'))
        {
            value.remove_prefix(1U);
        }
        while (!value.empty() && (value.back() == ' ' || value.back() == '\t' || value.back() == '\r'))
        {
            value.remove_suffix(1U);
        }
        return value;
    }

    // HTTP header names are case-insensitive; scans linearly since responses
    // carry a small, bounded number of headers.
    [[nodiscard]] auto find_header_ci(std::vector<http::OutboundHeader> const& headers, std::string_view name)
        -> std::optional<std::string>
    {
        for (auto const& header : headers)
        {
            if (equal_ci(header.name, name))
            {
                return header.value;
            }
        }
        return std::nullopt;
    }

    // Strips MIME parameters (e.g. "image/jpeg; charset=utf-8" -> "image/jpeg").
    [[nodiscard]] auto strip_mime_parameters(std::string value) -> std::string
    {
        auto const semicolon = value.find(';');
        if (semicolon != std::string::npos)
        {
            value.resize(semicolon);
        }
        while (!value.empty() && value.back() == ' ')
        {
            value.pop_back();
        }
        return value;
    }

    [[nodiscard]] auto starts_with(std::string_view value, std::string_view prefix) noexcept -> bool
    {
        return value.size() >= prefix.size() && value.substr(0U, prefix.size()) == prefix;
    }

    struct ParsedHttpsAuthority final
    {
        std::string host{};
        std::uint16_t port{443U};
    };

    // Extracts host and port from an absolute https:// URL. Rejects URLs with
    // userinfo, non-HTTPS schemes, or malformed IPv6/port syntax. The default
    // port is 443. This is a strict parser intended for untrusted redirect
    // URLs; it stops at the first '/', '?' or '#' so query strings and
    // fragments do not pollute the authority.
    [[nodiscard]] auto parse_https_authority(std::string_view url) -> std::optional<ParsedHttpsAuthority>
    {
        auto constexpr prefix = std::string_view{"https://"};
        if (!starts_with(url, prefix))
        {
            return std::nullopt;
        }
        auto const authority_start = prefix.size();
        auto const authority_end = url.find_first_of("/?#", authority_start);
        auto const authority = url.substr(authority_start, authority_end - authority_start);
        if (authority.empty() || authority.find('@') != std::string_view::npos)
        {
            return std::nullopt;
        }

        if (!authority.empty() && authority.front() == '[')
        {
            auto const close = authority.find(']');
            if (close == std::string_view::npos || close == 1U)
            {
                return std::nullopt;
            }
            auto port = std::uint16_t{443U};
            if (close + 1U < authority.size())
            {
                if (authority[close + 1U] != ':')
                {
                    return std::nullopt;
                }
                auto const* begin = authority.data() + close + 2U;
                auto const* end = authority.data() + authority.size();
                auto const parsed = std::from_chars(begin, end, port);
                if (parsed.ec != std::errc{} || parsed.ptr != end || port == 0U)
                {
                    return std::nullopt;
                }
            }
            return ParsedHttpsAuthority{std::string{authority.substr(1U, close - 1U)}, port};
        }

        auto const colon = authority.rfind(':');
        if (colon != std::string_view::npos && authority.find(':') == colon)
        {
            auto const* begin = authority.data() + colon + 1U;
            auto const* end = authority.data() + authority.size();
            auto port = std::uint16_t{443U};
            auto const parsed = std::from_chars(begin, end, port);
            if (parsed.ec != std::errc{} || parsed.ptr != end || port == 0U)
            {
                return std::nullopt;
            }
            return ParsedHttpsAuthority{std::string{authority.substr(0U, colon)}, port};
        }

        return ParsedHttpsAuthority{std::string{authority}, 443U};
    }

    [[nodiscard]] auto extract_multipart_boundary(std::string_view content_type) -> std::string
    {
        // RFC 2046 §5.1.1: parameter names are case-insensitive and the value
        // may be unquoted or quoted. Parameter names/values are separated by
        // optional linear whitespace (RFC 822), so "boundary=\"x\"" and
        // "boundary = x" are both valid. The parameter name is the last token
        // before the equals sign (e.g. "; boundary=").
        auto constexpr marker = std::string_view{"boundary"};
        auto pos = std::size_t{0U};
        while (pos < content_type.size())
        {
            auto const eq = content_type.find('=', pos);
            if (eq == std::string_view::npos)
            {
                return {};
            }
            auto name = trim(content_type.substr(pos, eq - pos));
            if (!name.empty())
            {
                // The parameter name is the token after any preceding semicolon.
                auto const semi = name.rfind(';');
                if (semi != std::string_view::npos)
                {
                    name = trim(name.substr(semi + 1U));
                }
            }
            if (equal_ci(name, marker))
            {
                auto value = trim(content_type.substr(eq + 1U));
                if (!value.empty() && value.front() == '"')
                {
                    value.remove_prefix(1U);
                    auto const end = value.find('"');
                    if (end == std::string_view::npos)
                    {
                        return {};
                    }
                    value = value.substr(0U, end);
                }
                else
                {
                    auto const end = value.find_first_of("; \t\r\n");
                    if (end != std::string_view::npos)
                    {
                        value = value.substr(0U, end);
                    }
                }
                return std::string{value};
            }
            pos = eq + 1U;
        }
        return {};
    }

    struct RawMultipartPart final
    {
        std::vector<std::pair<std::string, std::string>> headers{};
        std::string_view body{};
    };

    [[nodiscard]] auto find_raw_header_ci(RawMultipartPart const& part, std::string_view name)
        -> std::optional<std::string>
    {
        for (auto const& [key, value] : part.headers)
        {
            if (equal_ci(key, name))
            {
                return value;
            }
        }
        return std::nullopt;
    }

    // Splits a raw part (the bytes between two boundary delimiters) into its
    // header block and body per RFC 2046 §5.1: headers, a blank line, then the
    // body. A part may legitimately have an empty body (e.g. a `Location` redirect
    // part), so when no blank line is found the entire content is treated as
    // headers and the body is left empty.
    [[nodiscard]] auto parse_multipart_part(std::string_view raw) -> RawMultipartPart
    {
        auto part = RawMultipartPart{};
        auto separator = raw.find("\r\n\r\n");
        auto separator_len = std::size_t{4U};
        if (separator == std::string_view::npos)
        {
            separator = raw.find("\n\n");
            separator_len = 2U;
        }
        auto header_block = separator == std::string_view::npos ? raw : raw.substr(0U, separator);
        auto body = separator == std::string_view::npos ? std::string_view{} : raw.substr(separator + separator_len);
        // The trailing CRLF/LF belongs to the boundary delimiter's transport
        // padding, not the part body. Strip it when present.
        if (body.size() >= 2U && body.substr(body.size() - 2U) == "\r\n")
        {
            body.remove_suffix(2U);
        }
        else if (!body.empty() && body.back() == '\n')
        {
            body.remove_suffix(1U);
        }
        part.body = body;
        while (!header_block.empty())
        {
            auto const line_end = header_block.find('\n');
            auto line = line_end == std::string_view::npos ? header_block : header_block.substr(0U, line_end);
            if (!line.empty() && line.back() == '\r')
            {
                line.remove_suffix(1U);
            }
            if (auto const colon = line.find(':'); colon != std::string_view::npos)
            {
                part.headers.emplace_back(std::string{trim(line.substr(0U, colon))},
                                          std::string{trim(line.substr(colon + 1U))});
            }
            if (line_end == std::string_view::npos)
            {
                break;
            }
            header_block = header_block.substr(line_end + 1U);
        }
        return part;
    }

    // Returns true when `body` has a delimiter boundary at `offset`. RFC 2046
    // §5.1.1 requires the boundary delimiter line to appear on its own line:
    // it must be preceded by a line break (or start of body) and followed
    // immediately by either "--" (closing delimiter) or a line break
    // (transport padding). Without both checks a boundary string appearing
    // literally inside media bytes would be misinterpreted as the end of the
    // part.
    [[nodiscard]] auto boundary_at(std::string_view body, std::string_view boundary, std::size_t offset) -> bool
    {
        auto const after = offset + 2U + boundary.size();
        if (after > body.size())
        {
            return false;
        }
        if (body.compare(offset, 2U, "--") != 0)
        {
            return false;
        }
        if (body.compare(offset + 2U, boundary.size(), boundary) != 0)
        {
            return false;
        }
        // Preceded by start of body or a line break.
        if (offset != 0U)
        {
            if (offset >= 2U && body.compare(offset - 2U, 2U, "\r\n") == 0)
            {
                // fall through
            }
            else if (offset >= 1U && body[offset - 1U] == '\n')
            {
                // fall through
            }
            else
            {
                return false;
            }
        }
        // Followed by closing "--" or a line break.
        if (after == body.size())
        {
            return true;
        }
        if (body.compare(after, 2U, "--") == 0)
        {
            return true;
        }
        if (body.compare(after, 2U, "\r\n") == 0)
        {
            return true;
        }
        return body[after] == '\n';
    }

    // Finds the next real boundary delimiter at or after `start`, using
    // boundary_at() so inner boundary-like byte sequences are ignored.
    [[nodiscard]] auto find_next_boundary(std::string_view body, std::string_view boundary, std::size_t start)
        -> std::size_t
    {
        auto const max = body.size();
        if (start >= max)
        {
            return std::string_view::npos;
        }
        auto pos = start;
        while (pos < max)
        {
            if (boundary_at(body, boundary, pos))
            {
                return pos;
            }
            pos += 1U;
        }
        return std::string_view::npos;
    }

    // Splits a multipart/mixed body on "--{boundary}" delimiters per RFC 2046.
    // Requires the opening delimiter to start on a line boundary and ignores
    // boundary-like strings that are not preceded by a line break.
    [[nodiscard]] auto split_multipart_body(std::string_view body, std::string_view boundary)
        -> std::vector<RawMultipartPart>
    {
        auto parts = std::vector<RawMultipartPart>{};
        if (boundary.empty())
        {
            return parts;
        }
        auto pos = find_next_boundary(body, boundary, 0U);
        if (pos == std::string_view::npos)
        {
            return parts;
        }
        pos += 2U + boundary.size();
        while (pos <= body.size())
        {
            // Closing delimiter "--boundary--".
            if (body.compare(pos, 2U, "--") == 0)
            {
                break;
            }
            // Transport padding after a delimiter is CRLF or LF.
            if (body.compare(pos, 2U, "\r\n") == 0)
            {
                pos += 2U;
            }
            else if (pos < body.size() && body[pos] == '\n')
            {
                pos += 1U;
            }
            auto const next = find_next_boundary(body, boundary, pos);
            if (next == std::string_view::npos)
            {
                break;
            }
            auto const raw_part = body.substr(pos, next - pos);
            parts.push_back(parse_multipart_part(raw_part));
            pos = next + 2U + boundary.size();
        }
        return parts;
    }

    // Shared tail for both the authenticated and the deprecated fetch paths:
    // stores the fetched bytes through the media policy pipeline and records
    // the outcome in diagnostics/audit.
    [[nodiscard]] auto finalize_remote_media_fetch(HomeserverRuntime& runtime, std::string_view origin_server,
                                                   std::string_view media_id,
                                                   federation::ServerDiscoveryResult const& resolution,
                                                   std::string content_type, std::string bytes) -> OperationResult
    {
        auto remote_req = media::RemoteMediaDownloadRequest{};
        remote_req.origin_server = std::string{origin_server};
        remote_req.media_id = std::string{media_id};
        remote_req.resolved_host = resolution.resolved_host;
        remote_req.resolved_addresses = resolution.pinned_addresses;
        remote_req.content_type = std::move(content_type);
        remote_req.bytes = std::move(bytes);
        // Bytes fetched from a federated origin are never actually scanned here — there is
        // no AV engine wired into this codebase for any media source yet (see
        // docs/media-repository.md). Reporting scanner_clean=true would be a fabricated
        // verdict for attacker-controlled content; media::fetch_remote_media() decides the
        // real disposition (allow/allow-after-scan/quarantine/deny) via
        // RuntimeMediaConfig::remote_fetch_media_policy, so this must reflect that no scan
        // actually happened.
        remote_req.scanner_clean = false;
        remote_req.decoder_marked_safe = true;

        auto const fetch_result = media::fetch_remote_media(runtime.media_repository, remote_req);
        if (!fetch_result.ok)
        {
            log_diagnostic("remote_fetch.store_failed", {
                                                            {"origin_server", std::string{origin_server}, false},
                                                            {"reason",        fetch_result.reason,        false}
            });
            append_local_audit(runtime.database, observability::AuditCategory::moderation,
                               "media.remote_fetch_rejected", "server",
                               std::string{origin_server} + '/' + std::string{media_id}, fetch_result.reason);
            return make_operation_result(false, {}, fetch_result.reason, fetch_result.status);
        }

        log_diagnostic("remote_fetch.accepted", {
                                                    {"origin_server", std::string{origin_server},              false},
                                                    {"media_id",      std::string{media_id},                   false},
                                                    {"content_type",  fetch_result.content_type,               false},
                                                    {"size_bytes",    std::to_string(fetch_result.size_bytes), false}
        });
        append_local_audit(runtime.database, observability::AuditCategory::moderation, "media.remote_fetch_accepted",
                           "server", std::string{origin_server} + '/' + std::string{media_id},
                           fetch_result.content_type);
        return make_operation_result(true, fetch_result.content_type + "|" + fetch_result.bytes, {},
                                     fetch_result.status);
    }

    // Attempts the mandatory, authenticated federation media endpoint
    // (server-server-api.md#get_matrixfederationv1mediadownloadmediaid, added
    // in v1.11). Returns std::nullopt when the caller should fall back to the
    // deprecated /_matrix/media/v3/download endpoint per spec: a 404 response,
    // or a 200 response this server cannot use yet (an unparseable multipart
    // body). Any other outcome — success, a Location redirect (followed
    // SSRF-safely when possible), or a definitive failure such as 429/502/504 —
    // is returned directly, since the spec only mandates falling back on 404.
    [[nodiscard]] auto fetch_remote_media_via_federation_endpoint(HomeserverRuntime& runtime,
                                                                  federation::ServerDiscoveryResult const& resolution,
                                                                  std::string_view origin_server,
                                                                  std::string_view media_id, std::uint64_t max_bytes,
                                                                  std::string_view trusted_ca_pem)
        -> std::optional<OperationResult>
    {
        auto constexpr expected_secret_bytes = crypto::ed25519_secret_key_bytes;
        auto const signing_key = ensure_runtime_server_signing_key(runtime);
        if (!signing_key.has_value() || runtime.database.signing_secret_key.bytes().size() != expected_secret_bytes)
        {
            log_diagnostic("remote_fetch.federation_endpoint.no_signing_key",
                           {
                               {"origin_server", std::string{origin_server}, false}
            },
                           observability::LogEventSeverity::warning);
            return std::nullopt;
        }

        auto transaction = federation::OutboundTransaction{};
        transaction.method = "GET";
        transaction.target = "/_matrix/federation/v1/media/download/" + core::percent_encode_path_component(media_id);
        transaction.origin = runtime.config.server().server_name;
        transaction.destination = std::string{origin_server};

        auto call = federation::OutboundCall{};
        call.transaction = transaction;
        call.resolved_host = resolution.resolved_host;
        call.resolved_port = resolution.resolved_port;
        call.pinned_addresses = resolution.pinned_addresses;
        call.key_id = signing_key->key_id;
        call.secret_key = runtime.database.signing_secret_key.bytes();
        call.trusted_ca_pem = std::string{trusted_ca_pem};
        call.connect_timeout_seconds = 30U;
        call.total_timeout_seconds = 120U;
        // A small fixed allowance over the raw media cap covers the
        // multipart/mixed envelope (boundary markers, part headers, and the
        // empty JSON metadata part) wrapping the media bytes on this endpoint.
        auto constexpr multipart_envelope_overhead = std::size_t{4096U};
        call.max_response_body_bytes = static_cast<std::size_t>(max_bytes) + multipart_envelope_overhead;

        auto const request = federation::build_outbound_request(call);
        // Release runtime.mutex for the network round trip: a remote that
        // accepts the connection and then stalls would otherwise freeze every
        // other client and federation request for up to total_timeout_seconds.
        auto const out_result = [&]() {
            auto const unlocked = NetworkIoUnlock{};
            return runtime.outbound_client->perform(request);
        }();

        if (!out_result.ok)
        {
            log_diagnostic(
                "remote_fetch.federation_endpoint.network_failed",
                {
                    {"origin_server", std::string{origin_server}, false},
                    {"reason",        out_result.error_detail,    false}
            },
                observability::LogEventSeverity::warning);
            return std::nullopt;
        }

        if (out_result.response.status == 404U)
        {
            log_diagnostic("remote_fetch.federation_endpoint.unrecognized",
                           {
                               {"origin_server", std::string{origin_server}, false}
            });
            return std::nullopt;
        }

        if (out_result.response.status < 200U || out_result.response.status >= 300U)
        {
            // 429 (rate limited), 502 (too large), 504 (not yet uploaded), or
            // anything else: the spec only mandates falling back to the legacy
            // endpoint on 404, so surface this as the final result.
            auto const reason = "remote returned " + std::to_string(out_result.response.status);
            log_diagnostic("remote_fetch.federation_endpoint.http_failed",
                           {
                               {"origin_server", std::string{origin_server},                 false},
                               {"http_status",   std::to_string(out_result.response.status), false}
            },
                           observability::LogEventSeverity::warning);
            ++runtime.media_repository.metrics.remote_fetch_rejections;
            append_local_audit(runtime.database, observability::AuditCategory::moderation,
                               "media.remote_fetch_rejected", "server",
                               std::string{origin_server} + '/' + std::string{media_id}, reason);
            return make_operation_result(false, {}, reason, 502U);
        }

        auto const content_type_header =
            find_header_ci(out_result.response.headers, "content-type").value_or(std::string{});
        auto const parsed = parse_federation_media_multipart(content_type_header, out_result.response.body);
        if (!parsed.ok)
        {
            log_diagnostic("remote_fetch.federation_endpoint.unparseable",
                           {
                               {"origin_server", std::string{origin_server}, false}
            },
                           observability::LogEventSeverity::warning);
            return std::nullopt;
        }
        if (parsed.is_redirect)
        {
            // Location-redirect responses point at an arbitrary CDN URL. Follow
            // them only after SSRF-safe resolution and address pinning; if the
            // redirect cannot be resolved safely, fall back to the legacy
            // endpoint rather than failing the whole request.
            log_diagnostic(
                "remote_fetch.federation_endpoint.location",
                {
                    {"origin_server", std::string{origin_server}, false},
                    {"location",      parsed.location,            false}
            });
            if (runtime.discovery_network == nullptr)
            {
                log_diagnostic("remote_fetch.federation_endpoint.location_no_discovery",
                               {
                                   {"origin_server", std::string{origin_server}, false}
                },
                               observability::LogEventSeverity::warning);
                return std::nullopt;
            }
            // DNS resolution of the redirect target is network-bound too.
            auto const redirect_resolution = [&]() {
                auto const unlocked = NetworkIoUnlock{};
                return resolve_media_redirect_url(parsed.location, *runtime.discovery_network);
            }();
            if (!redirect_resolution.ok)
            {
                log_diagnostic("remote_fetch.federation_endpoint.location_rejected",
                               {
                                   {"origin_server", std::string{origin_server}, false},
                                   {"location",      parsed.location,            false},
                                   {"reason",        redirect_resolution.reason, false}
                },
                               observability::LogEventSeverity::warning);
                return std::nullopt;
            }

            auto redirect_req = http::OutboundRequest{};
            redirect_req.method = "GET";
            redirect_req.url = std::string{parsed.location};
            redirect_req.pinned_addresses = redirect_resolution.discovery.pinned_addresses;
            redirect_req.trusted_ca_pem = std::string{trusted_ca_pem};
            redirect_req.connect_timeout_seconds = 30U;
            redirect_req.total_timeout_seconds = 120U;
            redirect_req.max_response_body_bytes = static_cast<std::size_t>(max_bytes);

            auto const redirect_result = [&]() {
                auto const unlocked = NetworkIoUnlock{};
                return runtime.outbound_client->perform(redirect_req);
            }();
            if (!redirect_result.ok || redirect_result.response.status < 200U ||
                redirect_result.response.status >= 300U)
            {
                auto const reason = redirect_result.error_detail.empty()
                                        ? "remote returned " + std::to_string(redirect_result.response.status)
                                        : redirect_result.error_detail;
                log_diagnostic("remote_fetch.federation_endpoint.location_http_failed",
                               {
                                   {"origin_server", std::string{origin_server}, false},
                                   {"location",      parsed.location,            false},
                                   {"reason",        reason,                     false}
                },
                               observability::LogEventSeverity::warning);
                ++runtime.media_repository.metrics.remote_fetch_rejections;
                append_local_audit(runtime.database, observability::AuditCategory::moderation,
                                   "media.remote_fetch_rejected", "server",
                                   std::string{origin_server} + '/' + std::string{media_id}, reason);
                return make_operation_result(false, {}, reason, 502U);
            }

            auto const redirect_content_type =
                strip_mime_parameters(find_header_ci(redirect_result.response.headers, "content-type")
                                          .value_or(std::string{"application/octet-stream"}));
            return finalize_remote_media_fetch(runtime, origin_server, media_id, redirect_resolution.discovery,
                                               std::move(redirect_content_type), redirect_result.response.body);
        }

        return finalize_remote_media_fetch(runtime, origin_server, media_id, resolution, parsed.content_type,
                                           parsed.bytes);
    }

    // Fetch remote media via server discovery, trying the authenticated
    // federation endpoint first and falling back to the deprecated,
    // unauthenticated /_matrix/media/v3/download endpoint per spec. On success
    // the media is stored locally and the result contains the bytes. Falls
    // back to remote_media_fetch_disabled() when federation infrastructure is
    // unavailable.
    [[nodiscard]] auto fetch_remote_media_live(HomeserverRuntime& runtime, std::string_view origin_server,
                                               std::string_view media_id) -> OperationResult
    {
        auto* const outbound_client = runtime.outbound_client.get();
        auto* const discovery_network = runtime.discovery_network.get();
        if (outbound_client == nullptr || discovery_network == nullptr)
        {
            log_diagnostic("remote_fetch.no_federation", {
                                                             {"origin_server", std::string{origin_server}, false},
                                                             {"media_id",      std::string{media_id},      false}
            });
            return remote_media_fetch_disabled(runtime, origin_server, media_id);
        }

        // Test-only: bypass discover_server() entirely when the destination has a
        // forced resolution wired (see TestOnlyForcedOutboundResolution in
        // runtime.hpp). Always empty in production, so this branch never executes
        // outside integration tests — mirrors perform_sync_outbound_call in
        // room_service.cpp, which relies on the same seam for make_join et al.
        auto const forced_it = runtime.test_forced_outbound_resolution.find(std::string{origin_server});
        auto const forced = forced_it != runtime.test_forced_outbound_resolution.end();
        auto resolution = federation::ServerDiscoveryResult{};
        auto trusted_ca_pem = std::string{};
        if (forced)
        {
            resolution.discovery_allowed = true;
            resolution.resolved_host = forced_it->second.resolved_host;
            resolution.resolved_port = forced_it->second.resolved_port;
            resolution.pinned_addresses = forced_it->second.pinned_addresses;
            trusted_ca_pem = forced_it->second.trusted_ca_pem;
        }
        else
        {
            auto constexpr discovery_timeout = std::uint32_t{30U};
            auto const unlocked = NetworkIoUnlock{};
            resolution = federation::discover_server(origin_server, *discovery_network, discovery_timeout);
        }
        if (!resolution.discovery_allowed)
        {
            log_diagnostic("remote_fetch.discovery_failed", {
                                                                {"origin_server", std::string{origin_server}, false},
                                                                {"reason",        resolution.reason,          false}
            });
            ++runtime.media_repository.metrics.remote_fetch_rejections;
            append_local_audit(runtime.database, observability::AuditCategory::moderation,
                               "media.remote_fetch_rejected", "server",
                               std::string{origin_server} + '/' + std::string{media_id}, resolution.reason);
            return make_operation_result(false, {}, "server discovery failed", 502U);
        }

        auto const max_bytes = runtime.media_repository.config.max_upload_bytes > 0U
                                   ? runtime.media_repository.config.max_upload_bytes
                                   : std::uint64_t{16U * 1024U * 1024U};

        // Spec (server-server-api.md#content-repository, changed in v1.11): servers
        // MUST try the authenticated endpoint first and only fall back to the
        // deprecated one on a 404. Calling the deprecated endpoint
        // unconditionally — as this code previously did — makes every remote
        // fetch 404 against servers that have disabled it, which is the default
        // on current Synapse and Merovingian deployments.
        if (auto federated = fetch_remote_media_via_federation_endpoint(runtime, resolution, origin_server, media_id,
                                                                        max_bytes, trusted_ca_pem);
            federated.has_value())
        {
            return std::move(*federated);
        }

        auto url =
            remote_media_download_url(resolution.resolved_host, resolution.resolved_port, origin_server, media_id);
        // Mandatory per spec when falling back to the deprecated endpoint: tells
        // the remote server not to itself recurse into fetching the media from
        // yet another remote, since we are already the fallback path.
        url += "?allow_remote=false";

        auto out_req = http::OutboundRequest{};
        out_req.method = "GET";
        out_req.url = std::move(url);
        out_req.pinned_addresses = resolution.pinned_addresses;
        out_req.trusted_ca_pem = trusted_ca_pem;
        out_req.connect_timeout_seconds = 30U;
        out_req.total_timeout_seconds = 120U;
        out_req.max_response_body_bytes = static_cast<std::size_t>(max_bytes);

        auto const out_result = [&]() {
            auto const unlocked = NetworkIoUnlock{};
            return outbound_client->perform(out_req);
        }();
        if (!out_result.ok || out_result.response.status < 200U || out_result.response.status >= 300U)
        {
            auto const reason = out_result.error_detail.empty()
                                    ? "remote returned " + std::to_string(out_result.response.status)
                                    : out_result.error_detail;
            log_diagnostic("remote_fetch.http_failed",
                           {
                               {"origin_server", std::string{origin_server}, false},
                               {"reason",        reason,                     false}
            });
            ++runtime.media_repository.metrics.remote_fetch_rejections;
            append_local_audit(runtime.database, observability::AuditCategory::moderation,
                               "media.remote_fetch_rejected", "server",
                               std::string{origin_server} + '/' + std::string{media_id}, reason);
            return make_operation_result(false, {}, reason, 502U);
        }

        auto content_type = strip_mime_parameters(find_header_ci(out_result.response.headers, "content-type")
                                                      .value_or(std::string{"application/octet-stream"}));

        return finalize_remote_media_fetch(runtime, origin_server, media_id, resolution, std::move(content_type),
                                           out_result.response.body);
    }

    // Resamples media bytes in the sandboxed worker. Anything the worker cannot
    // handle (unsupported format, worker not installed, decode failure) degrades
    // to a 404 so a thumbnail request never hard-fails by serving the original
    // full-size bytes. Shared by the local and remote thumbnail paths.
    [[nodiscard]] auto generate_thumbnail_for_media(HomeserverRuntime& runtime, std::string_view media_id,
                                                    std::string_view content_type, std::string_view bytes,
                                                    std::uint32_t width, std::uint32_t height,
                                                    media::ThumbnailMethod method) -> OperationResult
    {
        auto const& media_config = runtime.media_repository.config;
        auto thumbnailer_config = media::ThumbnailerConfig{};
        thumbnailer_config.worker_path = media_config.thumbnail_worker_path;
        thumbnailer_config.worker_binary_fd = media_config.thumbnail_worker_fd;
        thumbnailer_config.timeout_seconds = media_config.thumbnail_timeout_seconds;
        thumbnailer_config.max_input_bytes = media_config.max_decode_input_bytes;
        thumbnailer_config.max_output_bytes = media_config.max_decode_output_bytes;
        thumbnailer_config.max_pixels = static_cast<std::uint32_t>(media_config.max_decode_pixels);

        auto request = media::ThumbnailRequest{};
        request.source_bytes = bytes;
        request.source_content_type = std::string{content_type};
        request.width = width;
        request.height = height;
        request.method = method;

        if (media_config.thumbnailing_enabled && !thumbnailer_config.worker_path.empty())
        {
            auto const result = media::generate_thumbnail(thumbnailer_config, request);
            if (result.ok)
            {
                ++runtime.media_repository.metrics.thumbnails_served;
                log_diagnostic("thumbnail.resampled", {
                                                          {"media_id", std::string{media_id},         false},
                                                          {"width",    std::to_string(result.width),  false},
                                                          {"height",   std::to_string(result.height), false}
                });
                return make_operation_result(true, result.content_type + "|" + result.bytes, {}, 200U);
            }
            log_diagnostic("thumbnail.generation_failed", {
                                                              {"media_id", std::string{media_id},         false},
                                                              {"reason",   result.reason,                 false},
                                                              {"status",   std::to_string(result.status), false}
            });
            return make_operation_result(false, {}, "thumbnail generation failed", 404U);
        }

        log_diagnostic("thumbnail.unavailable", {
                                                    {"media_id",     std::string{media_id},     false},
                                                    {"content_type", std::string{content_type}, false}
        });
        return make_operation_result(false, {}, "thumbnails unavailable", 404U);
    }

} // namespace

[[nodiscard]] auto remote_media_download_url(std::string_view resolved_host, std::uint16_t resolved_port,
                                             std::string_view origin_server, std::string_view media_id) -> std::string
{
    return "https://" + std::string{resolved_host} + ':' + std::to_string(resolved_port) +
           "/_matrix/media/v3/download/" + core::percent_encode_path_component(origin_server) + '/' +
           core::percent_encode_path_component(media_id);
}

[[nodiscard]] auto remote_federation_media_download_url(std::string_view resolved_host, std::uint16_t resolved_port,
                                                        std::string_view media_id) -> std::string
{
    return "https://" + std::string{resolved_host} + ':' + std::to_string(resolved_port) +
           "/_matrix/federation/v1/media/download/" + core::percent_encode_path_component(media_id);
}

[[nodiscard]] auto parse_federation_media_multipart(std::string_view content_type_header, std::string_view body)
    -> FederationMediaPart
{
    auto const boundary = extract_multipart_boundary(content_type_header);
    auto const parts = split_multipart_body(body, boundary);
    // Matrix Server-Server API v1.19 mandates exactly two parts: an
    // application/json metadata part and either an inline media part or a
    // Location redirect part. Fail closed if the count differs.
    if (parts.size() != 2U)
    {
        return {};
    }

    auto const& media_part = parts[1];
    auto result = FederationMediaPart{};
    if (auto const location = find_raw_header_ci(media_part, "location"); location.has_value())
    {
        result.ok = true;
        result.is_redirect = true;
        result.location = *location;
        return result;
    }

    result.ok = true;
    result.is_redirect = false;
    result.content_type = strip_mime_parameters(
        find_raw_header_ci(media_part, "content-type").value_or(std::string{"application/octet-stream"}));
    result.bytes = std::string{media_part.body};
    return result;
}

[[nodiscard]] auto resolve_media_redirect_url(std::string_view location_url,
                                              federation::ServerDiscoveryNetwork& network)
    -> MediaRedirectResolutionResult
{
    auto result = MediaRedirectResolutionResult{};
    auto const authority = parse_https_authority(location_url);
    if (!authority.has_value())
    {
        result.reason = "redirect URL is not a valid absolute https:// URL";
        return result;
    }

    result.discovery = federation::resolve_federation_destination(authority->host, authority->port, network);
    if (!result.discovery.discovery_allowed)
    {
        result.reason = std::move(result.discovery.reason);
        result.discovery = {};
        return result;
    }

    result.ok = true;
    return result;
}

[[nodiscard]] auto upload_local_media(HomeserverRuntime& runtime, std::string_view access_token,
                                      std::string_view declared_mime_type, std::string_view sniffed_mime_type,
                                      bool scanner_clean, std::string_view bytes) -> OperationResult
{
    auto const user_id = authenticated_user(runtime, access_token);
    if (!user_id.has_value())
    {
        log_diagnostic("upload.rejected", {
                                              {"reason", "unauthenticated", false}
        });
        return make_operation_result(false, {}, "unauthenticated", 401U);
    }

    auto const result = media::upload_local_media(
        runtime.media_repository, runtime.config.server().server_name,
        {*user_id, std::string{declared_mime_type}, std::string{sniffed_mime_type}, std::string{bytes}, scanner_clean});
    if (!result.ok)
    {
        log_diagnostic("upload.rejected", {
                                              {"actor",     *user_id,                        false},
                                              {"mime_type", std::string{declared_mime_type}, false},
                                              {"reason",    result.reason,                   false},
                                              {"status",    std::to_string(result.status),   false}
        });
        append_local_audit(runtime.database, observability::AuditCategory::moderation, "media.upload_rejected",
                           *user_id, "local-media", result.reason);
        return make_operation_result(false, {}, result.reason, result.status);
    }

    std::ignore = database::store_local_media(runtime.database.persistent_store, {
                                                                                     result.media_id,
                                                                                     *user_id,
                                                                                     result.content_type,
                                                                                     result.size_bytes,
                                                                                     result.hash_algorithm,
                                                                                     result.digest,
                                                                                     result.quarantined,
                                                                                     false,
                                                                                 });
    persist_blob_for_media(runtime, result.media_id);
    log_diagnostic(result.quarantined ? "upload.quarantined" : "upload.accepted",
                   {
                       {"actor",        *user_id,                                            false},
                       {"media_id",     result.media_id,                                     false},
                       {"content_type", result.content_type,                                 false},
                       {"size_bytes",   std::to_string(result.size_bytes),                   false},
                       {"deduplicated", std::string{result.deduplicated ? "true" : "false"}, false},
                       {"quarantined",  std::string{result.quarantined ? "true" : "false"},  false}
    });
    append_local_audit(runtime.database, observability::AuditCategory::moderation,
                       result.quarantined ? "media.upload_quarantined" : "media.upload_accepted", *user_id,
                       result.media_id,
                       result.quarantined ? result.reason : (result.deduplicated ? "deduplicated" : "stored"));
    return make_operation_result(true,
                                 result.content_uri + "|" + result.content_type + "|" + result.hash_algorithm + ':' +
                                     result.digest +
                                     "|deduplicated=" + std::string{result.deduplicated ? "true" : "false"} +
                                     "|quarantined=" + std::string{result.quarantined ? "true" : "false"},
                                 {}, result.status);
}

[[nodiscard]] auto download_local_media(HomeserverRuntime& runtime, std::string_view server_name,
                                        std::string_view media_id) -> OperationResult
{
    auto const policy = media_policy_decision(runtime, media_id);
    if (!policy.allowed)
    {
        return make_operation_result(false, {}, policy.reason.code, 403U);
    }

    if (server_name != runtime.config.server().server_name)
    {
        log_diagnostic("download.remote", {
                                              {"origin_server", std::string{server_name}, false},
                                              {"media_id",      std::string{media_id},    false}
        });
        return fetch_remote_media_live(runtime, server_name, media_id);
    }

    auto const result = media::download_local_media(runtime.media_repository, server_name, media_id);
    if (!result.ok)
    {
        log_diagnostic("download.rejected", {
                                                {"media_id", std::string{media_id},         false},
                                                {"reason",   result.reason,                 false},
                                                {"status",   std::to_string(result.status), false}
        });
        return make_operation_result(false, {}, result.reason, result.status);
    }
    log_diagnostic("download.accepted",
                   {
                       {"media_id",     std::string{media_id}, false},
                       {"content_type", result.content_type,   false}
    });
    return make_operation_result(true, result.content_type + "|" + result.bytes, {}, result.status);
}

[[nodiscard]] auto download_local_media_thumbnail(HomeserverRuntime& runtime, std::string_view server_name,
                                                  std::string_view media_id, std::uint32_t width, std::uint32_t height,
                                                  media::ThumbnailMethod method) -> OperationResult
{
    auto const policy = media_policy_decision(runtime, media_id);
    if (!policy.allowed)
    {
        return make_operation_result(false, {}, policy.reason.code, 403U);
    }

    if (server_name != runtime.config.server().server_name)
    {
        log_diagnostic("thumbnail.remote", {
                                               {"origin_server", std::string{server_name}, false},
                                               {"media_id",      std::string{media_id},    false}
        });
        // Fetch the remote media first, then resample it locally so a thumbnail
        // request never answers with the full-size original.
        auto const fetch_result = fetch_remote_media_live(runtime, server_name, media_id);
        if (!fetch_result.ok || fetch_result.status < 200U || fetch_result.status >= 300U)
        {
            return fetch_result;
        }
        auto const separator = fetch_result.value.find('|');
        if (separator == std::string::npos)
        {
            log_diagnostic("thumbnail.remote_malformed", {
                                                             {"origin_server", std::string{server_name}, false},
                                                             {"media_id",      std::string{media_id},    false}
            });
            return make_operation_result(false, {}, "remote media response malformed", 502U);
        }
        auto const content_type = std::string_view{fetch_result.value}.substr(0U, separator);
        auto const bytes = std::string_view{fetch_result.value}.substr(separator + 1U);
        return generate_thumbnail_for_media(runtime, media_id, content_type, bytes, width, height, method);
    }

    auto const* record = media::find_local_media_record(runtime.media_repository, media_id);
    if (record == nullptr || record->state != media::LocalMediaState::available)
    {
        log_diagnostic("thumbnail.not_found",
                       {
                           {"media_id", std::string{media_id}, false},
                           {"reason",   "record unavailable",  false}
        });
        return make_operation_result(false, {}, "thumbnail not found", 404U);
    }
    auto const* blob = media::find_local_media_blob(runtime.media_repository, record->storage_id);
    if (blob == nullptr)
    {
        log_diagnostic("thumbnail.blob_missing",
                       {
                           {"media_id",   std::string{media_id}, false},
                           {"storage_id", record->storage_id,    false}
        });
        return make_operation_result(false, {}, "thumbnail data not found", 404U);
    }

    return generate_thumbnail_for_media(runtime, media_id, record->content_type, blob->bytes, width, height, method);
}

[[nodiscard]] auto admin_quarantine_local_media(HomeserverRuntime& runtime, std::string_view access_token,
                                                std::string_view media_id, std::string_view reason) -> OperationResult
{
    auto const admin = require_admin(runtime, access_token);
    if (!admin.user_id.has_value())
    {
        auto const missing = admin.denial == AdminAuthResult::Denial::missing_token;
        return make_operation_result(false, {}, missing ? "admin authentication required" : "admin privileges required",
                                     missing ? 401U : 403U);
    }
    auto const& admin_user_id = *admin.user_id;

    auto const result = media::quarantine_local_media(runtime.media_repository, media_id, reason);
    if (result.ok)
    {
        std::ignore = database::update_local_media_state(runtime.database.persistent_store, media_id, true, false);
        std::ignore = database::append_admin_action(runtime.database.persistent_store,
                                                    {admin_user_id, "media.quarantine", std::string{media_id}});
        append_local_audit(runtime.database, observability::AuditCategory::moderation, "media.quarantined",
                           admin_user_id, media_id, reason);
    }
    return admin_result_to_operation(result);
}

[[nodiscard]] auto admin_release_local_media(HomeserverRuntime& runtime, std::string_view access_token,
                                             std::string_view media_id) -> OperationResult
{
    auto const admin = require_admin(runtime, access_token);
    if (!admin.user_id.has_value())
    {
        auto const missing = admin.denial == AdminAuthResult::Denial::missing_token;
        return make_operation_result(false, {}, missing ? "admin authentication required" : "admin privileges required",
                                     missing ? 401U : 403U);
    }
    auto const& admin_user_id = *admin.user_id;

    auto const result = media::release_local_media(runtime.media_repository, media_id);
    if (result.ok)
    {
        std::ignore = database::update_local_media_state(runtime.database.persistent_store, media_id, false, false);
        std::ignore = database::append_admin_action(runtime.database.persistent_store,
                                                    {admin_user_id, "media.release", std::string{media_id}});
        append_local_audit(runtime.database, observability::AuditCategory::moderation, "media.released", admin_user_id,
                           media_id, "released");
    }
    return admin_result_to_operation(result);
}

[[nodiscard]] auto admin_remove_local_media(HomeserverRuntime& runtime, std::string_view access_token,
                                            std::string_view media_id, std::string_view reason) -> OperationResult
{
    auto const admin = require_admin(runtime, access_token);
    if (!admin.user_id.has_value())
    {
        auto const missing = admin.denial == AdminAuthResult::Denial::missing_token;
        return make_operation_result(false, {}, missing ? "admin authentication required" : "admin privileges required",
                                     missing ? 401U : 403U);
    }
    auto const& admin_user_id = *admin.user_id;

    auto const result = media::remove_local_media(runtime.media_repository, media_id, reason);
    if (result.ok)
    {
        std::ignore = database::update_local_media_state(runtime.database.persistent_store, media_id, false, true);
        persist_blob_for_media(runtime, media_id);
        std::ignore = database::append_admin_action(runtime.database.persistent_store,
                                                    {admin_user_id, "media.remove", std::string{media_id}});
        append_local_audit(runtime.database, observability::AuditCategory::moderation, "media.removed", admin_user_id,
                           media_id, reason);
    }
    return admin_result_to_operation(result);
}

[[nodiscard]] auto remote_media_fetch_disabled(HomeserverRuntime& runtime, std::string_view origin_server,
                                               std::string_view media_id) -> OperationResult
{
    auto const result = media::fetch_remote_media_disabled(
        runtime.media_repository, {std::string{origin_server}, std::string{media_id}, std::string{origin_server}, {}});
    append_local_audit(runtime.database, observability::AuditCategory::moderation, "media.remote_fetch_rejected",
                       "server", std::string{origin_server} + '/' + std::string{media_id}, result.reason);
    return make_operation_result(result.ok, {}, result.reason, result.status);
}

[[nodiscard]] auto media_metrics_summary(HomeserverRuntime const& runtime) -> std::string
{
    auto const metrics = media::media_repository_metrics(runtime.media_repository);
    auto summary = std::string{};
    for (auto const& metric : metrics)
    {
        if (!summary.empty())
        {
            summary += '\n';
        }
        summary += metric.name + '=' + std::to_string(metric.value);
    }
    return summary;
}

} // namespace merovingian::homeserver
