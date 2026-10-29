// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/media_service.hpp"

#include "merovingian/core/query_params.hpp"
#include "merovingian/core/secret_buffer.hpp"
#include "merovingian/crypto/ed25519.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/federation/outbound_transaction.hpp"
#include "merovingian/federation/server_discovery.hpp"
#include "merovingian/homeserver/auth_service.hpp"
#include "merovingian/homeserver/client_outbound_proxy.hpp"
#include "merovingian/homeserver/local_services.hpp"
#include "merovingian/homeserver/media_upload_notifier.hpp"
#include "merovingian/homeserver/remote_media_fetch_coalescer.hpp"
#include "merovingian/homeserver/remote_media_fetch_scope.hpp"
#include "merovingian/homeserver/request_lock.hpp"
#include "merovingian/homeserver/room_service.hpp"
#include "merovingian/http/outbound_client.hpp"
#include "merovingian/media/repository.hpp"
#include "merovingian/media/security.hpp"
#include "merovingian/observability/logger.hpp"
#include "merovingian/observability/observability.hpp"
#include "merovingian/trust_safety/policy_engine.hpp"

#include <algorithm>
#include <cctype>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <variant>
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

    // MED-5: media requests identify a server by name. The same server can be
    // written with different case or with the default federation port, and must
    // be recognised as local so it is not bounced through remote fetching
    // (ADR-0115). Only the default port is dropped: example.org:8449 is a
    // different server name from example.org, and treating it as local would
    // serve this server's media under another server's mxc:// URI.
    [[nodiscard]] auto canonical_media_server_name(std::string_view server_name) -> std::string
    {
        auto canonical = std::string{server_name};
        std::ranges::transform(canonical, canonical.begin(), [](unsigned char c) {
            return static_cast<char>(std::tolower(c));
        });
        constexpr auto default_port_suffix = std::string_view{":8448"};
        if (canonical.size() > default_port_suffix.size() && canonical.ends_with(default_port_suffix))
        {
            canonical.resize(canonical.size() - default_port_suffix.size());
        }
        return canonical;
    }

    [[nodiscard]] auto is_local_media_server(HomeserverRuntime const& runtime, std::string_view server_name) -> bool
    {
        return canonical_media_server_name(server_name) ==
               canonical_media_server_name(runtime.config.server().server_name);
    }

    [[nodiscard]] auto admin_result_to_operation(media::LocalMediaAdminResult const& result) -> OperationResult
    {
        return make_operation_result(result.ok, result.media_id + "|" + media::local_media_state_name(result.state),
                                     result.reason, result.status);
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
                // RFC 2046 §5.1.1: "boundary := 0*69<bchars> bcharsnospace",
                // 1 to 70 characters. The remote chooses it, so a longer one
                // is refused rather than searched for.
                auto constexpr max_boundary_length = std::size_t{70U};
                if (value.size() > max_boundary_length)
                {
                    return {};
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

    // Returns true when the delimiter "--{boundary}" that occupies `body` from
    // `offset` stands on its own line. RFC 2046 §5.1.1 requires the boundary
    // delimiter line to be preceded by a line break (or start of body) and
    // followed immediately by either "--" (closing delimiter) or a line break
    // (transport padding). Without both checks a boundary string appearing
    // literally inside media bytes would be misinterpreted as the end of the
    // part. The caller has already matched the delimiter text, so every check
    // here is constant time.
    [[nodiscard]] auto delimiter_on_own_line(std::string_view body, std::size_t offset, std::size_t delimiter_size)
        -> bool
    {
        // Preceded by start of body or a line break.
        if (offset != 0U && body[offset - 1U] != '\n')
        {
            return false;
        }
        // Followed by end of body, closing "--" or a line break.
        auto const after = offset + delimiter_size;
        if (after == body.size())
        {
            return true;
        }
        return body.compare(after, 2U, "--") == 0 || body.compare(after, 2U, "\r\n") == 0 || body[after] == '\n';
    }

    // Finds the next real boundary delimiter at or after `start`. The remote
    // chooses both the boundary and the body, so the search is linear in the
    // body (Knuth-Morris-Pratt over "--{boundary}") rather than a comparison
    // restarted at every byte, which a self-overlapping boundary turns
    // quadratic; matches that are not on their own line are skipped.
    [[nodiscard]] auto find_next_boundary(std::string_view body, std::string_view boundary, std::size_t start)
        -> std::size_t
    {
        auto const delimiter = "--" + std::string{boundary};
        if (start >= body.size() || body.size() - start < delimiter.size())
        {
            return std::string_view::npos;
        }
        // failure[i]: length of the longest proper prefix of delimiter[0..i]
        // that is also its suffix.
        auto failure = std::vector<std::size_t>(delimiter.size(), 0U);
        for (auto i = std::size_t{1U}, k = std::size_t{0U}; i < delimiter.size(); ++i)
        {
            while (k > 0U && delimiter[i] != delimiter[k])
            {
                k = failure[k - 1U];
            }
            if (delimiter[i] == delimiter[k])
            {
                ++k;
            }
            failure[i] = k;
        }
        auto matched = std::size_t{0U};
        for (auto pos = start; pos < body.size(); ++pos)
        {
            while (matched > 0U && body[pos] != delimiter[matched])
            {
                matched = failure[matched - 1U];
            }
            if (body[pos] == delimiter[matched])
            {
                ++matched;
            }
            if (matched == delimiter.size())
            {
                auto const offset = pos + 1U - delimiter.size();
                if (delimiter_on_own_line(body, offset, delimiter.size()))
                {
                    return offset;
                }
                matched = failure[matched - 1U];
            }
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

    // OUT-7: a remote `serverName` is answered 404 M_NOT_FOUND, before any
    // discovery or outbound call, when live remote fetching is off
    // (security.media.remote_fetch_enabled, default false) or the request set
    // allow_remote=false (spec: the server "should not attempt to fetch the media
    // if it is deemed remote"). Counted, and logged; not audited: any
    // unauthenticated client can trigger this, so it must not write a durable
    // row per request (ADR-0080).
    [[nodiscard]] auto remote_media_refusal(HomeserverRuntime& runtime, std::string_view origin_server,
                                            std::string_view media_id, RemoteMediaRequestContext const& remote)
        -> std::optional<OperationResult>
    {
        auto const enabled = runtime.media_repository.config.remote_fetch_enabled;
        if (enabled && remote.allow_remote)
        {
            return std::nullopt;
        }
        ++runtime.media_repository.metrics.remote_fetch_rejections;
        log_diagnostic("remote_fetch.refused",
                       {
                           {"origin_server", std::string{origin_server},                                    false},
                           {"media_id",      std::string{media_id},                                         false},
                           {"reason",        enabled ? "allow_remote=false" : "remote_fetch_enabled=false", false}
        });
        return make_operation_result(false, {}, "media not found", 404U);
    }

    // The freeze (ADR-0068) on the deprecated /_matrix/media/v3 routes, for
    // remote media. The spec counts media the server "had to re-download"
    // during the freeze as media from after the freeze, which "SHOULD only be accessible via the
    // new, authenticated, endpoints". So these routes serve a remote copy only
    // when it was cached before the freeze, and never fetch one: the fetch
    // would itself make it post-freeze media.
    [[nodiscard]] auto legacy_remote_media_refusal(HomeserverRuntime& runtime, std::string_view origin_server,
                                                   std::string_view media_id) -> std::optional<OperationResult>
    {
        auto const* cached = media::find_cached_remote_media(runtime.media_repository, origin_server, media_id,
                                                             media::remote_media_cache_now_ms());
        if (cached != nullptr && cached->legacy_endpoint_visible)
        {
            return std::nullopt;
        }
        log_diagnostic("remote_fetch.legacy_frozen", {
                                                         {"origin_server", std::string{origin_server},           false},
                                                         {"media_id",      std::string{media_id},                false},
                                                         {"cached",        cached != nullptr ? "true" : "false", false}
        });
        return make_operation_result(false, {}, "media not found", 404U);
    }

    // The fetch's shared deadline (ADR-0079) ran out. 502, like every other
    // failure to obtain the remote bytes.
    [[nodiscard]] auto remote_media_deadline_exceeded(HomeserverRuntime& runtime, std::string_view origin_server,
                                                      std::string_view media_id) -> OperationResult
    {
        log_diagnostic("remote_fetch.deadline_exceeded", {
                                                             {"origin_server", std::string{origin_server}, false},
                                                             {"media_id",      std::string{media_id},      false}
        });
        ++runtime.media_repository.metrics.remote_fetch_rejections;
        append_local_audit(runtime.database, observability::AuditCategory::moderation, "media.remote_fetch_rejected",
                           "server", std::string{origin_server} + '/' + std::string{media_id}, "deadline exceeded");
        return make_operation_result(false, {}, "remote media fetch deadline exceeded", 502U);
    }

    // Shared tail for both the authenticated and the deprecated fetch paths:
    // stores the fetched bytes through the media policy pipeline and records
    // the outcome in diagnostics/audit.
    // ADR-0119: media bytes live only in the database. Reads the bytes of media
    // already resolved under the runtime mutex with the mutex released, then
    // re-checks under it that the media may still be served: moderation that
    // ran during the read wins. nullopt when the bytes cannot be read or the
    // media is no longer servable.
    [[nodiscard]] auto read_servable_media_bytes(HomeserverRuntime& runtime, std::string_view media_id,
                                                 std::string_view storage_id, bool legacy_endpoint)
        -> std::optional<std::string>
    {
        auto const read = database::prepare_media_blob_read(runtime.database.persistent_store, storage_id);
        auto bytes = [&read]() {
            auto const unlocked = RuntimeLockRelease{};
            return database::read_media_blob(read);
        }();
        if (!bytes.has_value() ||
            !media::local_media_still_servable(runtime.media_repository, media_id, storage_id, legacy_endpoint))
        {
            return std::nullopt;
        }
        return bytes;
    }

    // DB-5 / ADR-0119: makes media the repository has just admitted durable,
    // record and blob in one transaction. `new_blob` writes `bytes`; otherwise
    // only the shared blob's reference count changes. On failure the admission
    // is undone in memory, so memory never holds media the database lacks.
    // `completes_pending`, when not empty, is the reserved media ID (ADR-0212)
    // whose reservation row is deleted in the same transaction.
    [[nodiscard]] auto persist_admitted_media(HomeserverRuntime& runtime, std::string_view media_id,
                                              std::string_view owner_user_id, bool quarantined, std::string_view bytes,
                                              bool new_blob, std::string_view completes_pending = {}) -> bool
    {
        auto const* record = media::find_local_media_record(runtime.media_repository, media_id);
        auto const* blob =
            record == nullptr ? nullptr : media::find_local_media_blob(runtime.media_repository, record->storage_id);
        auto const persisted =
            blob != nullptr &&
            database::commit_local_media_upload(runtime.database.persistent_store,
                                                {record->media_id, std::string{owner_user_id}, record->content_type,
                                                 record->size_bytes, record->hash_algorithm, record->digest,
                                                 quarantined, false, false, record->upload_name},
                                                {blob->storage_id, blob->hash_algorithm, blob->digest, blob->size_bytes,
                                                 new_blob ? std::string{bytes} : std::string{}, blob->ref_count},
                                                new_blob, completes_pending);
        if (!persisted)
        {
            std::ignore = media::rollback_local_media_upload(runtime.media_repository, media_id);
            log_diagnostic(
                "media.persist_failed",
                {
                    {"owner",    std::string{owner_user_id}, false},
                    {"media_id", std::string{media_id},      false}
            },
                observability::LogEventSeverity::error);
        }
        return persisted;
    }

    // ADR-0119: makes freshly admitted remote media durable together with its
    // cache entry, and releases the stored copies the admission displaces (an
    // expired copy of the same file, and least recently used copies beyond
    // the cache cap), all in one transaction. Memory changes only after the
    // commit; on failure the admission is undone.
    [[nodiscard]] auto persist_remote_media_admission(HomeserverRuntime& runtime, std::string_view origin_server,
                                                      std::string_view remote_media_id,
                                                      media::RemoteMediaDownloadResult const& admitted,
                                                      std::string_view bytes, std::uint64_t now) -> bool
    {
        auto& repository = runtime.media_repository;
        auto const* record = media::find_local_media_record(repository, admitted.local_media_id);
        auto const* blob = record == nullptr ? nullptr : media::find_local_media_blob(repository, record->storage_id);
        auto persisted = false;
        auto const displaced = media::plan_remote_media_admission(repository, origin_server, remote_media_id,
                                                                  record == nullptr ? 0U : record->size_bytes);
        if (blob != nullptr)
        {
            // Each blob's reference count once the displaced records are gone.
            auto released_per_blob = std::map<std::string, std::uint64_t>{};
            auto releases = std::vector<database::PersistentRemoteMediaRelease>{};
            for (auto const& gone : displaced)
            {
                releases.push_back({gone.local_media_id, gone.origin_server, gone.media_id});
                if (auto const* gone_record = media::find_local_media_record(repository, gone.local_media_id);
                    gone_record != nullptr)
                {
                    ++released_per_blob[gone_record->storage_id];
                }
            }
            auto released_blobs = std::vector<database::PersistentBlobReferenceCount>{};
            for (auto const& [storage_id, released] : released_per_blob)
            {
                auto const* released_blob = media::find_local_media_blob(repository, storage_id);
                if (storage_id != blob->storage_id && released_blob != nullptr)
                {
                    released_blobs.push_back({storage_id, released_blob->ref_count - released});
                }
            }
            auto const own_released = released_per_blob[blob->storage_id];
            persisted = database::commit_remote_media_admission(
                runtime.database.persistent_store,
                {record->media_id, record->owner_user_id, record->content_type, record->size_bytes,
                 record->hash_algorithm, record->digest, admitted.quarantined, false, false, record->upload_name},
                {blob->storage_id, blob->hash_algorithm, blob->digest, blob->size_bytes,
                 admitted.stored_new_blob ? std::string{bytes} : std::string{}, blob->ref_count - own_released},
                admitted.stored_new_blob,
                {std::string{origin_server}, std::string{remote_media_id}, record->content_type, record->size_bytes,
                 admitted.quarantined, record->media_id, now},
                releases, released_blobs);
        }
        if (!persisted)
        {
            std::ignore = media::rollback_local_media_upload(repository, admitted.local_media_id);
            log_diagnostic("remote_fetch.persist_failed",
                           {
                               {"origin_server", std::string{origin_server},   false},
                               {"media_id",      std::string{remote_media_id}, false}
            },
                           observability::LogEventSeverity::error);
            return false;
        }
        media::apply_remote_media_admission(repository, origin_server, remote_media_id, admitted.local_media_id, now,
                                            displaced);
        return true;
    }

    [[nodiscard]] auto finalize_remote_media_fetch(HomeserverRuntime& runtime, std::string_view origin_server,
                                                   std::string_view media_id,
                                                   federation::ServerDiscoveryResult const& resolution,
                                                   std::string content_type, std::string bytes,
                                                   std::string upload_name = {}) -> OperationResult
    {
        auto remote_req = media::RemoteMediaDownloadRequest{};
        remote_req.upload_name = std::move(upload_name);
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

        auto const now = media::remote_media_cache_now_ms();
        auto const fetch_result = media::fetch_remote_media(runtime.media_repository, remote_req, now);
        // ADR-0119: an admitted remote file, quarantined or not, is made durable
        // like an upload; its bytes are not kept in memory.
        if (fetch_result.admitted_new_record &&
            !persist_remote_media_admission(runtime, origin_server, media_id, fetch_result, remote_req.bytes, now))
        {
            return make_operation_result(false, {}, "remote media could not be stored", 500U);
        }
        if (!fetch_result.ok || fetch_result.quarantined || fetch_result.status != 200U)
        {
            log_diagnostic("remote_fetch.store_failed", {
                                                            {"origin_server", std::string{origin_server}, false},
                                                            {"reason",        fetch_result.reason,        false}
            });
            append_local_audit(runtime.database, observability::AuditCategory::moderation,
                               "media.remote_fetch_rejected", "server",
                               std::string{origin_server} + '/' + std::string{media_id}, fetch_result.reason);
            if (fetch_result.quarantined)
            {
                return make_operation_result(false, {}, "media is quarantined", 451U);
            }
            auto const unexpected_success = fetch_result.status >= 200U && fetch_result.status < 300U;
            return make_operation_result(false, {},
                                         unexpected_success ? "remote media was not admitted" : fetch_result.reason,
                                         unexpected_success ? 502U : fetch_result.status);
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
        auto served =
            make_operation_result(true, fetch_result.content_type + "|" + fetch_result.bytes, {}, fetch_result.status);
        if (auto const* stored = media::find_local_media_record(runtime.media_repository, fetch_result.local_media_id);
            stored != nullptr)
        {
            served.media_filename = stored->upload_name;
        }
        return served;
    }

    // Attempts the mandatory, authenticated federation media endpoint
    // (server-server-api.md#get_matrixfederationv1mediadownloadmediaid, added
    // in v1.11). Returns std::nullopt when the caller should fall back to the
    // deprecated /_matrix/media/v3/download endpoint per spec: a 404 response,
    // or a 200 response this server cannot use yet (an unparseable multipart
    // body). Any other outcome — success, a Location redirect (followed
    // SSRF-safely when possible), or a definitive failure such as 429/502/504 —
    // is returned directly, since the spec only mandates falling back on 404.
    [[nodiscard]] auto fetch_remote_media_via_federation_endpoint(
        HomeserverRuntime& runtime, federation::ServerDiscoveryResult const& resolution, std::string_view origin_server,
        std::string_view media_id, std::uint64_t max_bytes, std::string_view trusted_ca_pem,
        OutboundDeadline const& deadline) -> std::optional<OperationResult>
    {
        // ADR-0079: the whole fetch shares one deadline. With none left there is
        // no time for the legacy fallback either, so this is a final answer,
        // not a std::nullopt "try the next endpoint".
        auto const federation_budget = deadline.remaining_seconds();
        if (federation_budget == 0U)
        {
            return remote_media_deadline_exceeded(runtime, origin_server, media_id);
        }
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
        // M-02: carry the certificate identity alongside the resolved target.
        call.tls_server_name = resolution.tls_server_name;
        call.resolved_port = resolution.resolved_port;
        call.pinned_addresses = resolution.pinned_addresses;
        call.key_id = signing_key->key_id;
        // Own the signing key so the outbound call can release runtime.mutex
        // without borrowing from the runtime's mlocked buffer.
        call.secret_key = core::SecretBuffer{runtime.database.signing_secret_key.bytes()};
        call.trusted_ca_pem = std::string{trusted_ca_pem};
        call.connect_timeout_seconds = std::min(federation_budget, 30U);
        call.total_timeout_seconds = federation_budget;
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
            auto const unlocked = RuntimeLockRelease{};
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
                auto const unlocked = RuntimeLockRelease{};
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
            redirect_req.url = redirect_resolution.url;
            redirect_req.pinned_addresses = redirect_resolution.discovery.pinned_addresses;
            redirect_req.trusted_ca_pem = std::string{trusted_ca_pem};
            auto const redirect_budget = deadline.remaining_seconds();
            if (redirect_budget == 0U)
            {
                return remote_media_deadline_exceeded(runtime, origin_server, media_id);
            }
            redirect_req.connect_timeout_seconds = std::min(redirect_budget, 30U);
            redirect_req.total_timeout_seconds = redirect_budget;
            redirect_req.max_response_body_bytes = static_cast<std::size_t>(max_bytes);

            auto const redirect_result = [&]() {
                auto const unlocked = RuntimeLockRelease{};
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
            auto redirect_filename = media::content_disposition_filename(
                find_header_ci(redirect_result.response.headers, "content-disposition").value_or(std::string{}));
            return finalize_remote_media_fetch(runtime, origin_server, media_id, redirect_resolution.discovery,
                                               std::move(redirect_content_type), redirect_result.response.body,
                                               std::move(redirect_filename));
        }

        return finalize_remote_media_fetch(runtime, origin_server, media_id, resolution, parsed.content_type,
                                           parsed.bytes, parsed.filename);
    }

    // The answer for a remote file the remote media cache already holds within
    // its TTL, or nullopt when it must be fetched. A cached copy answers for the
    // remote file whatever its state (ADR-0119), so quarantined or removed media
    // is not fetched again. Runs with the runtime mutex held; it is released only
    // for the byte read.
    [[nodiscard]] auto serve_cached_remote_media(HomeserverRuntime& runtime, std::string_view origin_server,
                                                 std::string_view media_id) -> std::optional<OperationResult>
    {
        auto const* cached = media::find_cached_remote_media(runtime.media_repository, origin_server, media_id,
                                                             media::remote_media_cache_now_ms());
        if (cached == nullptr)
        {
            return std::nullopt;
        }
        if (cached->state == media::LocalMediaState::quarantined)
        {
            return make_operation_result(false, {}, "media is quarantined", 451U);
        }
        if (cached->state == media::LocalMediaState::removed)
        {
            return make_operation_result(false, {}, "media not found", 404U);
        }
        // Copied: the record may move while the mutex is released for the read.
        auto const local_media_id = cached->media_id;
        auto const storage_id = cached->storage_id;
        auto const content_type = cached->content_type;
        auto const upload_name = cached->upload_name;
        auto const bytes = read_servable_media_bytes(runtime, local_media_id, storage_id, false);
        if (!bytes.has_value())
        {
            return std::nullopt;
        }
        log_diagnostic("remote_fetch.cache_hit", {
                                                     {"origin_server", std::string{origin_server}, false},
                                                     {"media_id",      std::string{media_id},      false}
        });
        auto served = make_operation_result(true, content_type + "|" + *bytes, {}, 200U);
        served.media_filename = upload_name;
        return served;
    }

    // ADR-0121: the right to fetch one remote file, or the answer when it no
    // longer needs fetching. Storing a second copy of a file would displace the
    // first from the cache and delete it while another request may still be
    // reading it, so a request that finds the file being fetched waits for that
    // fetch, with the runtime mutex released, and then serves the copy it
    // stored. If that fetch stored nothing, it leads a fetch itself. The wait
    // ends with `deadline`, as a 502 like any other fetch that runs out of time.
    [[nodiscard]] auto lead_remote_media_fetch(HomeserverRuntime& runtime, std::string_view origin_server,
                                               std::string_view media_id, OutboundDeadline const& deadline)
        -> std::variant<RemoteMediaFetchCoalescer::Lead, OperationResult>
    {
        auto const coalesce_key = canonical_media_server_name(origin_server) + '/' + std::string{media_id};
        auto& coalescer = *runtime.remote_media_fetch_coalescer;
        while (true)
        {
            if (auto lead = coalescer.try_lead(coalesce_key); lead.has_value())
            {
                return std::move(*lead);
            }
            log_diagnostic("remote_fetch.coalesced", {
                                                         {"origin_server", std::string{origin_server}, false},
                                                         {"media_id",      std::string{media_id},      false}
            });
            auto const idle = [&] {
                auto const unlocked = RuntimeLockRelease{};
                return coalescer.wait_until_idle(coalesce_key, deadline.end());
            }();
            if (!idle || deadline.expired())
            {
                return remote_media_deadline_exceeded(runtime, origin_server, media_id);
            }
            if (auto cached = serve_cached_remote_media(runtime, origin_server, media_id); cached.has_value())
            {
                return std::move(*cached);
            }
        }
    }

    // Fetch remote media via server discovery, trying the authenticated
    // federation endpoint first and falling back to the deprecated,
    // unauthenticated /_matrix/media/v3/download endpoint per spec. On success
    // the media is stored locally and the result contains the bytes. Falls
    // back to remote_media_fetch_disabled() when federation infrastructure is
    // unavailable.
    [[nodiscard]] auto fetch_remote_media_live(HomeserverRuntime& runtime, std::string_view origin_server,
                                               std::string_view media_id, RemoteMediaRequestContext const& remote)
        -> OperationResult
    {
        // OUT-7: every entry point has already asked, before its own policy
        // hook; asking again here means no future caller can reach discovery or
        // the network with the opt-in off.
        if (auto refusal = remote_media_refusal(runtime, origin_server, media_id, remote); refusal.has_value())
        {
            return std::move(*refusal);
        }
        // OUT-4 (ADR-0114): remote media admitted within the cache TTL is served
        // from the local record. This must come before the outbound budget slot,
        // discovery and the request below; checking after them saves storage
        // but still sends one outbound fetch per client request.
        if (auto cached = serve_cached_remote_media(runtime, origin_server, media_id); cached.has_value())
        {
            return std::move(*cached);
        }
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

        // ADR-0121: a main-pool request does not wait on the origin. Everything
        // quick is done (refusal, policy, cache); record that the fetch is
        // needed and return, and the transport hands the request to the media
        // fetch pool, which runs it again in admitted mode. The placeholder
        // result below never reaches the client.
        auto const fetch_mode = RemoteMediaFetchScope::current_mode();
        if (fetch_mode == RemoteMediaFetchMode::defer && RemoteMediaFetchScope::record_deferral())
        {
            log_diagnostic("remote_fetch.deferred", {
                                                        {"origin_server", std::string{origin_server}, false},
                                                        {"media_id",      std::string{media_id},      false}
            });
            return make_operation_result(false, {}, "remote media fetch deferred to the media fetch pool", 503U);
        }

        // ADR-0079: an inline fetch holds a request-pool thread for as long as
        // the remote takes, and it is reachable without authentication. Take a
        // slot in the client-outbound budget before releasing the runtime lock
        // for discovery, and keep it until the fetch has ended, on every path.
        // On the media fetch pool the transport's admission replaces it.
        auto const proxy_slot = fetch_mode == RemoteMediaFetchMode::inline_fetch
                                    ? admit_client_outbound_proxy(runtime, remote.client_key)
                                    : std::optional<http::InFlightBudget::Slot>{};
        if (fetch_mode == RemoteMediaFetchMode::inline_fetch && !proxy_slot.has_value())
        {
            log_diagnostic("remote_fetch.over_budget", {
                                                           {"origin_server", std::string{origin_server}, false}
            });
            auto refused = make_operation_result(false, {}, "too many concurrent remote media fetches", 429U);
            refused.retry_after_ms = runtime.client_outbound_proxy_policy.retry_after_ms;
            return refused;
        }
        auto const deadline = OutboundDeadline{
            effective_client_outbound_deadline(runtime, runtime.client_outbound_proxy_policy.media_deadline_seconds)};

        // ADR-0121: one fetch per remote file; held until this fetch has
        // stored its copy or failed, on every path.
        auto const lead = lead_remote_media_fetch(runtime, origin_server, media_id, deadline);
        if (std::holds_alternative<OperationResult>(lead))
        {
            return std::get<OperationResult>(lead);
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
            // The forced host is itself the authoritative name in this test seam.
            resolution.tls_server_name = forced_it->second.resolved_host;
            resolution.resolved_port = forced_it->second.resolved_port;
            resolution.pinned_addresses = forced_it->second.pinned_addresses;
            trusted_ca_pem = forced_it->second.trusted_ca_pem;
        }
        else
        {
            auto const discovery_timeout = std::min(deadline.remaining_seconds(), std::uint32_t{30U});
            auto const unlocked = RuntimeLockRelease{};
            resolution = federation::discover_server(origin_server, *discovery_network, discovery_timeout);
        }
        if (deadline.expired())
        {
            return remote_media_deadline_exceeded(runtime, origin_server, media_id);
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
                                                                        max_bytes, trusted_ca_pem, deadline);
            federated.has_value())
        {
            return std::move(*federated);
        }
        auto const legacy_budget = deadline.remaining_seconds();
        if (legacy_budget == 0U)
        {
            return remote_media_deadline_exceeded(runtime, origin_server, media_id);
        }

        // M-02: build the URL from the certificate identity, not the resolved
        // target; pinned addresses still route the connection to the latter.
        auto url = remote_media_download_url(resolution.tls_server_name.empty() ? resolution.resolved_host
                                                                                : resolution.tls_server_name,
                                             resolution.resolved_port, origin_server, media_id);
        // Mandatory per spec when falling back to the deprecated endpoint: tells
        // the remote server not to itself recurse into fetching the media from
        // yet another remote, since we are already the fallback path.
        url += "?allow_remote=false";

        auto out_req = http::OutboundRequest{};
        out_req.method = "GET";
        out_req.url = std::move(url);
        out_req.pinned_addresses = resolution.pinned_addresses;
        out_req.trusted_ca_pem = trusted_ca_pem;
        out_req.connect_timeout_seconds = std::min(legacy_budget, 30U);
        out_req.total_timeout_seconds = legacy_budget;
        out_req.max_response_body_bytes = static_cast<std::size_t>(max_bytes);

        auto const out_result = [&]() {
            auto const unlocked = RuntimeLockRelease{};
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
        auto filename = media::content_disposition_filename(
            find_header_ci(out_result.response.headers, "content-disposition").value_or(std::string{}));

        return finalize_remote_media_fetch(runtime, origin_server, media_id, resolution, std::move(content_type),
                                           out_result.response.body, std::move(filename));
    }

    // ADR-0212: 504 M_NOT_YET_UPLOADED, the spec's answer for a reserved media
    // ID whose content did not arrive in time.
    [[nodiscard]] auto not_yet_uploaded_result() -> OperationResult
    {
        auto result = make_operation_result(false, {}, "Content has not yet been uploaded", 504U);
        result.errcode = "M_NOT_YET_UPLOADED";
        return result;
    }

    enum class PendingDownload
    {
        // No reservation: the request goes on as for any other media ID.
        not_pending,
        // The content arrived while waiting.
        uploaded,
        // Still not uploaded when the wait ended.
        timed_out,
        // Handed to the media fetch pool (ADR-0121); the placeholder result is
        // discarded by the dispatcher.
        deferred,
    };

    // ADR-0212: concurrent pending-upload waits, at most media_fetch_threads - 1
    // so the media fetch pool always keeps a worker for remote fetches and
    // previews; one requester may hold half of them. A single-worker pool
    // admits no wait at all: every pending download is answered 504 at once.
    [[nodiscard]] auto pending_upload_wait_cap(HomeserverRuntime const& runtime) noexcept -> std::uint32_t
    {
        auto const threads = runtime.config.server().http.media_fetch_threads;
        return threads > 1U ? threads - 1U : 0U;
    }

    // ADR-0212: a download of a reserved but empty local media ID waits for
    // the upload, at most min(timeout_ms, pending_upload_max_wait_ms). It never
    // waits on a main-pool thread: there it defers to the media fetch pool like
    // a remote fetch. A wait is admitted first: under pending_upload_wait_cap
    // always, and on a request thread (no media fetch pool) with an ADR-0079
    // client-outbound slot too. A wait that is not admitted answers 504 at once,
    // which the spec allows ("The content repository MAY respond before the
    // timeout"). It never waits with runtime.mutex held. Runs with
    // runtime.mutex held and published (RequestLockScope).
    [[nodiscard]] auto await_pending_upload(HomeserverRuntime& runtime, std::string_view media_id,
                                            RemoteMediaRequestContext const& remote) -> PendingDownload
    {
        auto& repository = runtime.media_repository;
        if (media::find_local_media_record(repository, media_id) != nullptr ||
            media::find_pending_media_upload(repository, media_id, media::remote_media_cache_now_ms()) == nullptr)
        {
            return PendingDownload::not_pending;
        }
        auto const wait_ms = std::min(remote.timeout_ms, repository.config.pending_upload_max_wait_ms);
        if (wait_ms == 0U)
        {
            return PendingDownload::timed_out;
        }
        auto const wait_cap = pending_upload_wait_cap(runtime);
        auto const refuse_wait = [&media_id](std::string_view reason) {
            log_diagnostic("download.pending_wait_refused",
                           {
                               {"media_id", std::string{media_id}, false},
                               {"reason",   std::string{reason},   false}
            });
            return PendingDownload::timed_out;
        };
        // Answer a full cap here rather than spend a media fetch pool handoff on
        // a wait that will be refused; the slot below is the authoritative check.
        if (runtime.pending_upload_waits->active() >= wait_cap)
        {
            return refuse_wait("wait cap reached");
        }
        auto const mode = RemoteMediaFetchScope::current_mode();
        if (mode == RemoteMediaFetchMode::defer && RemoteMediaFetchScope::record_deferral())
        {
            log_diagnostic("download.pending_deferred", {
                                                            {"media_id", std::string{media_id}, false}
            });
            return PendingDownload::deferred;
        }
        // On a request thread the wait holds a main-pool worker: it takes an
        // ADR-0079 slot, as an inline remote fetch does. On the media fetch pool
        // the transport's admission already stands in for it.
        auto const outbound_slot = mode == RemoteMediaFetchMode::inline_fetch
                                       ? admit_client_outbound_proxy(runtime, remote.client_key)
                                       : std::optional<http::InFlightBudget::Slot>{};
        if (mode == RemoteMediaFetchMode::inline_fetch && !outbound_slot.has_value())
        {
            return refuse_wait("client outbound budget exhausted");
        }
        auto const wait_slot = runtime.pending_upload_waits->try_acquire(
            remote.requester.empty() ? remote.client_key : remote.requester, wait_cap, std::max(1U, wait_cap / 2U));
        if (!wait_slot.has_value())
        {
            return refuse_wait("wait cap reached");
        }
        auto const deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds{wait_ms};
        auto& notifier = *runtime.media_upload_notifier;
        while (true)
        {
            // Read while runtime.mutex is held: an upload that commits after the
            // release has moved the generation on, so its wake-up is not lost.
            auto const seen = notifier.generation();
            std::ignore = [&notifier, seen, deadline] {
                auto const unlocked = RuntimeLockRelease{};
                return notifier.wait_for_upload(seen, deadline);
            }();
            if (media::find_local_media_record(repository, media_id) != nullptr)
            {
                return PendingDownload::uploaded;
            }
            if (media::find_pending_media_upload(repository, media_id, media::remote_media_cache_now_ms()) == nullptr)
            {
                return PendingDownload::not_pending;
            }
            if (std::chrono::steady_clock::now() >= deadline)
            {
                return PendingDownload::timed_out;
            }
        }
    }

    // The answer for a download of a pending local media ID, or nullopt to go
    // on serving it normally.
    [[nodiscard]] auto pending_download_answer(HomeserverRuntime& runtime, std::string_view media_id,
                                               RemoteMediaRequestContext const& remote)
        -> std::optional<OperationResult>
    {
        switch (await_pending_upload(runtime, media_id, remote))
        {
        case PendingDownload::timed_out:
            return not_yet_uploaded_result();
        case PendingDownload::deferred:
            return make_operation_result(false, {}, "pending media wait deferred to the media fetch pool", 503U);
        case PendingDownload::not_pending:
        case PendingDownload::uploaded:
            break;
        }
        return std::nullopt;
    }

    // ADR-0212 / spec: the client-facing errcode for a refused upload. 403 for
    // a file type the server does not permit or an exhausted quota, 413
    // M_TOO_LARGE for content over max_upload_size.
    [[nodiscard]] auto refused_upload_result(media::LocalMediaUploadResult const& result) -> OperationResult
    {
        switch (result.status)
        {
        case 413U: {
            auto refused = make_operation_result(false, {}, result.reason, 413U);
            refused.errcode = "M_TOO_LARGE";
            return refused;
        }
        case 415U:
        case 507U: {
            auto refused = make_operation_result(false, {}, result.reason, 403U);
            refused.errcode = "M_FORBIDDEN";
            return refused;
        }
        case 409U: {
            auto refused = make_operation_result(false, {}, "Media already uploaded", 409U);
            refused.errcode = "M_CANNOT_OVERWRITE_MEDIA";
            return refused;
        }
        default:
            return make_operation_result(false, {}, result.reason, result.status);
        }
    }

    [[nodiscard]] auto invalid_upload_filename_result() -> OperationResult
    {
        auto refused = make_operation_result(false, {}, "filename is not a valid file name", 400U);
        refused.errcode = "M_INVALID_PARAM";
        return refused;
    }

    // MED-4: who a thumbnail decode counts against: the user when the request
    // is authenticated, otherwise the client address.
    [[nodiscard]] auto thumbnail_requester(RemoteMediaRequestContext const& remote) -> std::string
    {
        return remote.requester.empty() ? "address:" + remote.client_key : "user:" + remote.requester;
    }

    struct LocalThumbnailSource final
    {
        std::string media_id{};
        std::string storage_id{};
        bool legacy_endpoint{false};
    };

    // Resamples media bytes in the sandboxed worker. Anything the worker cannot
    // handle (unsupported format, worker not installed, decode failure) degrades
    // to a 404 so a thumbnail request never hard-fails by serving the original
    // full-size bytes. Shared by the local and remote thumbnail paths.
    // MED-4, ADR-0152: one thumbnail decode in flight for `requester`, counted
    // while held. Constructed and destroyed with runtime.mutex held.
    class ThumbnailDecodeSlot final
    {
    public:
        ThumbnailDecodeSlot(media::LocalMediaRepository& repository, std::string requester)
            : repository_{repository}
            , requester_{std::move(requester)}
        {
            ++repository_.get().thumbnail_decodes_in_flight[requester_];
        }
        ThumbnailDecodeSlot(ThumbnailDecodeSlot const&) = delete;
        auto operator=(ThumbnailDecodeSlot const&) -> ThumbnailDecodeSlot& = delete;
        ThumbnailDecodeSlot(ThumbnailDecodeSlot&&) = delete;
        auto operator=(ThumbnailDecodeSlot&&) -> ThumbnailDecodeSlot& = delete;
        ~ThumbnailDecodeSlot() noexcept
        {
            auto& in_flight = repository_.get().thumbnail_decodes_in_flight;
            if (auto const found = in_flight.find(requester_); found != in_flight.end() && --found->second == 0U)
            {
                in_flight.erase(found);
            }
        }

    private:
        std::reference_wrapper<media::LocalMediaRepository> repository_;
        std::string requester_;
    };

    [[nodiscard]] auto generate_thumbnail_for_media(HomeserverRuntime& runtime, std::string_view media_id,
                                                    std::string_view content_type, std::string_view bytes,
                                                    std::uint32_t width, std::uint32_t height,
                                                    media::ThumbnailMethod method,
                                                    std::optional<LocalThumbnailSource> local_source,
                                                    std::string_view requester) -> OperationResult
    {
        auto const& media_config = runtime.media_repository.config;
        // MED-4: a thumbnail already generated from this record's bytes is
        // served without a decode. The caller has checked the record is still
        // servable; the entry itself authorises nothing.
        auto const cache_key =
            local_source.has_value()
                ? std::optional<media::ThumbnailCacheKey>{media::ThumbnailCacheKey{local_source->media_id,
                                                                                   local_source->storage_id, width,
                                                                                   height, method}}
                : std::nullopt;
        if (cache_key.has_value())
        {
            if (auto cached = runtime.media_repository.thumbnail_cache.find(*cache_key); cached.has_value())
            {
                ++runtime.media_repository.metrics.thumbnails_served;
                return make_operation_result(true, cached->content_type + "|" + cached->bytes, {}, 200U);
            }
        }
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
            // MED-4: each requester runs at most thumbnail_max_concurrent_per_user
            // decodes at once, so one client cannot hold the decoder pool.
            auto const& in_flight = runtime.media_repository.thumbnail_decodes_in_flight;
            if (auto const found = in_flight.find(std::string{requester});
                found != in_flight.end() &&
                found->second >= std::max(media_config.thumbnail_max_concurrent_per_user, 1U))
            {
                log_diagnostic("thumbnail.concurrency_refused", {
                                                                    {"media_id", std::string{media_id}, false}
                });
                auto refused = make_operation_result(false, {}, "too many thumbnails in progress, retry shortly", 429U);
                refused.retry_after_ms = 1000U;
                return refused;
            }
            auto const slot = ThumbnailDecodeSlot{runtime.media_repository, std::string{requester}};
            // MED-4: decoding runs in a child process for up to the thumbnail
            // timeout; it touches no runtime state, so it runs unlocked.
            auto const result = [&thumbnailer_config, &request]() {
                auto const unlocked = RuntimeLockRelease{};
                return media::generate_thumbnail(thumbnailer_config, request);
            }();
            if (result.ok)
            {
                // The local record, not a shared blob or an earlier admission,
                // authorizes disclosure after the unlocked decode. Remote
                // sources carry the cached local record the bytes were
                // admitted as (MED-4), and the media policy is asked again:
                // either may have changed while the lock was released.
                //
                // Policy first, record last: a policy server round trip
                // releases runtime.mutex too, so the record is checked only
                // once nothing else can release the lock before the cache
                // insert and the response (PR #509 review).
                if (!media_policy_decision(runtime, media_id).allowed ||
                    (local_source.has_value() &&
                     !media::local_media_still_servable(runtime.media_repository, local_source->media_id,
                                                        local_source->storage_id, local_source->legacy_endpoint)))
                {
                    return make_operation_result(false, {}, "thumbnail source no longer available", 404U);
                }
                if (cache_key.has_value())
                {
                    runtime.media_repository.thumbnail_cache.insert(
                        *cache_key, media::CachedThumbnail{result.content_type, result.bytes},
                        media_config.thumbnail_cache_max_bytes);
                }
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
    // R17: a remote download serves the remote server's filename.
    result.filename =
        media::content_disposition_filename(find_raw_header_ci(media_part, "content-disposition").value_or(""));
    result.bytes = std::string{media_part.body};
    return result;
}

[[nodiscard]] auto resolve_media_redirect_url(std::string_view location_url,
                                              federation::ServerDiscoveryNetwork& network)
    -> MediaRedirectResolutionResult
{
    auto result = MediaRedirectResolutionResult{};
    auto const authority = http::parse_outbound_url(location_url);
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

    result.url = authority->url;
    result.ok = true;
    return result;
}

[[nodiscard]] auto upload_local_media(HomeserverRuntime& runtime, std::string_view access_token,
                                      std::string_view declared_mime_type, std::string_view sniffed_mime_type,
                                      bool scanner_clean, std::string_view bytes, std::string_view upload_name)
    -> OperationResult
{
    auto const user_id = authenticated_user(runtime, access_token);
    if (!user_id.has_value())
    {
        log_diagnostic("upload.rejected", {
                                              {"reason", "unauthenticated", false}
        });
        return make_operation_result(false, {}, "unauthenticated", 401U);
    }
    if (!upload_name.empty() && !media::media_filename_is_valid(upload_name))
    {
        return invalid_upload_filename_result();
    }

    auto request = media::LocalMediaUploadRequest{*user_id, std::string{declared_mime_type},
                                                  std::string{sniffed_mime_type}, std::string{bytes}, scanner_clean};
    request.upload_name = std::string{upload_name};
    auto const result =
        media::upload_local_media(runtime.media_repository, runtime.config.server().server_name, request);
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
        auto refused = refused_upload_result(result);
        // The internal status stays as the repository reported it; the client
        // API maps it (refused.errcode carries the spec's errcode).
        refused.status = result.status;
        return refused;
    }

    // DB-5: the client is given an mxc:// URI only once the media and its blob
    // are durable. Otherwise the upload is undone in memory too, so a restart
    // cannot make a URI the client was given disappear.
    if (!persist_admitted_media(runtime, result.media_id, *user_id, result.quarantined, bytes, !result.deduplicated))
    {
        log_diagnostic("upload.persist_failed",
                       {
                           {"actor",    *user_id,        false},
                           {"media_id", result.media_id, false}
        },
                       observability::LogEventSeverity::error);
        return make_operation_result(false, {}, "media could not be stored", 500U);
    }
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

[[nodiscard]] auto store_fetched_media_for_user(HomeserverRuntime& runtime, std::string_view owner_user_id,
                                                std::string_view declared_mime_type, std::string_view bytes)
    -> OperationResult
{
    auto request = media::LocalMediaUploadRequest{
        std::string{owner_user_id}, strip_mime_parameters(std::string{declared_mime_type}),
        media::sniff_mime_type(bytes), std::string{bytes}, !media::content_matches_eicar_test_signature(bytes)};
    auto const result =
        media::upload_local_media(runtime.media_repository, runtime.config.server().server_name, request);
    if (!result.ok)
    {
        log_diagnostic("fetched_media.rejected",
                       {
                           {"actor",  std::string{owner_user_id}, false},
                           {"reason", result.reason,              false}
        });
        return refused_upload_result(result);
    }
    if (!persist_admitted_media(runtime, result.media_id, owner_user_id, result.quarantined, bytes,
                                !result.deduplicated))
    {
        return make_operation_result(false, {}, "media could not be stored", 500U);
    }
    append_local_audit(runtime.database, observability::AuditCategory::moderation,
                       result.quarantined ? "media.preview_image_quarantined" : "media.preview_image_stored",
                       std::string{owner_user_id}, result.media_id, result.content_type);
    if (result.quarantined)
    {
        return make_operation_result(false, {}, "media is quarantined", 451U);
    }
    return make_operation_result(
        true, result.content_uri + "|" + std::to_string(result.size_bytes) + "|" + result.content_type, {}, 200U);
}

[[nodiscard]] auto create_pending_media_upload(HomeserverRuntime& runtime, std::string_view access_token)
    -> OperationResult
{
    auto const user_id = authenticated_user(runtime, access_token);
    if (!user_id.has_value())
    {
        return make_operation_result(false, {}, "unauthenticated", 401U);
    }
    auto& repository = runtime.media_repository;
    auto const plan = media::plan_pending_media_upload(repository, *user_id, media::remote_media_cache_now_ms());
    if (!plan.ok)
    {
        log_diagnostic("create.refused", {
                                             {"actor",  *user_id,    false},
                                             {"reason", plan.reason, false}
        });
        auto refused = make_operation_result(false, {}, plan.reason, plan.status);
        if (plan.status == 429U)
        {
            refused.errcode = "M_LIMIT_EXCEEDED";
        }
        return refused;
    }
    auto const& reservation = plan.reservation;
    if (!database::commit_pending_media_upload(
            runtime.database.persistent_store,
            {reservation.media_id, reservation.owner_user_id, reservation.created_at_ms, reservation.expires_at_ms},
            plan.expired_media_ids))
    {
        log_diagnostic("create.persist_failed",
                       {
                           {"actor", *user_id, false}
        },
                       observability::LogEventSeverity::error);
        return make_operation_result(false, {}, "media ID could not be reserved", 500U);
    }
    media::apply_pending_media_upload(repository, plan);
    log_diagnostic("create.accepted", {
                                          {"actor",    *user_id,             false},
                                          {"media_id", reservation.media_id, false}
    });
    append_local_audit(runtime.database, observability::AuditCategory::moderation, "media.create_reserved", *user_id,
                       reservation.media_id, "reserved");
    return make_operation_result(true,
                                 "mxc://" + runtime.config.server().server_name + "/" + reservation.media_id + "|" +
                                     std::to_string(reservation.expires_at_ms),
                                 {}, 200U);
}

[[nodiscard]] auto upload_pending_media(HomeserverRuntime& runtime, std::string_view access_token,
                                        std::string_view media_id, std::string_view declared_mime_type,
                                        std::string_view sniffed_mime_type, bool scanner_clean, std::string_view bytes,
                                        std::string_view upload_name) -> OperationResult
{
    auto const user_id = authenticated_user(runtime, access_token);
    if (!user_id.has_value())
    {
        return make_operation_result(false, {}, "unauthenticated", 401U);
    }
    auto& repository = runtime.media_repository;
    auto const refuse = [](std::uint16_t status, std::string_view errcode, std::string_view reason) {
        auto refused = make_operation_result(false, {}, std::string{reason}, status);
        refused.errcode = std::string{errcode};
        return refused;
    };
    switch (media::admit_pending_media_upload(repository, media_id, *user_id, media::remote_media_cache_now_ms()))
    {
    case media::PendingUploadAdmission::already_uploaded:
        return refuse(409U, "M_CANNOT_OVERWRITE_MEDIA", "Media already uploaded");
    case media::PendingUploadAdmission::not_found:
        return refuse(404U, "M_NOT_FOUND", "Unknown media ID");
    case media::PendingUploadAdmission::forbidden:
        return refuse(403U, "M_FORBIDDEN", "This media ID was not created by you");
    case media::PendingUploadAdmission::accepted:
        break;
    }
    if (!upload_name.empty() && !media::media_filename_is_valid(upload_name))
    {
        return invalid_upload_filename_result();
    }

    auto request = media::LocalMediaUploadRequest{*user_id, std::string{declared_mime_type},
                                                  std::string{sniffed_mime_type}, std::string{bytes}, scanner_clean};
    request.upload_name = std::string{upload_name};
    request.media_id = std::string{media_id};
    auto const result = media::upload_local_media(repository, runtime.config.server().server_name, request);
    if (!result.ok)
    {
        log_diagnostic("upload_pending.rejected", {
                                                      {"actor",    *user_id,                      false},
                                                      {"media_id", std::string{media_id},         false},
                                                      {"reason",   result.reason,                 false},
                                                      {"status",   std::to_string(result.status), false}
        });
        append_local_audit(runtime.database, observability::AuditCategory::moderation, "media.upload_rejected",
                           *user_id, std::string{media_id}, result.reason);
        return refused_upload_result(result);
    }
    // DB-5: durable before the client is told; the reservation row goes in the
    // same transaction. On failure the upload is undone and the reservation kept.
    if (!persist_admitted_media(runtime, result.media_id, *user_id, result.quarantined, bytes, !result.deduplicated,
                                media_id))
    {
        return make_operation_result(false, {}, "media could not be stored", 500U);
    }
    media::complete_pending_media_upload(repository, media_id);
    runtime.media_upload_notifier->notify_uploaded();
    append_local_audit(runtime.database, observability::AuditCategory::moderation,
                       result.quarantined ? "media.upload_quarantined" : "media.upload_accepted", *user_id,
                       result.media_id,
                       result.quarantined ? result.reason : (result.deduplicated ? "deduplicated" : "stored"));
    return make_operation_result(true, result.content_uri, {}, 200U);
}

[[nodiscard]] auto download_local_media(HomeserverRuntime& runtime, std::string_view server_name,
                                        std::string_view media_id, bool legacy_endpoint,
                                        RemoteMediaRequestContext const& remote) -> OperationResult
{
    // OUT-7: before the policy hook, which can itself make a network call.
    if (!is_local_media_server(runtime, server_name))
    {
        if (auto refusal = remote_media_refusal(runtime, server_name, media_id, remote); refusal.has_value())
        {
            return std::move(*refusal);
        }
        if (legacy_endpoint)
        {
            if (auto frozen = legacy_remote_media_refusal(runtime, server_name, media_id); frozen.has_value())
            {
                return std::move(*frozen);
            }
        }
    }
    auto const policy = media_policy_decision(runtime, media_id);
    if (!policy.allowed)
    {
        return make_operation_result(false, {}, policy.reason.code, 403U);
    }

    if (!is_local_media_server(runtime, server_name))
    {
        log_diagnostic("download.remote", {
                                              {"origin_server", std::string{server_name}, false},
                                              {"media_id",      std::string{media_id},    false}
        });
        return fetch_remote_media_live(runtime, server_name, media_id, remote);
    }

    // ADR-0212: a reserved ID whose content is not here yet. The legacy
    // endpoints never serve media uploaded after the freeze (ADR-0068), so
    // they do not wait for it either.
    if (!legacy_endpoint)
    {
        if (auto pending = pending_download_answer(runtime, media_id, remote); pending.has_value())
        {
            return std::move(*pending);
        }
    }
    auto const target = media::resolve_local_media_download(runtime.media_repository, media_id, legacy_endpoint);
    if (!target.ok)
    {
        log_diagnostic("download.rejected", {
                                                {"media_id", std::string{media_id},         false},
                                                {"reason",   target.reason,                 false},
                                                {"status",   std::to_string(target.status), false}
        });
        return make_operation_result(false, {}, target.reason, target.status);
    }
    auto const upload_name = [&runtime, media_id] {
        auto const* record = media::find_local_media_record(runtime.media_repository, media_id);
        return record == nullptr ? std::string{} : record->upload_name;
    }();
    auto const bytes = read_servable_media_bytes(runtime, media_id, target.storage_id, legacy_endpoint);
    if (!bytes.has_value())
    {
        log_diagnostic("download.unavailable", {
                                                   {"media_id", std::string{media_id}, false}
        });
        return make_operation_result(false, {}, "media not found", 404U);
    }
    log_diagnostic("download.accepted",
                   {
                       {"media_id",     std::string{media_id}, false},
                       {"content_type", target.content_type,   false}
    });
    auto served = make_operation_result(true, target.content_type + "|" + *bytes, {}, 200U);
    served.media_filename = upload_name;
    return served;
}

[[nodiscard]] auto download_local_media_for_federation(HomeserverRuntime& runtime, std::string_view media_id)
    -> media::LocalMediaDownloadResult
{
    // The repository's lookups rebuild its indices, so they must never run
    // without the runtime mutex; it used to be read here unlocked.
    auto guard = std::unique_lock<RuntimeMutex>{runtime.mutex};
    auto const scope = RequestLockScope{guard};
    auto const decision = media_policy_decision(runtime, media_id);
    if (!decision.allowed)
    {
        return {false, 403U, {}, {}, decision.reason.public_summary};
    }
    // ADR-0212: inbound federation has no media fetch pool to wait on, so a
    // reserved ID without content is answered 504 M_NOT_YET_UPLOADED at once
    // (the spec lets the server respond before timeout_ms).
    if (media::find_local_media_record(runtime.media_repository, media_id) == nullptr &&
        media::find_pending_media_upload(runtime.media_repository, media_id, media::remote_media_cache_now_ms()) !=
            nullptr)
    {
        return {false, 504U, {}, {}, "Content has not yet been uploaded"};
    }
    auto const target = media::resolve_local_media_download(runtime.media_repository, media_id, false);
    if (!target.ok)
    {
        return {false, target.status, {}, {}, target.reason};
    }
    auto bytes = read_servable_media_bytes(runtime, media_id, target.storage_id, false);
    if (!bytes.has_value())
    {
        return {false, 404U, {}, {}, "media not found"};
    }
    return {true, 200U, target.content_type, std::move(*bytes), {}};
}

[[nodiscard]] auto download_local_media_thumbnail_for_federation(HomeserverRuntime& runtime,
                                                                 federation::FederationThumbnailQuery const& query)
    -> media::LocalMediaDownloadResult
{
    // As download_local_media_for_federation: the repository's lookups need the runtime mutex, and
    // the thumbnail path releases it itself for the decode (RuntimeLockRelease finds this guard).
    auto guard = std::unique_lock<RuntimeMutex>{runtime.mutex};
    auto const scope = RequestLockScope{guard};
    // Local media only: a remote server is never asked to fetch more media for another server. A
    // reserved ID whose content is missing is answered 504 M_NOT_YET_UPLOADED at once (timeout 0),
    // never waited for: inbound federation has no media fetch pool to wait on (ADR-0212).
    auto context = RemoteMediaRequestContext{};
    context.allow_remote = false;
    context.timeout_ms = 0U;
    // The decode cap (MED-4) counts the requesting server like a user, so one peer cannot hold
    // the decoder pool.
    context.requester = "federation:" + query.origin;
    context.client_key = context.requester;
    auto const result = download_local_media_thumbnail(runtime, runtime.config.server().server_name, query.media_id,
                                                       query.width, query.height, query.method, false, context);
    if (!result.ok)
    {
        return {false, result.status, {}, {}, result.reason};
    }
    auto const separator = result.value.find('|');
    if (separator == std::string::npos)
    {
        return {false, 500U, {}, {}, "thumbnail response malformed"};
    }
    return {true, 200U, result.value.substr(0U, separator), result.value.substr(separator + 1U), {}};
}

[[nodiscard]] auto download_local_media_thumbnail(HomeserverRuntime& runtime, std::string_view server_name,
                                                  std::string_view media_id, std::uint32_t width, std::uint32_t height,
                                                  media::ThumbnailMethod method, bool legacy_endpoint,
                                                  RemoteMediaRequestContext const& remote) -> OperationResult
{
    // OUT-7: as in download_local_media.
    if (!is_local_media_server(runtime, server_name))
    {
        if (auto refusal = remote_media_refusal(runtime, server_name, media_id, remote); refusal.has_value())
        {
            return std::move(*refusal);
        }
        if (legacy_endpoint)
        {
            if (auto frozen = legacy_remote_media_refusal(runtime, server_name, media_id); frozen.has_value())
            {
                return std::move(*frozen);
            }
        }
    }
    auto const policy = media_policy_decision(runtime, media_id);
    if (!policy.allowed)
    {
        return make_operation_result(false, {}, policy.reason.code, 403U);
    }

    if (!is_local_media_server(runtime, server_name))
    {
        log_diagnostic("thumbnail.remote", {
                                               {"origin_server", std::string{server_name}, false},
                                               {"media_id",      std::string{media_id},    false}
        });
        // Fetch the remote media first, then resample it locally so a thumbnail
        // request never answers with the full-size original.
        auto const fetch_result = fetch_remote_media_live(runtime, server_name, media_id, remote);
        if (!fetch_result.ok || fetch_result.status != 200U)
        {
            if (fetch_result.status >= 200U && fetch_result.status < 300U)
            {
                return make_operation_result(false, {}, "remote media was not admitted", 502U);
            }
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
        // MED-4: the bytes were admitted as a cached local record (unless the
        // remote cache is disabled); that record, not the fetch, authorises
        // serving the decode once the lock is taken again.
        auto remote_source = std::optional<LocalThumbnailSource>{};
        if (auto const* cached = media::find_cached_remote_media(runtime.media_repository, server_name, media_id,
                                                                 media::remote_media_cache_now_ms());
            cached != nullptr)
        {
            remote_source = LocalThumbnailSource{cached->media_id, cached->storage_id, false};
        }
        return generate_thumbnail_for_media(runtime, media_id, content_type, bytes, width, height, method,
                                            std::move(remote_source), thumbnail_requester(remote));
    }

    if (!legacy_endpoint)
    {
        if (auto pending = pending_download_answer(runtime, media_id, remote); pending.has_value())
        {
            return std::move(*pending);
        }
    }
    auto const* record = media::find_local_media_record(runtime.media_repository, media_id);
    if (record == nullptr || record->state != media::LocalMediaState::available ||
        (legacy_endpoint && !record->legacy_endpoint_visible))
    {
        log_diagnostic("thumbnail.not_found",
                       {
                           {"media_id", std::string{media_id}, false},
                           {"reason",   "record unavailable",  false}
        });
        return make_operation_result(false, {}, "thumbnail not found", 404U);
    }
    auto const local_source = LocalThumbnailSource{std::string{media_id}, record->storage_id, legacy_endpoint};
    auto const content_type = record->content_type;
    auto const bytes = read_servable_media_bytes(runtime, local_source.media_id, local_source.storage_id,
                                                 local_source.legacy_endpoint);
    if (!bytes.has_value())
    {
        log_diagnostic("thumbnail.blob_missing", {
                                                     {"media_id", std::string{media_id}, false}
        });
        return make_operation_result(false, {}, "thumbnail data not found", 404U);
    }

    return generate_thumbnail_for_media(runtime, media_id, content_type, *bytes, width, height, method,
                                        std::move(local_source), thumbnail_requester(remote));
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

    auto const validation = media::validate_local_media_admin_action(runtime.media_repository, media_id,
                                                                     media::LocalMediaAdminAction::quarantine, reason);
    if (!validation.ok)
    {
        return admin_result_to_operation(validation);
    }

    auto const audit = database::PersistentAuditEvent{"moderation", "media.quarantined", admin_user_id,
                                                      std::string{media_id}, std::string{reason}};
    if (!database::commit_local_media_moderation(runtime.database.persistent_store, media_id, true, false,
                                                 {admin_user_id, "media.quarantine", std::string{media_id}}, audit))
    {
        return make_operation_result(false, {}, "media moderation persistence failed", 500U);
    }

    auto const result = media::quarantine_local_media(runtime.media_repository, media_id, reason);
    if (result.ok)
    {
        remember_local_audit(runtime.database, observability::AuditCategory::moderation, audit.event_type, audit.actor,
                             audit.target, audit.reason);
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

    auto const validation = media::validate_local_media_admin_action(runtime.media_repository, media_id,
                                                                     media::LocalMediaAdminAction::release);
    if (!validation.ok)
    {
        return admin_result_to_operation(validation);
    }

    auto const audit = database::PersistentAuditEvent{"moderation", "media.released", admin_user_id,
                                                      std::string{media_id}, "released"};
    if (!database::commit_local_media_moderation(runtime.database.persistent_store, media_id, false, false,
                                                 {admin_user_id, "media.release", std::string{media_id}}, audit))
    {
        return make_operation_result(false, {}, "media moderation persistence failed", 500U);
    }

    auto const result = media::release_local_media(runtime.media_repository, media_id);
    if (result.ok)
    {
        remember_local_audit(runtime.database, observability::AuditCategory::moderation, audit.event_type, audit.actor,
                             audit.target, audit.reason);
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

    auto const validation = media::validate_local_media_admin_action(runtime.media_repository, media_id,
                                                                     media::LocalMediaAdminAction::remove, reason);
    if (!validation.ok)
    {
        return admin_result_to_operation(validation);
    }

    auto const audit = database::PersistentAuditEvent{"moderation", "media.removed", admin_user_id,
                                                      std::string{media_id}, std::string{reason}};
    if (!database::commit_local_media_moderation(runtime.database.persistent_store, media_id, false, true,
                                                 {admin_user_id, "media.remove", std::string{media_id}}, audit))
    {
        return make_operation_result(false, {}, "media moderation persistence failed", 500U);
    }

    auto const result = media::remove_local_media(runtime.media_repository, media_id, reason);
    if (result.ok)
    {
        remember_local_audit(runtime.database, observability::AuditCategory::moderation, audit.event_type, audit.actor,
                             audit.target, audit.reason);
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
