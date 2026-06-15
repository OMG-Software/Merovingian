// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/media_service.hpp"

#include "merovingian/database/persistent_store.hpp"
#include "merovingian/federation/server_discovery.hpp"
#include "merovingian/homeserver/auth_service.hpp"
#include "merovingian/homeserver/local_services.hpp"
#include "merovingian/http/outbound_client.hpp"
#include "merovingian/media/repository.hpp"
#include "merovingian/observability/logger.hpp"
#include "merovingian/observability/observability.hpp"
#include "merovingian/trust_safety/policy_engine.hpp"

#include <cctype>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <tuple>
#include <vector>

namespace merovingian::homeserver
{
namespace
{

    auto log_diagnostic(std::string_view event, std::vector<observability::StructuredLogField> fields) -> void
    {
        LOG_DEBUG(observability::diagnostic_log_summary("media_service", event, std::move(fields)));
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

    // Fetch remote media via server discovery + HTTPS GET to /_matrix/media/v3/download/.
    // On success the media is stored locally and the result contains the bytes. Falls back
    // to remote_media_fetch_disabled() when federation infrastructure is unavailable.
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

        auto constexpr discovery_timeout = std::uint32_t{30U};
        auto const resolution = federation::discover_server(origin_server, *discovery_network, discovery_timeout);
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

        auto url = "https://" + resolution.resolved_host + ':' + std::to_string(resolution.resolved_port) +
                   "/_matrix/media/v3/download/" + std::string{media_id};
        auto const max_bytes = runtime.media_repository.config.max_upload_bytes > 0U
                                   ? runtime.media_repository.config.max_upload_bytes
                                   : std::uint64_t{16U * 1024U * 1024U};

        auto out_req = http::OutboundRequest{};
        out_req.method = "GET";
        out_req.url = std::move(url);
        out_req.pinned_addresses = resolution.pinned_addresses;
        out_req.connect_timeout_seconds = 30U;
        out_req.total_timeout_seconds = 120U;
        out_req.max_response_body_bytes = static_cast<std::size_t>(max_bytes);

        auto const out_result = outbound_client->perform(out_req);
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

        // Extract Content-Type from response headers. HTTP header names are case-insensitive;
        // check the two most common capitalisation variants sent by real homeservers.
        auto content_type = std::string{"application/octet-stream"};
        for (auto const& header : out_result.response.headers)
        {
            auto equal_ci = [](std::string const& a, std::string_view b) noexcept -> bool {
                if (a.size() != b.size())
                    return false;
                for (std::size_t i = 0U; i < a.size(); ++i)
                {
                    if (std::tolower(static_cast<unsigned char>(a[i])) !=
                        std::tolower(static_cast<unsigned char>(b[i])))
                        return false;
                }
                return true;
            };
            if (equal_ci(header.name, "content-type"))
            {
                content_type = header.value;
                // Strip MIME parameters (e.g. "image/jpeg; charset=utf-8" → "image/jpeg").
                auto const semicolon = content_type.find(';');
                if (semicolon != std::string::npos)
                {
                    content_type.resize(semicolon);
                }
                while (!content_type.empty() && content_type.back() == ' ')
                {
                    content_type.pop_back();
                }
                break;
            }
        }

        auto remote_req = media::RemoteMediaDownloadRequest{};
        remote_req.origin_server = std::string{origin_server};
        remote_req.media_id = std::string{media_id};
        remote_req.resolved_host = resolution.resolved_host;
        remote_req.resolved_addresses = resolution.pinned_addresses;
        remote_req.content_type = content_type;
        remote_req.bytes = out_result.response.body;
        remote_req.scanner_clean = true;
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

} // namespace

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
        // Remote thumbnailing is not yet performed locally; serve the fetched
        // remote media as-is.
        return fetch_remote_media_live(runtime, server_name, media_id);
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

    // Resample in the sandboxed worker. Anything the worker cannot handle
    // (unsupported format, worker not installed, decode failure) degrades to
    // serving the original bytes so a thumbnail request never hard-fails.
    auto const& media_config = runtime.media_repository.config;
    auto thumbnailer_config = media::ThumbnailerConfig{};
    thumbnailer_config.worker_path = media_config.thumbnail_worker_path;
    thumbnailer_config.timeout_seconds = media_config.thumbnail_timeout_seconds;
    thumbnailer_config.max_input_bytes = media_config.max_decode_input_bytes;
    thumbnailer_config.max_output_bytes = media_config.max_decode_output_bytes;
    thumbnailer_config.max_pixels = static_cast<std::uint32_t>(media_config.max_decode_pixels);

    auto request = media::ThumbnailRequest{};
    request.source_bytes = blob->bytes;
    request.source_content_type = record->content_type;
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
        log_diagnostic("thumbnail.fallback_original", {
                                                          {"media_id", std::string{media_id},         false},
                                                          {"reason",   result.reason,                 false},
                                                          {"status",   std::to_string(result.status), false}
        });
    }

    // Fallback: serve the original media bytes with their own content type.
    log_diagnostic("thumbnail.accepted_original",
                   {
                       {"media_id",     std::string{media_id}, false},
                       {"content_type", record->content_type,  false}
    });
    return make_operation_result(true, record->content_type + "|" + blob->bytes, {}, 200U);
}

[[nodiscard]] auto admin_quarantine_local_media(HomeserverRuntime& runtime, std::string_view access_token,
                                                std::string_view media_id, std::string_view reason) -> OperationResult
{
    auto const admin_user_id = authenticated_admin_user(runtime, access_token);
    if (!admin_user_id.has_value())
    {
        return make_operation_result(false, {}, "admin authentication required", 401U);
    }

    auto const result = media::quarantine_local_media(runtime.media_repository, media_id, reason);
    if (result.ok)
    {
        std::ignore = database::update_local_media_state(runtime.database.persistent_store, media_id, true, false);
        std::ignore = database::append_admin_action(runtime.database.persistent_store,
                                                    {*admin_user_id, "media.quarantine", std::string{media_id}});
        append_local_audit(runtime.database, observability::AuditCategory::moderation, "media.quarantined",
                           *admin_user_id, media_id, reason);
    }
    return admin_result_to_operation(result);
}

[[nodiscard]] auto admin_release_local_media(HomeserverRuntime& runtime, std::string_view access_token,
                                             std::string_view media_id) -> OperationResult
{
    auto const admin_user_id = authenticated_admin_user(runtime, access_token);
    if (!admin_user_id.has_value())
    {
        return make_operation_result(false, {}, "admin authentication required", 401U);
    }

    auto const result = media::release_local_media(runtime.media_repository, media_id);
    if (result.ok)
    {
        std::ignore = database::update_local_media_state(runtime.database.persistent_store, media_id, false, false);
        std::ignore = database::append_admin_action(runtime.database.persistent_store,
                                                    {*admin_user_id, "media.release", std::string{media_id}});
        append_local_audit(runtime.database, observability::AuditCategory::moderation, "media.released", *admin_user_id,
                           media_id, "released");
    }
    return admin_result_to_operation(result);
}

[[nodiscard]] auto admin_remove_local_media(HomeserverRuntime& runtime, std::string_view access_token,
                                            std::string_view media_id, std::string_view reason) -> OperationResult
{
    auto const admin_user_id = authenticated_admin_user(runtime, access_token);
    if (!admin_user_id.has_value())
    {
        return make_operation_result(false, {}, "admin authentication required", 401U);
    }

    auto const result = media::remove_local_media(runtime.media_repository, media_id, reason);
    if (result.ok)
    {
        std::ignore = database::update_local_media_state(runtime.database.persistent_store, media_id, false, true);
        persist_blob_for_media(runtime, media_id);
        std::ignore = database::append_admin_action(runtime.database.persistent_store,
                                                    {*admin_user_id, "media.remove", std::string{media_id}});
        append_local_audit(runtime.database, observability::AuditCategory::moderation, "media.removed", *admin_user_id,
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
