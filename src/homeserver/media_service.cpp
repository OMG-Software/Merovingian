// SPDX-License-Identifier: GPL-3.0-or-later

#include "local_services.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/homeserver/auth_service.hpp"
#include "merovingian/homeserver/media_service.hpp"
#include "merovingian/media/repository.hpp"
#include "merovingian/observability/logger.hpp"
#include "merovingian/observability/observability.hpp"

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

} // namespace

[[nodiscard]] auto upload_local_media(HomeserverRuntime& runtime, std::string_view access_token,
                                      std::string_view declared_mime_type, std::string_view sniffed_mime_type,
                                      bool scanner_clean, std::string_view bytes) -> OperationResult
{
    auto const user_id = authenticated_user(runtime, access_token);
    if (!user_id.has_value())
    {
        log_diagnostic("upload.rejected", {{"reason", "unauthenticated", false}});
        return make_operation_result(false, {}, "unauthenticated", 401U);
    }

    auto const result = media::upload_local_media(
        runtime.media_repository, runtime.config.server().server_name,
        {*user_id, std::string{declared_mime_type}, std::string{sniffed_mime_type}, std::string{bytes}, scanner_clean});
    if (!result.ok)
    {
        log_diagnostic("upload.rejected",
                       {{"actor",     *user_id,                              false},
                        {"mime_type", std::string{declared_mime_type},       false},
                        {"reason",    result.reason,                         false},
                        {"status",    std::to_string(result.status),         false}});
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
                   {{"actor",        *user_id,                                                        false},
                    {"media_id",     result.media_id,                                                 false},
                    {"content_type", result.content_type,                                             false},
                    {"size_bytes",   std::to_string(result.size_bytes),                               false},
                    {"deduplicated", std::string{result.deduplicated ? "true" : "false"},             false},
                    {"quarantined",  std::string{result.quarantined  ? "true" : "false"},             false}});
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
    if (server_name != runtime.config.server().server_name)
    {
        log_diagnostic("download.remote_rejected",
                       {{"origin_server", std::string{server_name}, false},
                        {"media_id",      std::string{media_id},    false},
                        {"reason",        "remote media fetch disabled", false}});
        return remote_media_fetch_disabled(runtime, server_name, media_id);
    }

    auto const result = media::download_local_media(runtime.media_repository, server_name, media_id);
    if (!result.ok)
    {
        log_diagnostic("download.rejected",
                       {{"media_id", std::string{media_id}, false},
                        {"reason",   result.reason,          false},
                        {"status",   std::to_string(result.status), false}});
        return make_operation_result(false, {}, result.reason, result.status);
    }
    log_diagnostic("download.accepted",
                   {{"media_id",     std::string{media_id},    false},
                    {"content_type", result.content_type,      false}});
    return make_operation_result(true, result.content_type + "|" + result.bytes, {}, result.status);
}

[[nodiscard]] auto download_local_media_thumbnail(HomeserverRuntime& runtime, std::string_view server_name,
                                                  std::string_view media_id) -> OperationResult
{
    if (server_name != runtime.config.server().server_name)
    {
        log_diagnostic("thumbnail.remote_rejected",
                       {{"origin_server", std::string{server_name}, false},
                        {"media_id",      std::string{media_id},    false},
                        {"reason",        "remote media fetch disabled", false}});
        return remote_media_fetch_disabled(runtime, server_name, media_id);
    }

    auto const* thumbnail = media::find_local_media_thumbnail(runtime.media_repository, media_id);
    if (thumbnail == nullptr)
    {
        log_diagnostic("thumbnail.not_found",
                       {{"media_id", std::string{media_id}, false},
                        {"reason",   "thumbnail not found", false}});
        return make_operation_result(false, {}, "thumbnail not found", 404U);
    }
    auto const* blob = media::find_local_media_blob(runtime.media_repository, thumbnail->storage_id);
    if (blob == nullptr)
    {
        log_diagnostic("thumbnail.blob_missing",
                       {{"media_id",   std::string{media_id},    false},
                        {"storage_id", thumbnail->storage_id, false}});
        return make_operation_result(false, {}, "thumbnail data not found", 404U);
    }
    log_diagnostic("thumbnail.accepted",
                   {{"media_id",     std::string{media_id},    false},
                    {"content_type", thumbnail->content_type,  false}});
    return make_operation_result(true, thumbnail->content_type + "|" + blob->bytes, {}, 200U);
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
