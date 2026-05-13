// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/vertical_slice.hpp"

#include "local_services.hpp"

#include "merovingian/database/persistent_store.hpp"
#include "merovingian/media/repository.hpp"

#include <string>
#include <string_view>

namespace merovingian::homeserver
{
namespace
{

[[nodiscard]] auto admin_result_to_operation(media::LocalMediaAdminResult const& result)
    -> OperationResult
{
    return make_operation_result(
        result.ok, result.media_id + "|" + media::local_media_state_name(result.state),
        result.reason, result.status);
}

} // namespace

[[nodiscard]] auto upload_local_media(HomeserverRuntime& runtime, std::string_view access_token,
                                      std::string_view declared_mime_type,
                                      std::string_view sniffed_mime_type, bool scanner_clean,
                                      std::string_view bytes) -> OperationResult
{
    auto const user_id = authenticated_user(runtime, access_token);
    if (!user_id.has_value())
    {
        return make_operation_result(false, {}, "unauthenticated", 401U);
    }

    auto const result = media::upload_local_media(
        runtime.media_repository, runtime.config.server().server_name,
        {*user_id, std::string{declared_mime_type}, std::string{sniffed_mime_type},
         std::string{bytes}, scanner_clean});
    if (!result.ok)
    {
        append_local_audit(runtime.database, observability::AuditCategory::moderation,
                           "media.upload_rejected", *user_id, "local-media", result.reason);
        return make_operation_result(false, {}, result.reason, result.status);
    }

    (void)database::store_local_media(runtime.database.persistent_store, {
                                                                             result.media_id,
                                                                             *user_id,
                                                                             result.content_type,
                                                                             result.size_bytes,
                                                                             result.hash_algorithm,
                                                                             result.digest,
                                                                             result.quarantined,
                                                                             false,
                                                                         });
    append_local_audit(runtime.database, observability::AuditCategory::moderation,
                       result.quarantined ? "media.upload_quarantined" : "media.upload_accepted",
                       *user_id, result.media_id,
                       result.quarantined ? result.reason
                                          : (result.deduplicated ? "deduplicated" : "stored"));
    return make_operation_result(
        true,
        result.content_uri + "|" + result.content_type + "|" + result.hash_algorithm + ':' +
            result.digest + "|deduplicated=" + std::string{result.deduplicated ? "true" : "false"} +
            "|quarantined=" + std::string{result.quarantined ? "true" : "false"},
        {}, result.status);
}

[[nodiscard]] auto download_local_media(HomeserverRuntime& runtime, std::string_view server_name,
                                        std::string_view media_id) -> OperationResult
{
    if (server_name != runtime.config.server().server_name)
    {
        return remote_media_fetch_disabled(runtime, server_name, media_id);
    }

    auto const result =
        media::download_local_media(runtime.media_repository, server_name, media_id);
    if (!result.ok)
    {
        return make_operation_result(false, {}, result.reason, result.status);
    }
    return make_operation_result(true, result.content_type + "|" + result.bytes, {}, result.status);
}

[[nodiscard]] auto admin_quarantine_local_media(HomeserverRuntime& runtime,
                                                std::string_view access_token,
                                                std::string_view media_id, std::string_view reason)
    -> OperationResult
{
    auto const admin_user_id = authenticated_admin_user(runtime, access_token);
    if (!admin_user_id.has_value())
    {
        return make_operation_result(false, {}, "admin authentication required", 401U);
    }

    auto const result = media::quarantine_local_media(runtime.media_repository, media_id, reason);
    if (result.ok)
    {
        (void)database::update_local_media_state(runtime.database.persistent_store, media_id, true,
                                                 false);
        (void)database::append_admin_action(
            runtime.database.persistent_store,
            {*admin_user_id, "media.quarantine", std::string{media_id}});
        append_local_audit(runtime.database, observability::AuditCategory::moderation,
                           "media.quarantined", *admin_user_id, media_id, reason);
    }
    return admin_result_to_operation(result);
}

[[nodiscard]] auto admin_release_local_media(HomeserverRuntime& runtime,
                                             std::string_view access_token,
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
        (void)database::update_local_media_state(runtime.database.persistent_store, media_id, false,
                                                 false);
        (void)database::append_admin_action(
            runtime.database.persistent_store,
            {*admin_user_id, "media.release", std::string{media_id}});
        append_local_audit(runtime.database, observability::AuditCategory::moderation,
                           "media.released", *admin_user_id, media_id, "released");
    }
    return admin_result_to_operation(result);
}

[[nodiscard]] auto admin_remove_local_media(HomeserverRuntime& runtime,
                                            std::string_view access_token,
                                            std::string_view media_id, std::string_view reason)
    -> OperationResult
{
    auto const admin_user_id = authenticated_admin_user(runtime, access_token);
    if (!admin_user_id.has_value())
    {
        return make_operation_result(false, {}, "admin authentication required", 401U);
    }

    auto const result = media::remove_local_media(runtime.media_repository, media_id, reason);
    if (result.ok)
    {
        (void)database::update_local_media_state(runtime.database.persistent_store, media_id, false,
                                                 true);
        (void)database::append_admin_action(
            runtime.database.persistent_store,
            {*admin_user_id, "media.remove", std::string{media_id}});
        append_local_audit(runtime.database, observability::AuditCategory::moderation,
                           "media.removed", *admin_user_id, media_id, reason);
    }
    return admin_result_to_operation(result);
}

[[nodiscard]] auto remote_media_fetch_disabled(HomeserverRuntime& runtime,
                                               std::string_view origin_server,
                                               std::string_view media_id) -> OperationResult
{
    auto const result = media::fetch_remote_media_disabled(
        runtime.media_repository,
        {std::string{origin_server}, std::string{media_id}, std::string{origin_server}, {}});
    append_local_audit(runtime.database, observability::AuditCategory::moderation,
                       "media.remote_fetch_rejected", "server",
                       std::string{origin_server} + '/' + std::string{media_id}, result.reason);
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
