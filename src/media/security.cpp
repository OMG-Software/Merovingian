// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/media/security.hpp"

#include "merovingian/federation/security.hpp"
#include "merovingian/observability/logger.hpp"
#include "merovingian/observability/observability.hpp"

#include <algorithm>
#include <string>
#include <vector>

namespace merovingian::media
{
namespace
{

    auto log_diagnostic(std::string_view event, std::vector<observability::StructuredLogField> fields,
                        observability::LogEventSeverity severity = observability::LogEventSeverity::debug) -> void
    {
        observability::log_diagnostic("media_security", event, fields, severity);
    }

    [[nodiscard]] auto matrix_id_is_valid(std::string_view id) noexcept -> bool
    {
        return id.size() >= 3U && id.front() == '@' && id.find(':') != std::string_view::npos;
    }

    [[nodiscard]] auto media_id_is_valid(std::string_view media_id) noexcept -> bool
    {
        return !media_id.empty() && media_id.find('/') == std::string_view::npos &&
               media_id.find("..") == std::string_view::npos;
    }

    [[nodiscard]] auto address_is_private_or_loopback(std::string_view address) noexcept -> bool
    {
        // Delegate to the federation helper, which uses inet_pton for exact
        // numeric private/loopback range checks (including 172.16/12, IPv4-mapped
        // IPv6, ULA, and link-local) and is the single source of truth for SSRF
        // address filtering. The prior string-prefix duplicate over-blocked public
        // 172.1-172.3 and under-blocked the rest of 172.16/12.
        return federation::ip_address_is_private_or_loopback(address);
    }

    [[nodiscard]] auto server_name_is_valid(std::string_view server_name) noexcept -> bool
    {
        return !server_name.empty() && server_name.find('.') != std::string_view::npos &&
               server_name.find(' ') == std::string_view::npos;
    }

} // namespace

auto media_disposition_name(MediaDisposition disposition) noexcept -> char const*
{
    switch (disposition)
    {
    case MediaDisposition::accept:
        return "accept";
    case MediaDisposition::quarantine:
        return "quarantine";
    case MediaDisposition::reject:
        return "reject";
    }

    return "unknown";
}

auto media_mime_type_is_allowed(MediaUploadPolicy const& policy, std::string_view mime_type) noexcept -> bool
{
    return std::ranges::any_of(policy.allowed_mime_types, [mime_type](std::string const& allowed) {
        return allowed == mime_type;
    });
}

auto evaluate_media_upload(MediaUploadPolicy const& policy, MediaUploadRequest const& request) -> MediaPolicyDecision
{
    if (policy.max_upload_bytes == 0U)
    {
        log_diagnostic("upload.rejected", {{"reason", "upload size limit is not configured", false}});
        return {MediaDisposition::reject, "upload size limit is not configured"};
    }
    if (request.byte_size == 0U)
    {
        log_diagnostic("upload.rejected", {{"reason", "empty media upload", false}});
        return {MediaDisposition::reject, "empty media upload"};
    }
    if (request.byte_size > policy.max_upload_bytes)
    {
        log_diagnostic("upload.rejected",
                       {{"byte_size", std::to_string(request.byte_size), false},
                        {"max_upload_bytes", std::to_string(policy.max_upload_bytes), false},
                        {"reason", "media upload exceeds size limit", false}});
        return {MediaDisposition::reject, "media upload exceeds size limit"};
    }
    if (policy.require_content_sniffing && request.sniffed_mime_type.empty())
    {
        log_diagnostic("upload.quarantined", {{"reason", "content sniffing result required", false}});
        return {MediaDisposition::quarantine, "content sniffing result required"};
    }
    if (!request.sniffed_mime_type.empty() && request.declared_mime_type != request.sniffed_mime_type)
    {
        log_diagnostic("upload.quarantined",
                       {{"declared_mime_type", request.declared_mime_type, false},
                        {"sniffed_mime_type", request.sniffed_mime_type, false},
                        {"reason", "declared MIME type does not match content", false}});
        return {MediaDisposition::quarantine, "declared MIME type does not match content"};
    }
    auto const mime_type = request.sniffed_mime_type.empty() ? std::string_view{request.declared_mime_type}
                                                             : std::string_view{request.sniffed_mime_type};
    if (!media_mime_type_is_allowed(policy, mime_type))
    {
        auto const disposition = policy.quarantine_unknown_mime ? MediaDisposition::quarantine : MediaDisposition::reject;
        log_diagnostic(disposition == MediaDisposition::quarantine ? "upload.quarantined" : "upload.rejected",
                       {{"mime_type", std::string{mime_type}, false},
                        {"reason", "media MIME type is not allowed", false}});
        return {disposition, "media MIME type is not allowed"};
    }
    if (!request.scanner_clean)
    {
        auto const disposition =
            policy.quarantine_scanner_failures ? MediaDisposition::quarantine : MediaDisposition::reject;
        log_diagnostic(disposition == MediaDisposition::quarantine ? "upload.quarantined" : "upload.rejected",
                       {{"reason", "media scanner did not clear upload", false}});
        return {disposition, "media scanner did not clear upload"};
    }
    if (request.content_hash.empty())
    {
        log_diagnostic("upload.quarantined", {{"reason", "content hash required for deduplication", false}});
        return {MediaDisposition::quarantine, "content hash required for deduplication"};
    }

    return {MediaDisposition::accept, {}};
}

auto remote_media_fetch_policy(RemoteMediaFetchRequest const& request) -> MediaPolicyDecision
{
    if (!request.isolate_remote_media)
    {
        log_diagnostic("remote_fetch.rejected", {{"reason", "remote media isolation is required", false}});
        return {MediaDisposition::reject, "remote media isolation is required"};
    }
    if (!server_name_is_valid(request.origin_server))
    {
        log_diagnostic("remote_fetch.rejected",
                       {{"origin_server", request.origin_server, false},
                        {"reason", "invalid remote media origin", false}});
        return {MediaDisposition::reject, "invalid remote media origin"};
    }
    if (!media_id_is_valid(request.media_id))
    {
        log_diagnostic("remote_fetch.rejected",
                       {{"origin_server", request.origin_server, false},
                        {"reason", "invalid remote media id", false}});
        return {MediaDisposition::reject, "invalid remote media id"};
    }
    if (request.resolved_host.empty() || request.resolved_addresses.empty())
    {
        log_diagnostic("remote_fetch.rejected",
                       {{"origin_server", request.origin_server, false},
                        {"reason", "remote media host is unresolved", false}});
        return {MediaDisposition::reject, "remote media host is unresolved"};
    }
    if (request.private_address_fetches_blocked)
    {
        for (auto const& address : request.resolved_addresses)
        {
            if (address_is_private_or_loopback(address))
            {
                log_diagnostic("remote_fetch.rejected",
                               {{"origin_server", request.origin_server, false},
                                {"address", address, false},
                                {"reason", "remote media address is private or loopback", false}});
                return {MediaDisposition::reject, "remote media address is private or loopback"};
            }
        }
    }

    return {MediaDisposition::accept, {}};
}

auto sandboxed_worker_plan_is_hardened(SandboxedMediaWorkerPlan const& plan) noexcept -> bool
{
    return plan.dedicated_worker && plan.network_disabled && plan.read_only_root && plan.private_tmp &&
           plan.seccomp_required && plan.decode_timeout_seconds > 0U && plan.memory_limit_bytes > 0U;
}

auto evaluate_decoder_safety(DecoderSafetyPolicy const& policy, DecoderSafetyRequest const& request)
    -> MediaPolicyDecision
{
    if (policy.unsafe_decoders_disabled && !request.decoder_marked_safe)
    {
        log_diagnostic("decoder.rejected", {{"reason", "decoder is not allowed", false}});
        return {MediaDisposition::reject, "decoder is not allowed"};
    }
    if (request.input_bytes > policy.max_input_bytes)
    {
        log_diagnostic("decoder.rejected",
                       {{"input_bytes", std::to_string(request.input_bytes), false},
                        {"max_input_bytes", std::to_string(policy.max_input_bytes), false},
                        {"reason", "decoder input exceeds limit", false}});
        return {MediaDisposition::reject, "decoder input exceeds limit"};
    }
    if (request.estimated_output_bytes > policy.max_output_bytes)
    {
        log_diagnostic("decoder.rejected",
                       {{"estimated_output_bytes", std::to_string(request.estimated_output_bytes), false},
                        {"max_output_bytes", std::to_string(policy.max_output_bytes), false},
                        {"reason", "decoded output exceeds limit", false}});
        return {MediaDisposition::reject, "decoded output exceeds limit"};
    }
    if (request.pixels > policy.max_pixels)
    {
        log_diagnostic("decoder.rejected",
                       {{"pixels", std::to_string(request.pixels), false},
                        {"max_pixels", std::to_string(policy.max_pixels), false},
                        {"reason", "decoded image dimensions exceed limit", false}});
        return {MediaDisposition::reject, "decoded image dimensions exceed limit"};
    }
    if (request.animation_frames > policy.max_animation_frames)
    {
        log_diagnostic("decoder.rejected",
                       {{"animation_frames", std::to_string(request.animation_frames), false},
                        {"max_animation_frames", std::to_string(policy.max_animation_frames), false},
                        {"reason", "animation frame count exceeds limit", false}});
        return {MediaDisposition::reject, "animation frame count exceeds limit"};
    }
    if (request.input_bytes > 0U && request.estimated_output_bytes / request.input_bytes > policy.max_expansion_ratio)
    {
        log_diagnostic("decoder.rejected",
                       {{"expansion_ratio",
                         std::to_string(request.estimated_output_bytes / request.input_bytes), false},
                        {"max_expansion_ratio", std::to_string(policy.max_expansion_ratio), false},
                        {"reason", "decoded output expansion ratio exceeds limit", false}});
        return {MediaDisposition::reject, "decoded output expansion ratio exceeds limit"};
    }

    return {MediaDisposition::accept, {}};
}

auto media_deduplication_key_is_valid(MediaDeduplicationKey const& key) noexcept -> bool
{
    return !key.hash_algorithm.empty() && !key.digest.empty() && key.byte_size > 0U;
}

auto make_media_deduplication_key(std::string_view hash_algorithm, std::string_view digest, std::uint64_t byte_size)
    -> MediaDeduplicationKey
{
    return {std::string{hash_algorithm}, std::string{digest}, byte_size};
}

auto admin_quarantine_policy(AdminQuarantineRequest const& request) -> MediaPolicyDecision
{
    if (!matrix_id_is_valid(request.admin_user_id))
    {
        log_diagnostic("admin_quarantine.rejected", {{"reason", "invalid admin user id", false}});
        return {MediaDisposition::reject, "invalid admin user id"};
    }
    if (!media_id_is_valid(request.media_id))
    {
        log_diagnostic("admin_quarantine.rejected",
                       {{"admin_user_id", request.admin_user_id, false},
                        {"reason", "invalid media id", false}});
        return {MediaDisposition::reject, "invalid media id"};
    }
    if (request.reason.empty() && request.action != AdminQuarantineAction::release)
    {
        log_diagnostic("admin_quarantine.rejected",
                       {{"admin_user_id", request.admin_user_id, false},
                        {"media_id", request.media_id, false},
                        {"reason", "quarantine reason is required", false}});
        return {MediaDisposition::reject, "quarantine reason is required"};
    }

    return {MediaDisposition::accept, {}};
}

auto media_security_boundary_notes() -> std::vector<std::string>
{
    return {
        "Remote media boundary: isolate remote fetches from local upload storage and reject private or loopback "
        "resolved addresses.",
        "Decoder boundary: decode media only in a sandboxed worker with no network, read-only root, private temporary "
        "storage, time limits, and memory limits.",
        "Expansion boundary: reject unsafe decoder choices, excessive output size, excessive pixels, too many "
        "animation frames, or suspicious decoded-output expansion ratios.",
        "Quarantine boundary: unknown MIME, mismatched MIME, scanner failures, missing hashes, and administrator "
        "actions use explicit quarantine decisions.",
    };
}

} // namespace merovingian::media
