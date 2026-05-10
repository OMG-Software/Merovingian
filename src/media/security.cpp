// SPDX-License-Identifier: GPL-3.0-or-later

#include <merovingian/media/security.hpp>

#include <algorithm>
#include <string>

namespace merovingian::media
{
namespace
{

[[nodiscard]] auto starts_with(std::string_view value, std::string_view prefix) noexcept -> bool
{
    return value.size() >= prefix.size() && value.substr(0U, prefix.size()) == prefix;
}

[[nodiscard]] auto matrix_id_is_valid(std::string_view id) noexcept -> bool
{
    return id.size() >= 3U && id.front() == '@' && id.find(':') != std::string_view::npos;
}

[[nodiscard]] auto media_id_is_valid(std::string_view media_id) noexcept -> bool
{
    return !media_id.empty() && media_id.find('/') == std::string_view::npos && media_id.find("..") == std::string_view::npos;
}

[[nodiscard]] auto address_is_private_or_loopback(std::string_view address) noexcept -> bool
{
    return address == "localhost" || address == "::1" || starts_with(address, "127.")
        || starts_with(address, "10.") || starts_with(address, "192.168.") || starts_with(address, "169.254.")
        || starts_with(address, "fc") || starts_with(address, "fd")
        || (starts_with(address, "172.") && address.size() >= 6U && address[4] >= '1' && address[4] <= '3');
}

[[nodiscard]] auto server_name_is_valid(std::string_view server_name) noexcept -> bool
{
    return !server_name.empty() && server_name.find('.') != std::string_view::npos && server_name.find(' ') == std::string_view::npos;
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
        return {MediaDisposition::reject, "upload size limit is not configured"};
    }
    if (request.byte_size == 0U)
    {
        return {MediaDisposition::reject, "empty media upload"};
    }
    if (request.byte_size > policy.max_upload_bytes)
    {
        return {MediaDisposition::reject, "media upload exceeds size limit"};
    }
    if (policy.require_content_sniffing && request.sniffed_mime_type.empty())
    {
        return {MediaDisposition::quarantine, "content sniffing result required"};
    }
    if (!request.sniffed_mime_type.empty() && request.declared_mime_type != request.sniffed_mime_type)
    {
        return {MediaDisposition::quarantine, "declared MIME type does not match content"};
    }
    auto const mime_type = request.sniffed_mime_type.empty() ? std::string_view{request.declared_mime_type}
                                                            : std::string_view{request.sniffed_mime_type};
    if (!media_mime_type_is_allowed(policy, mime_type))
    {
        return {policy.quarantine_unknown_mime ? MediaDisposition::quarantine : MediaDisposition::reject, "media MIME type is not allowed"};
    }
    if (!request.scanner_clean)
    {
        return {policy.quarantine_scanner_failures ? MediaDisposition::quarantine : MediaDisposition::reject, "media scanner did not clear upload"};
    }
    if (request.content_hash.empty())
    {
        return {MediaDisposition::quarantine, "content hash required for deduplication"};
    }

    return {MediaDisposition::accept, {}};
}

auto remote_media_fetch_policy(RemoteMediaFetchRequest const& request) -> MediaPolicyDecision
{
    if (!request.isolate_remote_media)
    {
        return {MediaDisposition::reject, "remote media isolation is required"};
    }
    if (!server_name_is_valid(request.origin_server))
    {
        return {MediaDisposition::reject, "invalid remote media origin"};
    }
    if (!media_id_is_valid(request.media_id))
    {
        return {MediaDisposition::reject, "invalid remote media id"};
    }
    if (request.resolved_host.empty() || request.resolved_addresses.empty())
    {
        return {MediaDisposition::reject, "remote media host is unresolved"};
    }
    if (request.private_address_fetches_blocked)
    {
        for (auto const& address : request.resolved_addresses)
        {
            if (address_is_private_or_loopback(address))
            {
                return {MediaDisposition::reject, "remote media address is private or loopback"};
            }
        }
    }

    return {MediaDisposition::accept, {}};
}

auto sandboxed_worker_plan_is_hardened(SandboxedMediaWorkerPlan const& plan) noexcept -> bool
{
    return plan.dedicated_worker && plan.network_disabled && plan.read_only_root && plan.private_tmp
        && plan.seccomp_required && plan.decode_timeout_seconds > 0U && plan.memory_limit_bytes > 0U;
}

auto evaluate_decoder_safety(DecoderSafetyPolicy const& policy, DecoderSafetyRequest const& request)
    -> MediaPolicyDecision
{
    if (policy.unsafe_decoders_disabled && !request.decoder_marked_safe)
    {
        return {MediaDisposition::reject, "decoder is not allowed"};
    }
    if (request.input_bytes > policy.max_input_bytes)
    {
        return {MediaDisposition::reject, "decoder input exceeds limit"};
    }
    if (request.estimated_output_bytes > policy.max_output_bytes)
    {
        return {MediaDisposition::reject, "decoded output exceeds limit"};
    }
    if (request.pixels > policy.max_pixels)
    {
        return {MediaDisposition::reject, "decoded image dimensions exceed limit"};
    }
    if (request.animation_frames > policy.max_animation_frames)
    {
        return {MediaDisposition::reject, "animation frame count exceeds limit"};
    }
    if (request.input_bytes > 0U && request.estimated_output_bytes / request.input_bytes > policy.max_expansion_ratio)
    {
        return {MediaDisposition::reject, "decoded output expansion ratio exceeds limit"};
    }

    return {MediaDisposition::accept, {}};
}

auto media_deduplication_key_is_valid(MediaDeduplicationKey const& key) noexcept -> bool
{
    return !key.hash_algorithm.empty() && !key.digest.empty() && key.byte_size > 0U;
}

auto make_media_deduplication_key(
    std::string_view hash_algorithm,
    std::string_view digest,
    std::uint64_t byte_size
) -> MediaDeduplicationKey
{
    return {std::string{hash_algorithm}, std::string{digest}, byte_size};
}

auto admin_quarantine_policy(AdminQuarantineRequest const& request) -> MediaPolicyDecision
{
    if (!matrix_id_is_valid(request.admin_user_id))
    {
        return {MediaDisposition::reject, "invalid admin user id"};
    }
    if (!media_id_is_valid(request.media_id))
    {
        return {MediaDisposition::reject, "invalid media id"};
    }
    if (request.reason.empty() && request.action != AdminQuarantineAction::release)
    {
        return {MediaDisposition::reject, "quarantine reason is required"};
    }

    return {MediaDisposition::accept, {}};
}

auto media_security_boundary_notes() -> std::vector<std::string>
{
    return {
        "Remote media boundary: isolate remote fetches from local upload storage and reject private or loopback resolved addresses.",
        "Decoder boundary: decode media only in a sandboxed worker with no network, read-only root, private temporary storage, time limits, and memory limits.",
        "Expansion boundary: reject unsafe decoder choices, excessive output size, excessive pixels, too many animation frames, or suspicious decoded-output expansion ratios.",
        "Quarantine boundary: unknown MIME, mismatched MIME, scanner failures, missing hashes, and administrator actions use explicit quarantine decisions.",
    };
}

} // namespace merovingian::media
