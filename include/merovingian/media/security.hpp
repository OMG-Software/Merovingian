// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace merovingian::media
{

enum class MediaDisposition
{
    accept,
    quarantine,
    reject,
};

struct MediaPolicyDecision final
{
    MediaDisposition disposition{MediaDisposition::reject};
    std::string reason{};
};

// Operator-selectable disposition for a class of media (local upload or
// remote/federated fetch), configured via `security.media.local_upload_policy`
// and `security.media.remote_fetch_media_policy`:
//   allow            - accept unconditionally; the scanner verdict is ignored.
//   allow_after_scan - accept only when the scanner verdict is clean (the
//                      historical, only, behaviour before this policy existed).
//   quarantine       - always hold for manual admin review, regardless of
//                      the scanner verdict.
//   deny             - reject unconditionally; this class of media is disabled.
enum class MediaAcceptancePolicy
{
    allow,
    allow_after_scan,
    quarantine,
    deny,
};

[[nodiscard]] auto media_acceptance_policy_name(MediaAcceptancePolicy policy) noexcept -> std::string_view;
// Falls back to the safest option (quarantine) for unrecognised input. Config
// parsing validates the string against exactly these four spellings before
// this ever runs, so the fallback is a defence-in-depth net, not a live path.
[[nodiscard]] auto parse_media_acceptance_policy(std::string_view value) noexcept -> MediaAcceptancePolicy;

struct MediaUploadPolicy final
{
    std::uint64_t max_upload_bytes{0U};
    std::vector<std::string> allowed_mime_types{};
    bool require_content_sniffing{true};
    bool quarantine_unknown_mime{true};
    bool quarantine_scanner_failures{true};
    MediaAcceptancePolicy acceptance_policy{MediaAcceptancePolicy::allow_after_scan};
};

struct MediaUploadRequest final
{
    std::uint64_t byte_size{0U};
    std::string declared_mime_type{};
    std::string sniffed_mime_type{};
    std::string content_hash{};
    bool scanner_clean{true};
};

struct RemoteMediaFetchRequest final
{
    std::string origin_server{};
    std::string media_id{};
    std::string resolved_host{};
    std::vector<std::string> resolved_addresses{};
    bool isolate_remote_media{true};
    bool private_address_fetches_blocked{true};
};

struct SandboxedMediaWorkerPlan final
{
    bool dedicated_worker{true};
    bool network_disabled{true};
    bool read_only_root{true};
    bool private_tmp{true};
    bool seccomp_required{true};
    std::uint32_t decode_timeout_seconds{10U};
    std::uint64_t memory_limit_bytes{268435456U};
};

struct DecoderSafetyPolicy final
{
    std::uint64_t max_input_bytes{0U};
    std::uint64_t max_output_bytes{0U};
    std::uint64_t max_pixels{0U};
    std::uint32_t max_animation_frames{1U};
    std::uint32_t max_expansion_ratio{100U};
    bool unsafe_decoders_disabled{true};
};

struct DecoderSafetyRequest final
{
    std::uint64_t input_bytes{0U};
    std::uint64_t estimated_output_bytes{0U};
    std::uint64_t pixels{0U};
    std::uint32_t animation_frames{1U};
    bool decoder_marked_safe{true};
};

struct MediaDeduplicationKey final
{
    std::string hash_algorithm{};
    std::string digest{};
    std::uint64_t byte_size{0U};
};

enum class AdminQuarantineAction
{
    quarantine,
    release,
    remove,
};

struct AdminQuarantineRequest final
{
    AdminQuarantineAction action{AdminQuarantineAction::quarantine};
    std::string admin_user_id{};
    std::string media_id{};
    std::string reason{};
};

[[nodiscard]] auto media_disposition_name(MediaDisposition disposition) noexcept -> char const*;
[[nodiscard]] auto media_mime_type_is_allowed(MediaUploadPolicy const& policy, std::string_view mime_type) noexcept
    -> bool;
[[nodiscard]] auto evaluate_media_upload(MediaUploadPolicy const& policy, MediaUploadRequest const& request)
    -> MediaPolicyDecision;
[[nodiscard]] auto remote_media_fetch_policy(RemoteMediaFetchRequest const& request) -> MediaPolicyDecision;
[[nodiscard]] auto sandboxed_worker_plan_is_hardened(SandboxedMediaWorkerPlan const& plan) noexcept -> bool;
[[nodiscard]] auto evaluate_decoder_safety(DecoderSafetyPolicy const& policy, DecoderSafetyRequest const& request)
    -> MediaPolicyDecision;
[[nodiscard]] auto media_deduplication_key_is_valid(MediaDeduplicationKey const& key) noexcept -> bool;
[[nodiscard]] auto make_media_deduplication_key(std::string_view hash_algorithm, std::string_view digest,
                                                std::uint64_t byte_size) -> MediaDeduplicationKey;
[[nodiscard]] auto admin_quarantine_policy(AdminQuarantineRequest const& request) -> MediaPolicyDecision;
[[nodiscard]] auto media_security_boundary_notes() -> std::vector<std::string>;

} // namespace merovingian::media
