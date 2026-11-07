// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/media/AdminQuarantineRequest.hpp"
#include "merovingian/media/DecoderSafetyPolicy.hpp"
#include "merovingian/media/DecoderSafetyRequest.hpp"
#include "merovingian/media/MediaAcceptancePolicy.hpp"
#include "merovingian/media/MediaDeduplicationKey.hpp"
#include "merovingian/media/MediaDisposition.hpp"
#include "merovingian/media/MediaPolicyDecision.hpp"
#include "merovingian/media/MediaUploadPolicy.hpp"
#include "merovingian/media/MediaUploadRequest.hpp"
#include "merovingian/media/RemoteMediaFetchRequest.hpp"
#include "merovingian/media/SandboxedMediaWorkerPlan.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace merovingian::media
{

// Content types the spec permits to be served with `Content-Disposition:
// inline` (CS API section "Serving inline content"). Anything outside this list
// must be served as an attachment so a browser cannot render it as active
// content in the media origin's context.
//
// Shared between the client-facing download path and the federation multipart
// body (0.12.5 audit, finding 8): the federation builder used to hardcode
// `inline` for every type, so a peer's clients were told to render an
// executable or a scripted HTML document inline -- bypassing the very
// allow-list the local path applies.
//
// The comparison is on the media type only: a charset or other parameter must
// not defeat the match, and must not let an unlisted type slip through by
// prefixing a listed one.
//
// Spec: ../../docs/matrix-v1.19-spec/client-server-api.md#serving-inline-content
[[nodiscard]] auto content_type_is_inline_safe(std::string_view content_type) noexcept -> bool;

// Whether `declared` is the same media type as `sniffed`, spelled differently.
// Media types compare case-insensitively (RFC 2045 section 5.1, RFC 6838 section
// 4.2), and a declared top-level type of `img` is read as `image`, a common
// misspelling. Nothing else matches: a parameter, surrounding whitespace, another
// subtype or another top-level type is a different type. `sniffed` is the type
// `sniff_mime_type` found in the bytes, so a match says the declared string names
// what the bytes are. The upload policy treats a match as no mismatch, and the
// file is then served under the declared spelling (owner decision 2026-10-29).
[[nodiscard]] auto media_types_are_equivalent(std::string_view declared, std::string_view sniffed) noexcept -> bool;

// The longest file name, in bytes, that a Content-Disposition header names.
inline constexpr std::size_t max_media_filename_bytes = 255U;

// True when `filename` may be named in a Content-Disposition header: not empty,
// at most max_media_filename_bytes of well-formed UTF-8, and free of control
// characters and path separators.
[[nodiscard]] auto media_filename_is_valid(std::string_view filename) noexcept -> bool;

// The Content-Disposition value for media of `content_type`: `inline` when the
// type is inline-safe, otherwise `attachment`, followed by the file name when
// `filename` is valid (RFC 6266: a quoted string for printable ASCII, otherwise
// `filename*=utf-8''` percent-encoding). An invalid or empty `filename` is left
// out, so no caller-chosen byte can end or extend the header line.
//
// Spec: ../../docs/matrix-v1.19-spec/client-server-api.md#get_matrixclientv1mediadownloadservernamemediaidfilename
[[nodiscard]] auto media_content_disposition(std::string_view content_type, std::string_view filename) -> std::string;

// The file name a remote server's Content-Disposition value names
// (`filename=` as a token or quoted string, or RFC 5987 `filename*=utf-8''...`,
// which wins), or empty when there is none or it fails media_filename_is_valid.
// Reads at most 1024 bytes of the value, in one linear pass.
[[nodiscard]] auto content_disposition_filename(std::string_view header_value) -> std::string;

[[nodiscard]] auto media_acceptance_policy_name(MediaAcceptancePolicy policy) noexcept -> std::string_view;
// Falls back to the safest option (quarantine) for unrecognised input. Config
// parsing validates the string against exactly these four spellings before
// this ever runs, so the fallback is a defence-in-depth net, not a live path.
[[nodiscard]] auto parse_media_acceptance_policy(std::string_view value) noexcept -> MediaAcceptancePolicy;

// Inspects the leading bytes of an upload and returns the MIME type its
// content actually matches, independent of any client-declared Content-Type.
// Recognizes the magic-byte signatures of the media module's default
// allow-list (image/png, image/jpeg, image/gif, application/pdf) plus a
// text/plain heuristic (printable ASCII/UTF-8 with no control bytes besides
// tab/newline/CR). Falls back to application/octet-stream when nothing
// matches — never returns empty, so callers cannot mistake "no bytes" for
// "sniffing was skipped".
[[nodiscard]] auto sniff_mime_type(std::string_view bytes) -> std::string;

// Merovingian does not integrate a real antivirus engine (see
// docs/user-manual.md and the WARNING in config/merovingian.conf.example —
// E2EE makes any scanner meaningless for encrypted-room attachments
// regardless of this check). This is a deterministic, dependency-free check
// for the industry-standard EICAR antivirus test signature
// (https://www.eicar.org/download-anti-malware-testfile/), so that
// `security.media.enable_av_scanner` has a genuine, testable effect on
// plaintext uploads rather than being a permanent no-op, and so the
// quarantine path can be exercised end-to-end without needing real malware.
[[nodiscard]] auto content_matches_eicar_test_signature(std::string_view bytes) noexcept -> bool;

// True for a Matrix Content URI as the spec defines it ("Matrix Content (mxc://) URIs"):
// `mxc://<server-name>/<media-id>`, a valid server name and a media ID of one or more of
// `A-Za-z0-9`, `_` and `-` (so no further `/`, query or fragment). Used wherever a client
// supplies an MXC URI that the server stores, such as a profile's `avatar_url`.
[[nodiscard]] auto mxc_uri_is_valid(std::string_view uri) noexcept -> bool;

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
