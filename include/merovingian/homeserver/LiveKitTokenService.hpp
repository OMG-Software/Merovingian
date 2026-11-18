// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/homeserver/LiveKitTokenRequest.hpp"
#include "merovingian/homeserver/OperationResult.hpp"
#include "merovingian/homeserver/RuntimeMutex.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <variant>

namespace merovingian::homeserver
{

struct ClientServerRuntime;
struct HomeserverRuntime;
struct LocalHttpRequest;

// The built-in MatrixRTC token service (MSC4195; ADR-0829).

// Bounds on the identifiers a request names. A slot or member ID is the `slot_id` or `member.id` of an
// `m.rtc.member` state event, whose state key is itself at most 255 bytes.
inline constexpr auto max_livekit_slot_id_bytes = std::size_t{255U};
inline constexpr auto max_livekit_member_id_bytes = std::size_t{255U};
inline constexpr auto max_livekit_room_id_bytes = std::size_t{255U};
inline constexpr auto max_livekit_url_bytes = std::size_t{2048U};
// A user ID is at most 255 bytes (the identifier grammar).
inline constexpr auto max_livekit_user_id_bytes = std::size_t{255U};

// The federation route this server asks another server's token service on (ADR-0831), and the largest answer read:
// a `jwt` is at most `crypto::hs256_token_max_bytes`.
inline constexpr auto federation_livekit_token_path = std::string_view{"/_matrix/federation/v1/rtc/livekit/get_token"};
inline constexpr auto livekit_relay_response_max_bytes = std::uint64_t{8U * 1024U};

// What a client body reads as, or the 400 to answer. Not std::expected, which this project's toolchain does not
// build.
using LiveKitTokenRequestResult = std::variant<LiveKitTokenRequest, OperationResult>;

// The client body `{url, room_id, slot_id, member_id[, server_name]}`. A failure is the 400 to answer:
// `M_BAD_JSON` for a body that is not a JSON object, `M_MISSING_PARAM` for a missing member, `M_INVALID_PARAM` for one
// of the wrong type or out of bounds.
[[nodiscard]] auto parse_client_livekit_token_request(std::string_view body) -> LiveKitTokenRequestResult;

// `POST /_matrix/client/{v1,unstable/io.element.msc4195}/rtc/livekit/get_token` for `user_id`, whom the dispatcher
// authenticated. A `server_name` naming another server is relayed to it over federation (ADR-0831). `guard` holds
// `runtime.mutex`; it is released only around the call to LiveKit or to the other server. The answer's `value` is the
// response body on success; on failure `status`, `errcode` and `reason` say what to answer.
[[nodiscard]] auto issue_client_livekit_token(ClientServerRuntime& rt, LocalHttpRequest const& req,
                                              std::string const& user_id, RuntimeLock& guard) -> OperationResult;

// `POST /_matrix/federation/{v1,unstable/io.element.msc4195}/rtc/livekit/get_token` from `origin`, the server main
// verified the X-Matrix signature of, with the request's `body` (ADR-0831). The caller holds `runtime.mutex`; nothing
// here blocks. A token for a user of another server can subscribe only.
[[nodiscard]] auto issue_federation_livekit_token(HomeserverRuntime& runtime, std::string_view origin,
                                                  std::string_view body) -> OperationResult;

} // namespace merovingian::homeserver
