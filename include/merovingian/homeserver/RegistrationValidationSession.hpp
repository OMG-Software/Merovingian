// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <optional>
#include <string>

namespace merovingian::homeserver
{

struct RegistrationValidationSession final
{
    std::string sid{};
    std::string purpose{"register"};
    std::string medium{};
    std::string address{};
    std::string client_secret{};
    std::string client_ip{};
    std::optional<std::string> user_id{};
    std::optional<std::string> country{};
    std::optional<std::string> next_link{};
    std::uint64_t send_attempt{0U};
    std::uint64_t created_at_ms{0U};
    std::uint64_t updated_at_ms{0U};
    // Zero until a trusted identity server has reported this session validated
    // (AUTH-5): this server cannot send email or SMS, so it has no way to
    // validate a 3PID itself and a session is never born validated.
    std::uint64_t validated_at_ms{0U};
    // The trusted identity server that issued `sid`, and the caller's access
    // token for it, kept so the server can ask that identity server whether the
    // session was validated (getValidated3pid). In memory only, for the life of
    // the session (it is pruned with the session after the validation TTL, and
    // erased as soon as the 3PID is added or bound); never persisted or logged.
    std::string identity_server_base_url{};
    std::string identity_access_token{};
    // Password reset by email only (ADR-0481): the code this server emailed, empty when none was sent (the address
    // belongs to no account) or once the session is validated, and the wrong codes tried so far. In memory only,
    // wiped with the session, never logged.
    std::string reset_token{};
    std::uint8_t token_attempts{0U};
    // When this session's code was last emailed (wall-clock ms), zero if never: the per-address throttle reads it
    // from every session of the address, so it survives the session that used up its tries.
    std::uint64_t reset_sent_at_ms{0U};
};

} // namespace merovingian::homeserver
