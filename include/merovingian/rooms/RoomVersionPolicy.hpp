// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/rooms/AuthRules.hpp"
#include "merovingian/rooms/EventFormat.hpp"
#include "merovingian/rooms/EventIdFormat.hpp"
#include "merovingian/rooms/RedactionRules.hpp"
#include "merovingian/rooms/StateResolutionAlgorithm.hpp"

#include <string_view>
#include <vector>

namespace merovingian::rooms
{

struct RoomVersionPolicy final
{
    std::string_view id{};
    EventFormat event_format{EventFormat::room_v3_plus};
    RedactionRules redaction_rules{RedactionRules::room_v11_plus};
    AuthRules auth_rules{AuthRules::room_v6_plus};
    StateResolutionAlgorithm state_resolution{StateResolutionAlgorithm::v2};
    EventIdFormat event_id_format{EventIdFormat::reference_hash};
    bool stable{false};
    // MSC4291 (room v12): the room ID is "!" + the reference hash of the
    // m.room.create event, the create event carries no room_id, and the create
    // event is implicit in every event's auth_events (never listed explicitly).
    bool create_event_is_room_id{false};
    // MSC4289 (room v12): the create event sender and every user listed in the
    // create event's content.additional_creators hold an effectively infinite
    // power level that outranks any integer power level.
    bool privilege_room_creators{false};
    // Room v10 onwards require every value in m.room.power_levels to be a real
    // integer. Versions 1-9 accept a string representation of an integer for
    // backwards compatibility, and events using it are valid and must be both
    // accepted and read correctly -- rejecting them, or reading them as absent,
    // breaks federation with older rooms.
    // Spec: ../../docs/matrix-v1.19-spec/rooms/v10.md
    //       "Values in m.room.power_levels events must be integers"
    bool power_levels_require_integers{false};
    // Room versions 1-5 also accept a float power level, read by applying
    // exponential notation and truncating at the decimal point; values outside
    // binary64, Infinity and NaN are rejected. v6 made Canonical JSON (which has
    // no floats) mandatory. EVT-12 (d), ADR-0150.
    // Spec: ../../docs/matrix-v1.19-spec/rooms/v3.md
    //       "m.room.power_levels events accept values as floats"
    bool power_levels_accept_floats{false};
    // Which join rules the version's authorization rules define. A join rule
    // a version does not define falls through to "Otherwise, reject".
    //   knock            — rooms/v7.md: joins ("invite or knock") and the
    //                      knock membership.
    //   restricted       — rooms/v8.md: restricted joins via
    //                      join_authorised_via_users_server.
    //   knock_restricted — rooms/v10.md: joins ("restricted or
    //                      knock_restricted") and knocks ("knock or
    //                      knock_restricted").
    bool knock_join_rule{false};
    bool restricted_join_rule{false};
    bool knock_restricted_join_rule{false};
    // Redaction details finer than the RedactionRules buckets. The redacted
    // form feeds the reference hash, so each must match the version exactly.
    //   redaction_keeps_aliases — m.room.aliases keeps "aliases" (v1-v5;
    //                             rooms/v6.md removed it).
    //   redaction_keeps_join_authorisation — m.room.member keeps
    //                             "join_authorised_via_users_server" (v9+;
    //                             v8 keeps only "membership").
    bool redaction_keeps_aliases{false};
    bool redaction_keeps_join_authorisation{false};
    // Room versions 1-4 ignore a signing key's valid_until_ts when checking an
    // event's signatures. From v5 the key MUST still be valid at the event's
    // origin_server_ts (rooms/v5.md, "Signing key validity period"). Off by
    // default, so a version that forgets to set it enforces the check.
    bool ignores_key_validity{false};
    // Room v3 event IDs are the reference hash in standard Unpadded Base64
    // (rooms/v3.md); v4 onwards use URL-safe base64 (rooms/v4.md).
    bool event_id_url_safe_base64{true};
};

[[nodiscard]] auto known_room_versions() -> std::vector<RoomVersionPolicy>;
[[nodiscard]] auto find_room_version_policy(std::string_view id) noexcept -> RoomVersionPolicy const*;
[[nodiscard]] auto room_version_is_supported(std::string_view id) noexcept -> bool;

} // namespace merovingian::rooms
