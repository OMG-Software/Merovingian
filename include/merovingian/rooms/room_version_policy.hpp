// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string_view>
#include <vector>

namespace merovingian::rooms
{

enum class EventFormat : unsigned char
{
    room_v3_plus,
};

enum class RedactionRules : unsigned char
{
    room_v1_v7,    // v1–v7: join_rules preserves only join_rule
    room_v8_v10,   // v8–v10: join_rules also preserves allow (restricted joins, MSC3083)
    room_v11_plus, // v11+: revised rules (aliases stripped, third_party_invite in member, etc.)
};

enum class AuthRules : unsigned char
{
    room_v1,
    room_v6_plus, // room versions 6–11
    room_v12,     // room version 12 (MSC4289/MSC4291): creator privilege + implicit create
};

enum class StateResolutionAlgorithm : unsigned char
{
    v2,
    // Room v12 (MSC4289/MSC4291): state resolution v2.1 — the iterative auth
    // checks algorithm starts from an empty state map instead of the
    // unconflicted state map, and the full conflicted set additionally
    // includes the conflicted state subgraph.
    // Spec: ../../docs/matrix-v1.19-spec/rooms/v12.md — "State resolution"
    // ("This state resolution algorithm is largely the same as the algorithm
    // found in room version 2 with the following modifications").
    v2_1,
};

enum class EventIdFormat : unsigned char
{
    reference_hash,
};

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
};

[[nodiscard]] auto known_room_versions() -> std::vector<RoomVersionPolicy>;
[[nodiscard]] auto find_room_version_policy(std::string_view id) noexcept -> RoomVersionPolicy const*;
[[nodiscard]] auto room_version_is_supported(std::string_view id) noexcept -> bool;

} // namespace merovingian::rooms
