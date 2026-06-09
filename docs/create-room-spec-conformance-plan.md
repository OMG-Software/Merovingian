# `POST /createRoom` — Matrix v1.18 Spec Conformance Plan

Audited against: https://spec.matrix.org/v1.18/client-server-api/#post_matrixclientv3createroom  
Audit date: 2026-05-27  
Branch: fix-key-server-lock-contention (merged to main after PR #148)

---

## Implementation status

Completed on `fix-key-server-lock-contention` on 2026-05-27. The room-service
builder now owns the full Matrix v1.18 `createRoom` event chain, room aliases
are persisted and exposed through the client directory routes, and outbound
federation invites use the created room's real version. The remaining gap is
local execution evidence on this Windows checkout: the new conformance tests are
present, but the native Meson toolchain is unavailable here (`clang-18`,
`clang++-18`, and `pkg-config` are missing). The WSL build (`build-wsl.cmd`,
forcefallback subprojects) runs the suite locally.

**Update (0.4.39): room version 12 (MSC4291 + MSC4289).** `create_room` now
derives v12 room IDs from the `m.room.create` event's reference hash (`!` + hash,
no `:server`), omits `room_id` from the create event, and excludes the create
event from `auth_events`; room creators (`sender` + `additional_creators`) hold
infinite power. This fixed the Synapse `send_join` `BadSignatureError` on the
create event. See `docs/event-engine.md` for the authoritative description and
`tests/unit/test_client_server.cpp` / `test_events.cpp` / `test_event_auth_rules.cpp`
for the v10/v11/v12 conformance coverage.

---

## Background

After adding initial room state event generation (PR #148), the implementation was
audited against the Matrix v1.18 spec. Eleven deviations were found: three produce
wrong values on the wire (bugs), eight silently ignore client parameters (missing
features). This document is the implementation plan to close all eleven.

---

## Spec-mandated event emission order

The server MUST create events in this order during `createRoom`:

1. `m.room.create` — content: `creator`, `room_version`, plus any `creation_content` extras
2. `m.room.member` — creator joins (`membership: join`)
3. `m.room.power_levels` — default content, then `power_level_content_override` merged on top
4. `m.room.canonical_alias` — only if `room_alias_name` is provided
5. Preset events — `m.room.join_rules`, `m.room.history_visibility`, `m.room.guest_access`
6. `initial_state` events — applied in the order listed by the client
7. `m.room.name` — only if `name` is provided
8. `m.room.topic` — only if `topic` is provided
9. Invite events — `m.room.member` (`membership: invite`) for each entry in `invite` and `invite_3pid`

---

## Spec-mandated preset table

| Preset | `join_rules` | `history_visibility` | `guest_access` | Other |
|---|---|---|---|---|
| `private_chat` | `invite` | `shared` | `can_join` | |
| `trusted_private_chat` | `invite` | `shared` | `can_join` | All invitees get power level 100 (same as creator). In room v12+, `m.room.tombstone` power level MUST be > `state_default` (e.g. 150). Per v1.16: invited users appended to `additional_creators` in `m.room.create`. |
| `public_chat` | `public` | `shared` | `forbidden` | |

When `preset` is absent, derive it from `visibility`: `public` → `public_chat`, `private` → `private_chat`.

---

## Issues

### Issue 1 — `public_chat` emits `world_readable` instead of `shared` 🔴

**Severity:** Bug — wrong value on the wire.

**Location:** `src/homeserver/client_server.cpp`

```cpp
// Current (wrong):
auto const history_vis = (preset_val != nullptr && *preset_val == "public_chat") ? "world_readable" : "shared";
```

`world_readable` allows non-members to read room history without joining. The spec
says `public_chat` uses `shared`, which means history is visible only after joining.
This also pollutes the `/publicRooms` directory: `world_readable` is the flag clients
use to surface truly open rooms.

**Fix:** Change the ternary to `"shared"` for `public_chat`.

```cpp
auto const history_vis = "shared"; // All presets use "shared" per spec.
```

**Test:** Add SCENARIO asserting that a `public_chat` room's `m.room.history_visibility`
state event contains `shared`, not `world_readable`.

---

### Issue 2 — `m.room.guest_access` never emitted 🔴

**Severity:** Bug — required event absent from room state.

**Location:** `src/homeserver/client_server.cpp`

The spec requires all three presets to emit `m.room.guest_access`. Its absence means:
- `/publicRooms` always reports `guest_can_join: false` for locally-created rooms,
  regardless of preset.
- Federation peers see a room with no guest access policy, which may affect their
  join decisions.

**Fix:** Derive `guest_access` from the preset and always emit the event.

```cpp
auto const guest_access = (preset_val != nullptr && *preset_val == "public_chat")
                              ? "forbidden"
                              : "can_join"; // private_chat and trusted_private_chat

// After the join_rules / history_visibility send_state calls:
send_state("m.room.guest_access",
           json_serialize(json_obj({json_member("guest_access", json_str(guest_access))})));
```

**Test:** Assert `m.room.guest_access` is present in room state after creation for each
preset. Assert `guest_access` value matches the preset table above.

---

### Issue 3 — Outbound federation invite hardcodes room version `"12"` 🔴

**Severity:** Bug — wrong value on the wire.

**Location:** `src/homeserver/client_server.cpp` (invite dispatch block)

```cpp
// Current (wrong):
federation::make_outbound_invite(invitee_server, ..., "12", *invite_json, {});
```

Rooms are created as version `"10"` (hardcoded in `create_room`). Sending
`room_version: "12"` in the invite tells the remote server to apply v12 auth rules
to a v10 room, which is incorrect.

**Fix:** Read the room version from the stored `m.room.create` event using
`room_version_for_room` (already exists in `room_service.cpp`) and pass it through
to the invite dispatch. Since `room_version_for_room` lives in an anonymous namespace
in `room_service.cpp`, either:
- Expose a small public helper `room_version_for_room` from `room_service.hpp`, or
- Pass the room version string as a parameter down from `createRoom` into the invite
  dispatch block (simpler, no ABI change).

**Test:** Assert the invite transaction body sent over federation contains the correct
`room_version` for the created room.

---

### Issue 4 — `room_version` request parameter ignored 🟡

**Severity:** Missing feature — client-requested room versions silently ignored.

**Location:** `src/homeserver/room_service.cpp` (`create_room`) and
`src/homeserver/client_server.cpp` (createRoom handler)

`create_room` hardcodes `"room_version":"10"` in the `m.room.create` content and
never consults the client's `room_version` field.

**Fix:**
1. Add a `room_version` parameter to `create_room` (or pass it as part of a
   `CreateRoomOptions` struct — see Issue 5 for why a struct is cleaner).
2. In the client_server handler, read `room_version` from the request body (default
   to the server's configured default, which for now is `"10"`).
3. Validate the requested version against `rooms::find_room_version_policy`; return
   `400 M_UNSUPPORTED_ROOM_VERSION` if not supported.
4. Pass it into `create_room` so it is embedded in `m.room.create`.

**Test:** Assert that requesting `room_version: "11"` creates a room whose
`m.room.create` content contains `room_version: "11"`.

---

### Issue 5 — `creation_content` extras not applied to `m.room.create` 🟡

**Severity:** Missing feature — `m.federate: false` (and any other client-supplied
extras) are silently dropped.

**Location:** `src/homeserver/room_service.cpp` (`create_room`) and
`src/homeserver/client_server.cpp`

The spec says the server builds `m.room.create` content from `creation_content`, then
overwrites `creator` and `room_version`. Any additional keys the client provides
(most commonly `m.federate: false` for private rooms) must be present in the event.

**Fix:** Accept `creation_content` as a parameter in `create_room` (or in a
`CreateRoomOptions` struct). Merge client-supplied keys into the content object, then
overwrite `creator` and `room_version` with server-authoritative values.

Note: `m.federate: false` implies the room should not be shared with other servers.
If `m.federate` is false, the server SHOULD refuse federation join requests for that
room. This is a follow-on behavioral change, not strictly required by this fix.

**Test:** Assert `m.room.create` content contains `m.federate: false` when the client
sends it in `creation_content`.

---

### Issue 6 — `power_level_content_override` not applied 🟡

**Severity:** Missing feature — client-supplied power level overrides are silently
dropped.

**Location:** `src/homeserver/room_service.cpp` (`create_room`) and
`src/homeserver/client_server.cpp`

The spec says the server generates the default `m.room.power_levels` content and then
merges `power_level_content_override` on top of it before sending the event.

**Fix:** Accept `power_level_content_override` as a parameter. After constructing the
default power levels JSON object, iterate the override object's members and overwrite
or insert each key into the default content before emitting the event.

**Test:** Assert that `power_level_content_override: { "events_default": 50 }` results
in the `m.room.power_levels` event containing `events_default: 50`.

---

### Issue 7 — `initial_state` events not processed 🟡

**Severity:** Missing feature — client-supplied state overrides are silently dropped.

**Location:** `src/homeserver/client_server.cpp`

After preset events (step 5 in the emission order), the server MUST apply each event
from the `initial_state` array in the order given. Each item has `type`, optional
`state_key` (defaults to `""`), and `content`.

**Fix:** After the preset `send_state` calls and before `m.room.name`/`m.room.topic`,
iterate `initial_state`:

```cpp
if (auto const* initial_state_arr = ...; initial_state_arr != nullptr) {
    for (auto const& item : *initial_state_arr) {
        // extract type, state_key (default ""), content
        // call send_state(type, serialize(content), state_key)
    }
}
```

**Test:** Assert that `initial_state: [{ type: "m.room.encryption", state_key: "",
content: { algorithm: "m.megolm.v1.aes-sha2" } }]` results in `m.room.encryption`
being present in the room's state.

---

### Issue 8 — `trusted_private_chat` preset not fully implemented 🟡

**Severity:** Missing feature — invitees do not receive power level 100; room v12
tombstone requirement not met.

**Location:** `src/homeserver/client_server.cpp`

For `trusted_private_chat`:
- All users in `invite` must receive power level 100 in `m.room.power_levels`.
- In room version ≥ 12, the `m.room.tombstone` event power level must be set higher
  than `state_default` (e.g. 150).
- Per Matrix v1.16, invited users should also be added to `additional_creators` in
  the `m.room.create` content.

**Fix:**
1. After reading the `invite` list and detecting `trusted_private_chat`, build a
   `users` map in the power levels content that includes each invitee at power 100.
2. For room v12+, add `"m.room.tombstone": 150` (or `state_default + 1`) to the
   `events` map in power levels.
3. Pass invitees into `create_room`'s `creation_content` as `additional_creators`
   when the preset is `trusted_private_chat`.

**Test:** Assert that for `trusted_private_chat`, the `m.room.power_levels` `users`
map contains each invitee at level 100. Assert `additional_creators` in
`m.room.create` contains the invitees.

---

### Issue 9 — `visibility` not used to derive preset when `preset` is absent 🟡

**Severity:** Missing feature — `visibility: "public"` without explicit preset
produces an invite-rule room.

**Location:** `src/homeserver/client_server.cpp`

Spec: if `preset` is absent, use `visibility` to select it: `"public"` → `public_chat`,
`"private"` → `private_chat`.

**Fix:**

```cpp
auto const* visibility_val = body_obj != nullptr ? string_member(*body_obj, "visibility") : nullptr;
auto const effective_preset = [&]() -> std::string_view {
    if (preset_val != nullptr) return *preset_val;
    if (visibility_val != nullptr && *visibility_val == "public") return "public_chat";
    return "private_chat"; // default
}();
```

**Test:** Assert that `visibility: "public"` without `preset` produces a room with
`join_rules: public` and `guest_access: forbidden`.

---

### Issue 10 — `room_alias_name` and `m.room.canonical_alias` not handled 🟡

**Severity:** Missing feature.

**Location:** `src/homeserver/client_server.cpp` and a new alias registry.

**Fix:**
1. On `createRoom` with `room_alias_name` provided, verify the alias is not already
   taken; return `400 M_ROOM_IN_USE` if it is.
2. Register the alias in the persistent store (a new `aliases` table mapping
   `#alias:server` → `!roomId:server`).
3. Emit `m.room.canonical_alias` state event with `alias: "#<room_alias_name>:<server>"`.
4. Wire `GET /_matrix/client/v3/directory/room/{roomAlias}` and
   `PUT /_matrix/client/v3/directory/room/{roomAlias}` to the alias registry.

**Test:** Assert that `room_alias_name: "test"` produces a room with a
`m.room.canonical_alias` state event and that the alias resolves via the directory
endpoint.

---

### Issue 11 — `is_direct` not propagated to invite member events 🟡

**Severity:** Missing feature — DM rooms not correctly classified by clients.

**Location:** `src/homeserver/client_server.cpp` (invite dispatch in createRoom)

When `is_direct: true` is sent in the request, the `m.room.member` invite events
emitted for each user in `invite` must include `"is_direct": true` in their content.
This is how clients (Element, Cinny, etc.) recognise DM rooms.

**Fix:**

```cpp
auto const* is_direct_val = body_obj != nullptr ? bool_member(*body_obj, "is_direct") : nullptr;
auto const is_direct = is_direct_val != nullptr && *is_direct_val;

// In the invite loop:
auto member_content = json_obj({json_member("membership", json_str("invite"))});
if (is_direct) {
    member_content.push_back(json_member("is_direct", json_bool(true)));
}
send_state("m.room.member", json_serialize(member_content), invitee);
```

**Test:** Assert that `is_direct: true` produces invite member events whose content
contains `is_direct: true`.

---

## Refactor recommendation

Issues 4–8 all require passing additional parameters from the client-server handler
into `create_room`. Rather than adding individual function parameters for each,
introduce a `CreateRoomOptions` struct:

```cpp
struct CreateRoomOptions {
    std::string room_version{"10"};                    // Issue 4
    canonicaljson::Object creation_content{};          // Issue 5
    canonicaljson::Object power_level_content_override{}; // Issue 6
    std::vector<canonicaljson::Value> initial_state{}; // Issue 7
    std::vector<std::string> trusted_invitees{};       // Issue 8 (for power levels)
    std::string preset{};                              // Issue 8
};
```

`create_room` can then consume this struct and build the correct event chain in one
place, keeping the client_server handler focused on HTTP parsing.

---

## Implementation order

Fix in this sequence to keep intermediate states in a valid, testable condition:

| Step | Issues | Rationale |
|---|---|---|
| 1 | #1 (history_visibility), #2 (guest_access) | Bugs first; both are two-line fixes in `client_server.cpp` |
| 2 | #9 (visibility → preset) | Prerequisite for correct preset behavior |
| 3 | Introduce `CreateRoomOptions` struct | Refactor prerequisite for Issues 4–8 |
| 4 | #4 (room_version), #5 (creation_content) | Bundle: both touch `create_room`'s `m.room.create` build |
| 5 | #6 (power_level_content_override) | Touches `m.room.power_levels` build in `create_room` |
| 6 | #8 (trusted_private_chat) | Builds on power levels; needs `CreateRoomOptions.trusted_invitees` |
| 7 | #7 (initial_state) | Client_server handler loop, depends on `CreateRoomOptions` |
| 8 | #3 (invite room version) | Small fix, depends on `room_version` flowing through (#4) |
| 9 | #11 (is_direct) | Small fix in invite loop |
| 10 | #10 (room_alias_name) | Largest scope; needs new persistent alias table and directory routes |

---

## Versioning

Each step above is a separate commit on a dedicated branch. Bump the version once at
branch creation (see `docs/versioning.md`). Do not bump per intermediate commit.

Record completed steps in `CHANGELOG.md` under the new version and update
`docs/todos/` after each step.
