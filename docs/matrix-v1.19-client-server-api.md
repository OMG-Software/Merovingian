# Matrix v1.19 Client-Server API Reference

> Generated file. Do not edit endpoint rows by hand; regenerate with `node scripts/generate-matrix-v119-spec-doc.mjs`.
>
> This lists every operation in the v1.19 OpenAPI document. It is a spec reference, not an implementation-status tracker: operations the server does not route are listed in `docs/todos/capability-gaps.md`.

## Source

- Official OpenAPI document: https://spec.matrix.org/v1.19/client-server-api/
- Human-readable reference: https://spec.matrix.org/v1.19/client-server-api/
- OpenAPI: 3.1.0
- Title: Matrix Client-Server API
- Version: v1.19
- Generated: 2026-07-23
- Source SHA-256: `c7fe4072c6810491e436ac8e6dc212c7d653b6ce53b59e4ac752b4664b6f0e68`

## Summary

- Paths: 136
- Operations: 166
- Tags: 30

| Tag | Operations |
| --- | ---: |
| Account management | 17 |
| Application service room directory management | 1 |
| Capabilities | 1 |
| Device management | 5 |
| End-to-end encryption | 20 |
| Event relationships | 3 |
| Media | 13 |
| Mutual Rooms | 1 |
| OpenID | 1 |
| Presence | 2 |
| Push notifications | 12 |
| Read Markers | 1 |
| Reporting content | 3 |
| Room creation | 1 |
| Room directory | 4 |
| Room discovery | 4 |
| Room membership | 11 |
| Room participation | 21 |
| Room upgrades | 1 |
| Search | 1 |
| Send-to-Device messaging | 1 |
| Server administration | 9 |
| Session management | 9 |
| Spaces | 1 |
| Third-party Lookup | 6 |
| Threads | 1 |
| untagged | 3 |
| User data | 11 |
| User directory | 1 |
| VOIP | 1 |

## Account management

| Method | Path | Operation ID | Auth | Request body | Responses |
| --- | --- | --- | --- | --- | --- |
| `GET` | `/_matrix/client/v1/register/m.login.registration_token/validity` | `registrationTokenValidity` | none | - | 200, 403, 429 |
| `GET` | `/_matrix/client/v3/account/3pid` | `getAccount3PIDs` | access token | - | 200 |
| `POST` | `/_matrix/client/v3/account/3pid` | `post3PIDs` | access token | required application/json | 200, 403 |
| `POST` | `/_matrix/client/v3/account/3pid/add` | `add3PID` | access token | required application/json | 200, 400, 401, 429 |
| `POST` | `/_matrix/client/v3/account/3pid/bind` | `bind3PID` | access token | required application/json | 200, 400, 429 |
| `POST` | `/_matrix/client/v3/account/3pid/delete` | `delete3pidFromAccount` | access token | required application/json | 200 |
| `POST` | `/_matrix/client/v3/account/3pid/email/requestToken` | `requestTokenTo3PIDEmail` | none | required application/json | 200, 400, 403 |
| `POST` | `/_matrix/client/v3/account/3pid/msisdn/requestToken` | `requestTokenTo3PIDMSISDN` | none | required application/json | 200, 400, 403 |
| `POST` | `/_matrix/client/v3/account/3pid/unbind` | `unbind3pidFromAccount` | access token | required application/json | 200 |
| `POST` | `/_matrix/client/v3/account/deactivate` | `deactivateAccount` | optional | required application/json | 200, 401, 429 |
| `POST` | `/_matrix/client/v3/account/password` | `changePassword` | optional | required application/json | 200, 401, 429 |
| `POST` | `/_matrix/client/v3/account/password/email/requestToken` | `requestTokenToResetPasswordEmail` | none | required application/json | 200, 400, 403 |
| `POST` | `/_matrix/client/v3/account/password/msisdn/requestToken` | `requestTokenToResetPasswordMSISDN` | none | required application/json | 200, 400, 403 |
| `POST` | `/_matrix/client/v3/register` | `register` | none | required application/json | 200, 400, 401, 403, 429 |
| `GET` | `/_matrix/client/v3/register/available` | `checkUsernameAvailability` | none | - | 200, 400, 429 |
| `POST` | `/_matrix/client/v3/register/email/requestToken` | `requestTokenToRegisterEmail` | none | required application/json | 200, 400, 403 |
| `POST` | `/_matrix/client/v3/register/msisdn/requestToken` | `requestTokenToRegisterMSISDN` | none | required application/json | 200, 400, 403 |

## Application service room directory management

| Method | Path | Operation ID | Auth | Request body | Responses |
| --- | --- | --- | --- | --- | --- |
| `PUT` | `/_matrix/client/v3/directory/list/appservice/{networkId}/{roomId}` | `updateAppserviceRoomDirectoryVisibility` | appservice token | required application/json | 200 |

## Capabilities

| Method | Path | Operation ID | Auth | Request body | Responses |
| --- | --- | --- | --- | --- | --- |
| `GET` | `/_matrix/client/v3/capabilities` | `getCapabilities` | access token | - | 200, 429 |

## Device management

| Method | Path | Operation ID | Auth | Request body | Responses |
| --- | --- | --- | --- | --- | --- |
| `POST` | `/_matrix/client/v3/delete_devices` | `deleteDevices` | access token | required application/json | 200, 401 |
| `GET` | `/_matrix/client/v3/devices` | `getDevices` | access token | - | 200 |
| `GET` | `/_matrix/client/v3/devices/{deviceId}` | `getDevice` | access token | - | 200, 404 |
| `PUT` | `/_matrix/client/v3/devices/{deviceId}` | `updateDevice` | access token | required application/json | 200, 201, 404 |
| `DELETE` | `/_matrix/client/v3/devices/{deviceId}` | `deleteDevice` | access token | required application/json | 200, 401 |

Single-device GET, PUT and password-UIA DELETE extract `deviceId` from the
request path before the query separator. Unrelated query text does not rename
the selected device or alter its deletion/session revocation. Authentication
and the password-UIA requirement remain unchanged.

## End-to-end encryption

| Method | Path | Operation ID | Auth | Request body | Responses |
| --- | --- | --- | --- | --- | --- |
| `GET` | `/_matrix/client/v3/keys/changes` | `getKeysChanges` | access token | - | 200 |
| `POST` | `/_matrix/client/v3/keys/claim` | `claimKeys` | access token | required application/json | 200 |
| `POST` | `/_matrix/client/v3/keys/device_signing/upload` | `uploadCrossSigningKeys` | access token | required application/json | 200, 400, 403 |
| `POST` | `/_matrix/client/v3/keys/query` | `queryKeys` | access token | required application/json | 200 |
| `POST` | `/_matrix/client/v3/keys/signatures/upload` | `uploadCrossSigningSignatures` | access token | required application/json | 200 |
| `POST` | `/_matrix/client/v3/keys/upload` | `uploadKeys` | access token | required application/json | 200 |
| `GET` | `/_matrix/client/v3/room_keys/keys` | `getRoomKeys` | access token | - | 200, 404, 429 |
| `PUT` | `/_matrix/client/v3/room_keys/keys` | `putRoomKeys` | access token | required application/json | 200, 403, 404, 429 |
| `DELETE` | `/_matrix/client/v3/room_keys/keys` | `deleteRoomKeys` | access token | - | 200, 404, 429 |
| `GET` | `/_matrix/client/v3/room_keys/keys/{roomId}` | `getRoomKeysByRoomId` | access token | - | 200, 404, 429 |
| `PUT` | `/_matrix/client/v3/room_keys/keys/{roomId}` | `putRoomKeysByRoomId` | access token | required application/json | 200, 403, 404, 429 |
| `DELETE` | `/_matrix/client/v3/room_keys/keys/{roomId}` | `deleteRoomKeysByRoomId` | access token | - | 200, 404, 429 |
| `GET` | `/_matrix/client/v3/room_keys/keys/{roomId}/{sessionId}` | `getRoomKeyBySessionId` | access token | - | 200, 404, 429 |
| `PUT` | `/_matrix/client/v3/room_keys/keys/{roomId}/{sessionId}` | `putRoomKeyBySessionId` | access token | required application/json | 200, 403, 429 |
| `DELETE` | `/_matrix/client/v3/room_keys/keys/{roomId}/{sessionId}` | `deleteRoomKeyBySessionId` | access token | - | 200, 404, 429 |
| `GET` | `/_matrix/client/v3/room_keys/version` | `getRoomKeysVersionCurrent` | access token | - | 200, 404, 429 |
| `POST` | `/_matrix/client/v3/room_keys/version` | `postRoomKeysVersion` | access token | required application/json | 200, 429 |
| `GET` | `/_matrix/client/v3/room_keys/version/{version}` | `getRoomKeysVersion` | access token | - | 200, 404, 429 |
| `PUT` | `/_matrix/client/v3/room_keys/version/{version}` | `putRoomKeysVersion` | access token | required application/json | 200, 400, 404, 429 |
| `DELETE` | `/_matrix/client/v3/room_keys/version/{version}` | `deleteRoomKeysVersion` | access token | - | 200, 404, 429 |

Backup-version DELETE also selects `version` from the path before `?`.
Unrelated query text cannot turn a successful deletion into a no-op on the
intended version. SQLite regressions check deletion after reopening the store,
preservation of another version and repeated deletion; encryption and backed-up
session cascade are outside that regression's scope.

## Event relationships

| Method | Path | Operation ID | Auth | Request body | Responses |
| --- | --- | --- | --- | --- | --- |
| `GET` | `/_matrix/client/v1/rooms/{roomId}/relations/{eventId}` | `getRelatingEvents` | access token | - | 200, 404 |
| `GET` | `/_matrix/client/v1/rooms/{roomId}/relations/{eventId}/{relType}` | `getRelatingEventsWithRelType` | access token | - | 200, 404 |
| `GET` | `/_matrix/client/v1/rooms/{roomId}/relations/{eventId}/{relType}/{eventType}` | `getRelatingEventsWithRelTypeAndEventType` | access token | - | 200, 404 |

## Media

| Method | Path | Operation ID | Auth | Request body | Responses |
| --- | --- | --- | --- | --- | --- |
| `GET` | `/_matrix/client/v1/media/config` | `getConfigAuthed` | access token | - | 200, 429 |
| `GET` | `/_matrix/client/v1/media/download/{serverName}/{mediaId}` | `getContentAuthed` | access token | - | 200, 307, 308, 429, 502, 504 |
| `GET` | `/_matrix/client/v1/media/download/{serverName}/{mediaId}/{fileName}` | `getContentOverrideNameAuthed` | access token | - | 200, 307, 308, 429, 502, 504 |
| `GET` | `/_matrix/client/v1/media/preview_url` | `getUrlPreviewAuthed` | access token | - | 200, 429 |
| `GET` | `/_matrix/client/v1/media/thumbnail/{serverName}/{mediaId}` | `getContentThumbnailAuthed` | access token | - | 200, 307, 308, 400, 413, 429, 502, 504 |
| `POST` | `/_matrix/media/v1/create` | `createContent` | access token | - | 200, 403, 429 |
| `GET` | `/_matrix/media/v3/config` | `getConfig` | access token | - | 200, 429 |
| `GET` | `/_matrix/media/v3/download/{serverName}/{mediaId}` | `getContent` | none | - | 200, 307, 308, 429, 502, 504 |
| `GET` | `/_matrix/media/v3/download/{serverName}/{mediaId}/{fileName}` | `getContentOverrideName` | none | - | 200, 307, 308, 429, 502, 504 |
| `GET` | `/_matrix/media/v3/preview_url` | `getUrlPreview` | access token | - | 200, 429 |
| `GET` | `/_matrix/media/v3/thumbnail/{serverName}/{mediaId}` | `getContentThumbnail` | none | - | 200, 307, 308, 400, 413, 429, 502, 504 |
| `POST` | `/_matrix/media/v3/upload` | `uploadContent` | access token | required application/octet-stream | 200, 403, 413, 429 |
| `PUT` | `/_matrix/media/v3/upload/{serverName}/{mediaId}` | `uploadContentToMXC` | access token | required application/octet-stream | 200, 403, 404, 409, 413, 429 |

## Mutual Rooms

| Method | Path | Operation ID | Auth | Request body | Responses |
| --- | --- | --- | --- | --- | --- |
| `GET` | `/_matrix/client/v1/mutual_rooms` | `getMutualRooms` | access token | - | 200, 400, 429 |

## OpenID

| Method | Path | Operation ID | Auth | Request body | Responses |
| --- | --- | --- | --- | --- | --- |
| `POST` | `/_matrix/client/v3/user/{userId}/openid/request_token` | `requestOpenIdToken` | access token | required application/json | 200, 429 |

## Presence

| Method | Path | Operation ID | Auth | Request body | Responses |
| --- | --- | --- | --- | --- | --- |
| `GET` | `/_matrix/client/v3/presence/{userId}/status` | `getPresence` | access token | - | 200, 403, 404 |
| `PUT` | `/_matrix/client/v3/presence/{userId}/status` | `setPresence` | access token | required application/json | 200, 429 |

`GET` answers the caller's own presence, or another user's when they share a joined room (otherwise 403 `M_FORBIDDEN`, also for a user who does not exist); a local user with no presence is `offline`, a remote one is 404. `GET /sync` takes `set_presence` (`online` when omitted, `unavailable`, `offline`; another value is 400 `M_INVALID_PARAM`) and carries `presence.events` for users sharing a joined room. `presence.enabled=false` makes `GET` 404, `PUT` a 200 that stores nothing, and `/sync` presence-free. See `docs/user-manual.md` "Presence".

## Push notifications

| Method | Path | Operation ID | Auth | Request body | Responses |
| --- | --- | --- | --- | --- | --- |
| `GET` | `/_matrix/client/v3/notifications` | `getNotifications` | access token | - | 200 |
| `GET` | `/_matrix/client/v3/pushers` | `getPushers` | access token | - | 200 |
| `POST` | `/_matrix/client/v3/pushers/set` | `postPusher` | access token | required application/json | 200, 400, 429 |
| `GET` | `/_matrix/client/v3/pushrules/` | `getPushRules` | access token | - | 200 |
| `GET` | `/_matrix/client/v3/pushrules/global/` | `getPushRulesGlobal` | access token | - | 200 |
| `GET` | `/_matrix/client/v3/pushrules/global/{kind}/{ruleId}` | `getPushRule` | access token | - | 200, 404 |
| `PUT` | `/_matrix/client/v3/pushrules/global/{kind}/{ruleId}` | `setPushRule` | access token | required application/json | 200, 400, 404, 429 |
| `DELETE` | `/_matrix/client/v3/pushrules/global/{kind}/{ruleId}` | `deletePushRule` | access token | - | 200, 404 |
| `GET` | `/_matrix/client/v3/pushrules/global/{kind}/{ruleId}/actions` | `getPushRuleActions` | access token | - | 200, 404 |
| `PUT` | `/_matrix/client/v3/pushrules/global/{kind}/{ruleId}/actions` | `setPushRuleActions` | access token | required application/json | 200, 404 |
| `GET` | `/_matrix/client/v3/pushrules/global/{kind}/{ruleId}/enabled` | `isPushRuleEnabled` | access token | - | 200, 404 |
| `PUT` | `/_matrix/client/v3/pushrules/global/{kind}/{ruleId}/enabled` | `setPushRuleEnabled` | access token | required application/json | 200, 404 |

## Read Markers

| Method | Path | Operation ID | Auth | Request body | Responses |
| --- | --- | --- | --- | --- | --- |
| `POST` | `/_matrix/client/v3/rooms/{roomId}/read_markers` | `setReadMarker` | access token | required application/json | 200, 429 |

## Reporting content

| Method | Path | Operation ID | Auth | Request body | Responses |
| --- | --- | --- | --- | --- | --- |
| `POST` | `/_matrix/client/v3/rooms/{roomId}/report` | `reportRoom` | access token | required application/json | 200, 404, 429 |
| `POST` | `/_matrix/client/v3/rooms/{roomId}/report/{eventId}` | `reportEvent` | access token | required application/json | 200, 404 |
| `POST` | `/_matrix/client/v3/users/{userId}/report` | `reportUser` | access token | required application/json | 200, 404, 429 |

## Room creation

| Method | Path | Operation ID | Auth | Request body | Responses |
| --- | --- | --- | --- | --- | --- |
| `POST` | `/_matrix/client/v3/createRoom` | `createRoom` | access token | required application/json | 200, 400, 403 |

## Room directory

| Method | Path | Operation ID | Auth | Request body | Responses |
| --- | --- | --- | --- | --- | --- |
| `GET` | `/_matrix/client/v3/directory/room/{roomAlias}` | `getRoomIdByAlias` | none | - | 200, 400, 404 |
| `PUT` | `/_matrix/client/v3/directory/room/{roomAlias}` | `setRoomAlias` | access token | required application/json | 200, 400, 403, 404, 409 |
| `DELETE` | `/_matrix/client/v3/directory/room/{roomAlias}` | `deleteRoomAlias` | access token | - | 200, 400, 403, 404 |
| `GET` | `/_matrix/client/v3/rooms/{roomId}/aliases` | `getLocalAliases` | access token | - | 200, 400, 403, 429 |

## Room discovery

| Method | Path | Operation ID | Auth | Request body | Responses |
| --- | --- | --- | --- | --- | --- |
| `GET` | `/_matrix/client/v3/directory/list/room/{roomId}` | `getRoomVisibilityOnDirectory` | none | - | 200, 404 |
| `PUT` | `/_matrix/client/v3/directory/list/room/{roomId}` | `setRoomVisibilityOnDirectory` | access token | required application/json | 200, 400, 403, 404 |
| `GET` | `/_matrix/client/v3/publicRooms` | `getPublicRooms` | none | - | 200 |
| `POST` | `/_matrix/client/v3/publicRooms` | `queryPublicRooms` | access token | required application/json | 200 |

Implementation note (0.12.16, CSAZ-5): local public-room listings now require
explicit directory publication; a public join rule alone does not publish a
room. `createRoom` defaults to private directory visibility, and explicit
public visibility publishes it. The existing public-join listing filter is
retained. Directory publication is still in-memory, and POST authentication
has not yet been enforced; both remain tracked gaps, not completed fixes.

## Room membership

| Method | Path | Operation ID | Auth | Request body | Responses |
| --- | --- | --- | --- | --- | --- |
| `POST` | `/_matrix/client/v3/join/{roomIdOrAlias}` | `joinRoom` | access token | required application/json | 200, 403, 429 |
| `GET` | `/_matrix/client/v3/joined_rooms` | `getJoinedRooms` | access token | - | 200 |
| `POST` | `/_matrix/client/v3/knock/{roomIdOrAlias}` | `knockRoom` | access token | required application/json | 200, 403, 404, 429 |
| `POST` | `/_matrix/client/v3/rooms/{roomId}/ban` | `ban` | access token | required application/json | 200, 403 |
| `POST` | `/_matrix/client/v3/rooms/{roomId}/forget` | `forgetRoom` | access token | - | 200, 400, 429 |
| `POST` | `/_matrix/client/v3/rooms/{roomId}/invite` | `inviteBy3PID` | access token | required application/json | 200, 403, 429 |
| `POST` | `/_matrix/client/v3/rooms/{roomId}/invite` | `inviteUser` | access token | required application/json | 200, 400, 403, 429 |
| `POST` | `/_matrix/client/v3/rooms/{roomId}/join` | `joinRoomById` | access token | required application/json | 200, 403, 429 |
| `POST` | `/_matrix/client/v3/rooms/{roomId}/kick` | `kick` | access token | required application/json | 200, 403 |
| `POST` | `/_matrix/client/v3/rooms/{roomId}/leave` | `leaveRoom` | access token | required application/json | 200, 429 |
| `POST` | `/_matrix/client/v3/rooms/{roomId}/unban` | `unban` | access token | required application/json | 200, 403 |

Implementation note (0.12.16, CSAZ-7): invite and knock summaries expose only
`sender`, `type`, `state_key`, and `content`. The disclosure policy permits the
seven room-summary types recommended in the stripped-state specification plus
the recipient's own membership, excluding other membership events, ACLs, power
levels, and custom private state. Local invitations retain their invitation-time
snapshot; historical and federated snapshots are re-pruned on client reads,
including sliding-sync invite responses. Matrix permits additional event types;
the restrictive allowlist is our policy (ADR-0088), not a protocol prohibition.

Implementation note (0.12.59): `POST /knock/{roomIdOrAlias}` on a room this server is not in goes over
federation (`make_knock`, `send_knock`) to the servers named by `via` or the pre-v1.12 `server_name`, routed as
a join is (ADR-0242, ADR-0243), with the body's `reason` on the knock event. A resident's 403 is a 403. The
resident's `knock_room_state` is kept, without entries whose signature does not check out, and shown as
`knock_state`. A room alias is not resolved by `/knock` yet: it answers 404.

Implementation note (Complement run 10): `POST /rooms/{roomId}/kick` answers `403 M_FORBIDDEN` when the target is not currently in
the room (spec, kick 403: "The kickee is not currently in the room."). "In the room" is a membership of `join`, `invite`
or `knock`, the states a `leave` event can end; a user who left, was banned or never had a membership is refused (a
ban is lifted with `/unban`).

Implementation note (Complement run 10):

- `GET /rooms/{roomId}/event/{eventId}` answers `404 M_NOT_FOUND` to a user with no read access to the room, the same
  answer as for an event that does not exist (the endpoint's only error is 404). `/context` still answers 403.
- `PUT /rooms/{roomId}/state/m.room.canonical_alias` validates the aliases the new content adds (those not already in the
  room's current event): `400 M_INVALID_PARAM` for invalid syntax or a wrong field type, `400 M_BAD_ALIAS` for an alias on
  this server that is not in the directory or points at another room. An alias on another server is checked for syntax
  only (the SHOULD would need a federation call); aliases already listed or being removed are not validated. The check
  runs only for a sender who may send the event, so anyone else gets the 403. `createRoom` `initial_state` is not
  validated this way.
- `createRoom` `topic` writes `m.room.topic` with both `topic` and `m.topic` = `{"m.text":[{"body":..,"mimetype":"text/plain"}]}`,
  after `initial_state`, so it overwrites a topic given there. A `room_version` that is not a JSON string is
  `400 M_BAD_JSON`.
- Key backup uploads (`PUT /room_keys/keys[/{roomId}[/{sessionId}]]`) keep the better key for a session the backup
  already holds: a verified key beats an unverified one, then the lower `first_message_index`, then the lower
  `forwarded_count`. Keys equal on all three are not ordered by the spec; the one just uploaded replaces. The response
  is 200 either way.

Implementation note (run 10, 0.12.63): `invite_room_state` (an invite sent to another server) and
`knock_room_state` (a `send_knock` answer from this server) hold the room's stored signed PDUs of the
stripped-state types, create event first, as spec v1.16 requires; the client's `invite_state` and
`knock_state` are still stripped events. An inbound room version 12+ invite whose `invite_room_state` has no
create event, an unsigned or stripped entry, or an entry of another room is refused with 400
`M_INVALID_PARAM`; versions 1 to 11 are accepted as sent. `POST /rooms/{roomId}/leave` on an invite from
another server is a `make_leave` / `send_leave` to the inviter's server (the invite is ended locally when that
server no longer has the room), and `POST /join/{roomId}` with no server named tries the inviter's server.

## Room participation

| Method | Path | Operation ID | Auth | Request body | Responses |
| --- | --- | --- | --- | --- | --- |
| `GET` | `/_matrix/client/v1/rooms/{roomId}/timestamp_to_event` | `getEventByTimestamp` | access token | - | 200, 404, 429 |
| `GET` | `/_matrix/client/v3/events` | `getEvents` | access token | - | 200, 400 |
| `GET` | `/_matrix/client/v3/events` | `peekEvents` | access token | - | 200, 400 |
| `GET` | `/_matrix/client/v3/events/{eventId}` | `getOneEvent` | access token | - | 200, 404 |
| `GET` | `/_matrix/client/v3/initialSync` | `initialSync` | access token | - | 200, 404 |
| `GET` | `/_matrix/client/v3/rooms/{roomId}/context/{eventId}` | `getEventContext` | access token | - | 200 |
| `GET` | `/_matrix/client/v3/rooms/{roomId}/event/{eventId}` | `getOneRoomEvent` | access token | - | 200, 404 |
| `GET` | `/_matrix/client/v3/rooms/{roomId}/initialSync` | `roomInitialSync` | access token | - | 200, 403 |
| `GET` | `/_matrix/client/v3/rooms/{roomId}/joined_members` | `getJoinedMembersByRoom` | access token | - | 200, 403 |
| `GET` | `/_matrix/client/v3/rooms/{roomId}/members` | `getMembersByRoom` | access token | - | 200, 403 |
| `GET` | `/_matrix/client/v3/rooms/{roomId}/messages` | `getRoomEvents` | access token | - | 200, 403 |
| `POST` | `/_matrix/client/v3/rooms/{roomId}/receipt/{receiptType}/{eventId}` | `postReceipt` | access token | required application/json | 200, 400, 429 |
| `PUT` | `/_matrix/client/v3/rooms/{roomId}/redact/{eventId}/{txnId}` | `redactEvent` | access token | required application/json | 200, 400, 403, 404 |
| `PUT` | `/_matrix/client/v3/rooms/{roomId}/send/{eventType}/{txnId}` | `sendMessage` | access token | required application/json | 200, 400 |
| `GET` | `/_matrix/client/v3/rooms/{roomId}/state` | `getRoomState` | access token | - | 200, 403 |
| `GET` | `/_matrix/client/v3/rooms/{roomId}/state/{eventType}/{stateKey}` | `getRoomStateWithKey` | access token | - | 200, 403, 404 |
| `PUT` | `/_matrix/client/v3/rooms/{roomId}/state/{eventType}/{stateKey}` | `setRoomStateWithKey` | access token | required application/json | 200, 400, 403 |
| `PUT` | `/_matrix/client/v3/rooms/{roomId}/typing/{userId}` | `setTyping` | access token | required application/json | 200, 429 |
| `GET` | `/_matrix/client/v3/sync` | `sync` | access token | - | 200 |
| `POST` | `/_matrix/client/v3/user/{userId}/filter` | `defineFilter` | access token | required application/json | 200 |
| `GET` | `/_matrix/client/v3/user/{userId}/filter/{filterId}` | `getFilter` | access token | - | 200, 404 |

## Room upgrades

| Method | Path | Operation ID | Auth | Request body | Responses |
| --- | --- | --- | --- | --- | --- |
| `POST` | `/_matrix/client/v3/rooms/{roomId}/upgrade` | `upgradeRoom` | access token | required application/json | 200, 400, 403 |

## Search

| Method | Path | Operation ID | Auth | Request body | Responses |
| --- | --- | --- | --- | --- | --- |
| `POST` | `/_matrix/client/v3/search` | `search` | access token | required application/json | 200, 400, 429 |

## Send-to-Device messaging

| Method | Path | Operation ID | Auth | Request body | Responses |
| --- | --- | --- | --- | --- | --- |
| `PUT` | `/_matrix/client/v3/sendToDevice/{eventType}/{txnId}` | `sendToDevice` | access token | required application/json | 200 |

## Server administration

| Method | Path | Operation ID | Auth | Request body | Responses |
| --- | --- | --- | --- | --- | --- |
| `GET` | `/_matrix/client/v1/admin/lock/{userId}` | `getAdminLockUser` | access token | - | 200, 400, 403, 404 |
| `PUT` | `/_matrix/client/v1/admin/lock/{userId}` | `setAdminLockUser` | access token | required application/json | 200, 400, 403, 404 |
| `GET` | `/_matrix/client/v1/admin/suspend/{userId}` | `getAdminSuspendUser` | access token | - | 200, 400, 403, 404 |
| `PUT` | `/_matrix/client/v1/admin/suspend/{userId}` | `setAdminSuspendUser` | access token | required application/json | 200, 400, 403, 404 |
| `GET` | `/_matrix/client/v3/admin/whois/{userId}` | `getWhoIs` | access token | - | 200 |
| `GET` | `/_matrix/client/versions` | `getVersions` | optional | - | 200 |
| `GET` | `/.well-known/matrix/client` | `getWellknown` | none | - | 200, 404 |
| `GET` | `/.well-known/matrix/policy_server` | `getWellknownPolicy` | none | - | 200, 404 |
| `GET` | `/.well-known/matrix/support` | `getWellknownSupport` | none | - | 200, 404 |

## Session management

| Method | Path | Operation ID | Auth | Request body | Responses |
| --- | --- | --- | --- | --- | --- |
| `GET` | `/_matrix/client/v1/auth_metadata` | `getAuthMetadata` | none | - | 200, 404 |

Implemented: returns RFC 8414 metadata when `server.oidc.*` is configured; `404 M_UNRECOGNIZED` otherwise.
| `POST` | `/_matrix/client/v1/login/get_token` | `generateLoginToken` | access token | required application/json | 200, 400, 401, 429 |
| `GET` | `/_matrix/client/v3/account/whoami` | `getTokenOwner` | access token | - | 200, 401, 403, 429 |
| `GET` | `/_matrix/client/v3/login` | `getLoginFlows` | none | - | 200, 404, 429 |
| `POST` | `/_matrix/client/v3/login` | `login` | none | required application/json | 200, 400, 403, 429 |
| `GET` | `/_matrix/client/v3/login/sso/redirect` | `redirectToSSO` | none | - | 302 |
| `GET` | `/_matrix/client/v3/login/sso/redirect/{idpId}` | `redirectToIdP` | none | - | 302, 404 |
| `POST` | `/_matrix/client/v3/logout` | `logout` | access token | - | 200 |
| `POST` | `/_matrix/client/v3/logout/all` | `logout_all` | access token | - | 200 |

Refresh-enabled `POST /_matrix/client/v3/login` and `POST /_matrix/client/v3/refresh`
include `expires_in_ms` for positive configured access-token lifetimes. When
`security.access_token_lifetime_ms` is zero, both omit the optional field: its
absence means that the issued access token does not expire (Matrix v1.19).
Legacy login without refresh support is unchanged. These response semantics are
covered by `tests/conformance/test_token_expiry_conformance.cpp`; registration
expiry responses are outside that scenario's scope.

## Spaces

| Method | Path | Operation ID | Auth | Request body | Responses |
| --- | --- | --- | --- | --- | --- |
| `GET` | `/_matrix/client/v1/rooms/{roomId}/hierarchy` | `getSpaceHierarchy` | access token | - | 200, 400, 403, 429 |

`getSpaceHierarchy` walks the space depth-first. A child room this server holds state for is judged from that state for the
requesting user: joined or invited, `public`, `knock` / `knock_restricted`, `world_readable`, or `restricted` with the user joined
to one of the rooms the join rule names. A child it holds no state for is asked for over federation
(`GET /_matrix/federation/v1/hierarchy/{roomId}`) from the servers in the link's `via` (at most 3 per room, 16 requests per
walk, one outbound-budget slot and one deadline per request, `429 M_LIMIT_EXCEEDED` when the budget is full) and kept only if
the requesting user may see it according to what that server reported; local state, where the server has it, is always used
instead of the remote answer. With `suggested_only=true` the walk and every space's `children_state` carry the suggested links only.

`getRoomSummary` (Complement run 10) answers for a room, or a local alias, this server holds state for. `via` is accepted and
ignored: a room this server has no state of, or an alias on another server, is `404` to an authenticated caller and `401
M_MISSING_TOKEN` to one without a token, as every room it may not see is (asking a peer for a summary is not implemented). An authenticated caller is shown a room they are joined to, invited to or have knocked on, or that is `public`,
`knock` / `knock_restricted`, `world_readable`, or `restricted` with the caller joined to an allowed room; any other room is
`404 M_NOT_FOUND`. `membership` is the caller's own membership when they have one, and is absent without a token. A request
without a token (the spec's MAY) is served for `public`, `knock`, `knock_restricted` and `world_readable` rooms only, and
every other room, existing or not, gets the same `401 M_MISSING_TOKEN`. The body is the hierarchy's room chunk without
`children_state`.

## Third-party Lookup

| Method | Path | Operation ID | Auth | Request body | Responses |
| --- | --- | --- | --- | --- | --- |
| `GET` | `/_matrix/client/v3/thirdparty/location` | `queryLocationByAlias` | access token | - | 200, 404 |
| `GET` | `/_matrix/client/v3/thirdparty/location/{protocol}` | `queryLocationByProtocol` | access token | - | 200, 404 |
| `GET` | `/_matrix/client/v3/thirdparty/protocol/{protocol}` | `getProtocolMetadata` | access token | - | 200, 404 |
| `GET` | `/_matrix/client/v3/thirdparty/protocols` | `getProtocols` | access token | - | 200 |
| `GET` | `/_matrix/client/v3/thirdparty/user` | `queryUserByID` | access token | - | 200, 404 |
| `GET` | `/_matrix/client/v3/thirdparty/user/{protocol}` | `queryUserByProtocol` | access token | - | 200, 404 |

## Threads

| Method | Path | Operation ID | Auth | Request body | Responses |
| --- | --- | --- | --- | --- | --- |
| `GET` | `/_matrix/client/v1/rooms/{roomId}/threads` | `getThreadRoots` | access token | - | 200, 400, 403, 429 |

## untagged

| Method | Path | Operation ID | Auth | Request body | Responses |
| --- | --- | --- | --- | --- | --- |
| `POST` | `/_matrix/client/v1/appservice/{appserviceId}/ping` | `pingAppservice` | appservice token | required application/json | 200, 400, 403, 502, 504 |
| `GET` | `/_matrix/client/v1/room_summary/{roomIdOrAlias}` | `getRoomSummary` | signed request | - | 200, 404 |
| `POST` | `/_matrix/client/v3/refresh` | `refresh` | none | required application/json | 200, 401, 429 |

## User data

| Method | Path | Operation ID | Auth | Request body | Responses |
| --- | --- | --- | --- | --- | --- |
| `GET` | `/_matrix/client/v3/profile/{userId}` | `getUserProfile` | none | - | 200, 403, 404 |
| `GET` | `/_matrix/client/v3/profile/{userId}/{keyName}` | `getProfileField` | none | - | 200, 403, 404 |
| `PUT` | `/_matrix/client/v3/profile/{userId}/{keyName}` | `setProfileField` | access token | required application/json | 200, 400, 403, 429 |
| `DELETE` | `/_matrix/client/v3/profile/{userId}/{keyName}` | `deleteProfileField` | access token | - | 200, 400, 403, 429 |
| `GET` | `/_matrix/client/v3/user/{userId}/account_data/{type}` | `getAccountData` | access token | - | 200, 403, 404 |
| `PUT` | `/_matrix/client/v3/user/{userId}/account_data/{type}` | `setAccountData` | access token | required application/json | 200, 400, 403, 405 |
| `GET` | `/_matrix/client/v3/user/{userId}/rooms/{roomId}/account_data/{type}` | `getAccountDataPerRoom` | access token | - | 200, 400, 403, 404 |
| `PUT` | `/_matrix/client/v3/user/{userId}/rooms/{roomId}/account_data/{type}` | `setAccountDataPerRoom` | access token | required application/json | 200, 400, 403, 405 |
| `GET` | `/_matrix/client/v3/user/{userId}/rooms/{roomId}/tags` | `getRoomTags` | access token | - | 200 |
| `PUT` | `/_matrix/client/v3/user/{userId}/rooms/{roomId}/tags/{tag}` | `setRoomTag` | access token | required application/json | 200 |
| `DELETE` | `/_matrix/client/v3/user/{userId}/rooms/{roomId}/tags/{tag}` | `deleteRoomTag` | access token | - | 200 |

## User directory

| Method | Path | Operation ID | Auth | Request body | Responses |
| --- | --- | --- | --- | --- | --- |
| `POST` | `/_matrix/client/v3/user_directory/search` | `searchUserDirectory` | access token | required application/json | 200, 429 |

## VOIP

| Method | Path | Operation ID | Auth | Request body | Responses |
| --- | --- | --- | --- | --- | --- |
| `GET` | `/_matrix/client/v3/voip/turnServer` | `getTurnServer` | access token | - | 200, 429 |

### Security audit follow-up (0.12.17)

POST /_matrix/client/v3/publicRooms runs after the shared authentication and account-state gates, including remote lookups. Directory publication is durable and independent of join rules: a published invite-only room remains listed. Presence sync includes only peers sharing a current joined membership; PUT presence requires online, offline or unavailable and an optional string status_msg. The local 1024 UTF-8 byte status cap is resource policy (ADR-0098).

## Application service ping, network directories and 3PID requestToken (conformance wave 3)

`POST /_matrix/client/v1/appservice/{appserviceId}/ping` requires an application service `as_token` whose appservice is the one named in the path (`403 M_FORBIDDEN` for a user's token, another appservice's token or an unknown id; `401` with no token). It calls `POST /_matrix/app/v1/ping` on the registered `url` with the registration's hs_token and the optional `transaction_id`, copied as given, the empty string included (a non-string is `400 M_BAD_JSON`), and answers `200 {"duration_ms": N}`, `400 M_URL_NOT_SET`, `502 M_CONNECTION_FAILED`, `502 M_BAD_STATUS` carrying the appservice's `status` and a body cut to 1024 bytes of well-formed UTF-8, or `504 M_CONNECTION_TIMEOUT`. It is not rate limited for a verified appservice, holds a client-outbound slot (`429 M_LIMIT_EXCEEDED` when none is free), and releases `runtime.mutex` for the call.

`PUT /_matrix/client/v3/directory/list/appservice/{networkId}/{roomId}` takes `{"visibility": "public" | "private"}` from an `as_token` and persists the room in the directory of that network (ADR-0192): `networkId` must be a protocol the registration declares (`404 M_NOT_FOUND`), the room must exist (`404`) and the appservice must have an interest in it (`403 M_FORBIDDEN`); a user's token is `403`. `POST /publicRooms` lists the homeserver's own directory by default, one network's rooms for `third_party_instance_id` (the `instance_id` from `GET /thirdparty/protocol/{protocol}`, `<registration id>:<protocol>:<index>`), and both together for `include_all_networks: true`. Naming both is `400 M_INVALID_PARAM`; a wrong type for either is `400 M_BAD_JSON`; an id that names no network lists nothing. A `?server=` lookup forwards both fields to the remote server.

The four `requestToken` endpoints (`/register/{email,msisdn}/requestToken`, `/account/3pid/{email,msisdn}/requestToken`) forward the client's `send_attempt` to the identity server, and every route that forwards an `id_access_token` (those, `/account/3pid/bind`, `/account/3pid` and the 3PID form of `/rooms/{roomId}/invite`) answers `400 M_INVALID_PARAM` for one that is not printable ASCII without spaces of at most 4096 bytes.

## Per-user key and filter caps (CSAZ-10)

`POST /_matrix/client/v3/keys/upload` answers 400 `M_TOO_LARGE` and stores nothing (no device, one-time or fallback keys) when the request would leave a device holding more than `server.client_api.max_one_time_keys_per_device` one-time keys; key IDs already held are not counted twice. A device keeps one fallback key per algorithm: a newly uploaded fallback key replaces the previous key of that algorithm. `POST /_matrix/client/v3/keys/signatures/upload` answers 400 `M_TOO_LARGE` and stores nothing when it would take the signer past `server.client_api.max_key_signatures_per_user` distinct (target user, target key) signatures. `POST /_matrix/client/v3/user/{userId}/filter` returns the existing `filter_id` for a definition identical to a stored one after JSON canonicalisation, and otherwise answers 400 `M_TOO_LARGE` once the user holds `server.client_api.max_filters_per_user` filters. Over-cap requests are refused, never satisfied by evicting stored rows. See [operator budgets](user-manual.md#operational-budgets).

## Readings of open spec points chosen to match Complement (0.12.60)

In each case below the spec leaves the choice to the server; the owner decided to follow Complement's reading.

- **Event size limit status.** A locally composed event over 65536 bytes (or with a `type` or `state_key` over 255 bytes) is refused `413 M_TOO_LARGE` on `PUT /send`, `PUT /state`, membership endpoints and `createRoom` (it was `400 M_TOO_LARGE`). The other `M_TOO_LARGE` refusals (per-user caps) stay 400.
- **`POST /user/{userId}/filter` validates the Filter schema.** A field of the wrong JSON type, a `senders`/`not_senders` entry that is not a user ID, or a `rooms`/`not_rooms` entry that is not a room ID answers `400 M_BAD_JSON` and stores nothing (it was stored and answered 200). `/sync` and `/messages` still read leniently any filter stored before.
- **`POST /keys/upload` and a malformed `device_keys`.** Missing or non-object `keys`, non-string `user_id`/`device_id`, non-list `algorithms` or non-object `signatures` answer `400 M_BAD_JSON`. A well-formed object naming another user or device, or lacking the `curve25519:`/`ed25519:` pair for the device, stays `M_INVALID_PARAM`. `algorithms` and `signatures` are checked only when present.
- **`GET /rooms/{roomId}/messages` with `lazy_load_members`.** `state` holds only the `m.room.member` events of the senders of the returned `chunk` (no other state). Redundant membership events are not tracked across calls, so a sender's membership is sent on every page (the spec's `include_redundant_members` default permits it). `/context` is unchanged.
- **Initial `/sync` carries `m.push_rules`.** An initial `/sync` (no usable `since`) always holds a global `m.push_rules` account-data event with the user's effective ruleset (the server defaults plus their changes), if the filter's `account_data` admits it. An incremental `/sync` carries it only after a change.
- **A hole in the event graph makes a joined room's `/sync` timeline `limited` (ADR-0289).** The spec defines `limited` by the filter `limit` and leaves events the server never received over federation unspecified; an event in the window whose `prev_events` are not all held (no row, or an outlier with no state group; rejected, soft-failed and backfilled events count as held, ADR-0290) starts a limited timeline at that event, with `prev_batch` for `/messages` to reach what lies before. A limited incremental sync carries the state at the start of the timeline. Sliding sync is unchanged.
- **`POST /user_directory/search` searches visible users only.** A search considers the users who share a joined room with the requester, and users joined to a room whose join rule is `public` or whose history visibility is `world_readable`. The requester is found only through a public or world-readable room. Before, every local profile matched.
- **`POST /account/password` deletes pushers of revoked devices.** With `logout_devices` true (the default), the pushers set (`POST /pushers/set`) with the access token of a device whose tokens the change revokes are deleted. The requesting device's pushers, and pushers with no recorded device, stay. A pusher records its device in `pushers.device_id`.
- **A failed UIA stage carries `errcode` and `error`.** A wrong account password on `POST /account/password`, `/account/deactivate`, `/account/3pid/add`, `/keys/device_signing/upload`, `DELETE /devices/{deviceId}` and `POST /delete_devices` is `401` with the `flows`, `params` and `session` of the challenge plus `errcode: M_FORBIDDEN` and `error`; a request making no attempt gets the bare challenge. `DELETE /devices/{deviceId}` does not compare the user a password `identifier` names with the token's user: the password checked is the token owner's (the spec states no status for a mismatch).
- **`POST /logout` and `POST /logout/all` delete the device(s).** `GET /devices` no longer lists the logged-out device (all of the user's devices after `/logout/all`). A request with no token is `401 M_MISSING_TOKEN`.
- **`POST /register`.** `username` is checked (`400 M_INVALID_USERNAME`, `M_USER_IN_USE`, `M_EXCLUSIVE`) before UIA starts, as the spec requires; a single-shot `m.login.dummy` request with no `session` completes, and a `session` the server did not issue is answered `401` with the challenge (ADR-0276).
- **`M_NOT_JSON` and `405 M_UNRECOGNIZED`.** A request body that is not valid JSON (including invalid UTF-8) is `400 M_NOT_JSON` on every client endpoint. A served path used with a method it does not serve is `405 M_UNRECOGNIZED` (with `Allow` for fixed paths) on the client, media, key and federation surfaces; an unserved path stays `404 M_UNRECOGNIZED`. See [http-transport.md](http-transport.md).

## Remote profiles and redactions of unknown events (Complement run 10)

- **`GET /profile/{userId}[/{keyName}]` for a user of another server** asks that server's `GET /_matrix/federation/v1/query/profile` (with `field` for a single key) and answers with its `displayname` and `avatar_url` only; the remote's 404 is a 404 here, its 403 a 403, and any other failure `502 M_UNKNOWN`. It is a client request that calls another server, so it holds a client-outbound slot (`429 M_LIMIT_EXCEEDED` when refused) and runs under the directory deadline (ADR-0079).
- **`PUT /rooms/{roomId}/redact/{eventId}/{txnId}` for an event this server does not hold** is accepted (200) when the sender holds the room's `redact` level, because the spec defines no 404 and the redaction must reach the servers that hold the event. A sender below that level is refused `403 M_FORBIDDEN`: whose event it is cannot be checked. An event held in another room is still `404 M_NOT_FOUND`. The redaction is judged against its target if the target arrives later.

## Configurable response budgets (0.12.18)

The client-server runtime applies `server.client_api` policy to sync room/timeline counts, message/search/context work and pages, notifications/relations/threads/public-room/hierarchy listings and transient session cardinality. Sliding-sync parsing receives the same configured policy for timeline/subscription/state-pair caps. Client-requested limits remain upper bounds; increasing a server maximum does not change a client's requested timeline size or bypass history visibility, ignore-list or accepted-event filtering. See [operator budgets](user-manual.md#operational-budgets) for defaults and ranges. Runtime policies require restart.

## Conformance audit wave 4 (0.12.38)

Room account data (`GET`/`PUT /user/{userId}/rooms/{roomId}/account_data/{type}`) is routed. Both account-data `PUT`s require a JSON object body (`400 M_NOT_JSON` / `M_BAD_JSON`) and refuse the server-managed `m.fully_read` and `m.push_rules` with `405 M_BAD_JSON`. A room `PUT` needs a membership row in the room and stops new types at `server.client_api.max_room_account_data_per_room` (ADR-0197). `POST /register` without `username` gets a generated localpart (ADR-0198). `PUT /rooms/{roomId}/typing/{userId}` requires a boolean `typing`, and typing expires after its `timeout`, at most 120 s (ADR-0199). `POST /search` covers rooms the user has left, up to the point they left.

## Event lookup by timestamp (0.12.64)

`GET /rooms/{roomId}/timestamp_to_event?ts=&dir=` (ADR-0299, ADR-0300) returns `{event_id, origin_server_ts}` of the event
nearest `ts` in the direction `dir` (`f` or `b`). Both parameters are required (400 `M_MISSING_PARAM` / `M_INVALID_PARAM`).
The boundary is inclusive and events sharing a timestamp are ordered by (`origin_server_ts`, `depth`, `stream_ordering`),
so `f` finds the first and `b` the last. A user who cannot read the room gets 403 `M_FORBIDDEN` like `/messages`; events
`sync::HistoryVisibility` withholds are stepped over, up to 1000 candidates, then 404. The lookup is one seek of the
per-room time index of `EventTable`. When the local answer is absent, or has a `prev_event` this server does not hold,
up to three servers of the room (longest in the room first, by the stream ordering of their earliest current join) are
asked over `GET /_matrix/federation/v1/timestamp_to_event/{roomId}`, one at a time, under one client-outbound slot and the
10 s directory deadline. A remote answer counts only if it is on the requested side and strictly closer; the event is then
fetched with `GET /event/{eventId}` and stored through the verified backfill path, and returned only if that succeeded and
the user may see it. No slot: 429 when there is no local answer, the local answer otherwise. Rate limiting follows the
route tier; the federation endpoint is not rate limited (spec) and judges the requesting server like the other room
reads (403 for a server with no joined user, events its users could not see stepped over).

The 400 and 403 answers are not in the operation's response list above, which is generated from the spec: 400 follows the
common error codes for a missing or malformed required parameter, and 403 is the owner's choice for a user who may not read
the room (ADR-0299).

## Application service timestamp massaging (0.12.64)

An application service (a request authenticated with an `as_token`) may append `ts=<milliseconds>` to
`PUT /rooms/{roomId}/send/{eventType}/{txnId}` and `PUT /rooms/{roomId}/state/{eventType}/{stateKey}` (Application
Service API, "Timestamp massaging"; ADR-0303). The event's `origin_server_ts` is then `ts`. A `ts` that is not a
decimal integer in `[-(2**53)+1, (2**53)-1]` (empty, fractional, exponent, signed `+`, out of range) is refused with
`400 M_INVALID_PARAM` and nothing is stored. Without `ts` the server's own clock is used. Only these two routes read
`ts`; on any other route, or from a caller that is not an application service, it is ignored. The spec is silent on
whether a non-appservice `ts` should be rejected, so the server leaves such a request as it would be without it.
The event is still appended at the tip of the DAG: `depth`, `prev_events` and the stream position are those of "now",
and `GET /timestamp_to_event` orders by the massaged timestamp as it does for any event.
