# Matrix v1.18 Client-Server API Reference

> Generated file. Do not edit endpoint rows by hand; regenerate with `node scripts/generate-matrix-v118-spec-doc.mjs`.

## Source

- Official OpenAPI document: matrix-v1.18-spec/client-server-api.md
- Human-readable reference: matrix-v1.18-spec/client-server-api.md
- OpenAPI: 3.1.0
- Title: Matrix Client-Server API
- Version: v1.18
- Generated: 2026-05-21
- Source SHA-256: `2d5c59705e40bd4570b1d78908b57d9a5a7f3d7975a2ac3db8699d7d5c754604`

## Summary

- Paths: 135
- Operations: 165
- Tags: 29

| Tag | Operations |
| --- | ---: |
| Account management | 17 |
| Application service room directory management | 1 |
| Capabilities | 1 |
| Device management | 5 |
| End-to-end encryption | 20 |
| Event relationships | 3 |
| Media | 13 |
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
| `POST` | `/_matrix/client/v3/account/3pid/add` | `add3PID` | access token | required application/json | 200, 401, 429 |
| `POST` | `/_matrix/client/v3/account/3pid/bind` | `bind3PID` | access token | required application/json | 200, 429 |
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

## OpenID

| Method | Path | Operation ID | Auth | Request body | Responses |
| --- | --- | --- | --- | --- | --- |
| `POST` | `/_matrix/client/v3/user/{userId}/openid/request_token` | `requestOpenIdToken` | access token | required application/json | 200, 429 |

## Presence

| Method | Path | Operation ID | Auth | Request body | Responses |
| --- | --- | --- | --- | --- | --- |
| `GET` | `/_matrix/client/v3/presence/{userId}/status` | `getPresence` | access token | - | 200, 403, 404 |
| `PUT` | `/_matrix/client/v3/presence/{userId}/status` | `setPresence` | access token | required application/json | 200, 429 |

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
| `PUT` | `/_matrix/client/v3/directory/room/{roomAlias}` | `setRoomAlias` | access token | required application/json | 200, 400, 409 |
| `DELETE` | `/_matrix/client/v3/directory/room/{roomAlias}` | `deleteRoomAlias` | access token | - | 200, 404 |
| `GET` | `/_matrix/client/v3/rooms/{roomId}/aliases` | `getLocalAliases` | access token | - | 200, 400, 403, 429 |

## Room discovery

| Method | Path | Operation ID | Auth | Request body | Responses |
| --- | --- | --- | --- | --- | --- |
| `GET` | `/_matrix/client/v3/directory/list/room/{roomId}` | `getRoomVisibilityOnDirectory` | none | - | 200, 404 |
| `PUT` | `/_matrix/client/v3/directory/list/room/{roomId}` | `setRoomVisibilityOnDirectory` | access token | required application/json | 200, 404 |
| `GET` | `/_matrix/client/v3/publicRooms` | `getPublicRooms` | none | - | 200 |
| `POST` | `/_matrix/client/v3/publicRooms` | `queryPublicRooms` | access token | required application/json | 200 |

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

`leaveRoom` is implemented as an idempotent client operation: when the caller is already effectively out of the room, Merovingian still returns `200 {}` instead of surfacing stale local membership state back to the client.

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
| `PUT` | `/_matrix/client/v3/rooms/{roomId}/redact/{eventId}/{txnId}` | `redactEvent` | access token | required application/json | 200 |
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
| `POST` | `/_matrix/client/v1/login/get_token` | `generateLoginToken` | access token | required application/json | 200, 400, 401, 429 |
| `GET` | `/_matrix/client/v3/account/whoami` | `getTokenOwner` | access token | - | 200, 401, 403, 429 |
| `GET` | `/_matrix/client/v3/login` | `getLoginFlows` | none | - | 200, 404, 429 |
| `POST` | `/_matrix/client/v3/login` | `login` | none | required application/json | 200, 400, 403, 429 |
| `GET` | `/_matrix/client/v3/login/sso/redirect` | `redirectToSSO` | none | - | 302 |
| `GET` | `/_matrix/client/v3/login/sso/redirect/{idpId}` | `redirectToIdP` | none | - | 302, 404 |
| `POST` | `/_matrix/client/v3/logout` | `logout` | access token | - | 200 |
| `POST` | `/_matrix/client/v3/logout/all` | `logout_all` | access token | - | 200 |

## Spaces

| Method | Path | Operation ID | Auth | Request body | Responses |
| --- | --- | --- | --- | --- | --- |
| `GET` | `/_matrix/client/v1/rooms/{roomId}/hierarchy` | `getSpaceHierarchy` | access token | - | 200, 400, 403, 429 |

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

---

## Unstable Extensions

The following endpoints are **not part of the stable v1.18 spec**. They are served under
`/_matrix/client/unstable/` and are advertised via `unstable_features` in
`/_matrix/client/versions`. They may change or be removed when finalised by the spec process.

### MSC4186 — Simplified Sliding Sync

- **Proposal**: <https://github.com/matrix-org/matrix-spec-proposals/blob/main/proposals/4186-simplified-sliding-sync.md>
- **Advertised via**: `unstable_features["org.matrix.msc4186"] = true` and
  `unstable_features["org.matrix.simplified_msc3575"] = true` in `/_matrix/client/versions`
- **Implementation files**:
  - `include/merovingian/sync/sliding_sync.hpp` — request/response types
  - `include/merovingian/sync/sliding_sync_parser.hpp` + `src/sync/sliding_sync_parser.cpp` — request parser
  - `include/merovingian/sync/sliding_sync_room_list.hpp` + `src/sync/sliding_sync_room_list.cpp` — room-list windowing and ops
  - `include/merovingian/sync/sliding_sync_room_builder.hpp` + `src/sync/sliding_sync_room_builder.cpp` — per-room response builder
  - `include/merovingian/sync/sliding_sync_extensions.hpp` + `src/sync/sliding_sync_extensions.cpp` — five extensions
  - `src/homeserver/client_server.cpp` — HTTP handler (`sliding_sync_json`)

| Method | Path | Auth | Request body | Responses |
| --- | --- | --- | --- | --- |
| `POST` | `/_matrix/client/unstable/org.matrix.msc4186/sync` | access token | optional `application/json` | 200, 400 |

#### Query parameters

| Parameter | Type | Description |
| --- | --- | --- |
| `pos` | string | Opaque position token from the previous response. Absent on first request (initial sync). |
| `timeout` | integer | Long-poll wait time in milliseconds. Absent or 0 = respond immediately. |

#### Request body fields

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `conn_id` | string | optional | Identifies a logical connection so the server can maintain separate state per client tab. |
| `lists` | object | optional | Named room lists. Keys are arbitrary list IDs chosen by the client. |
| `lists.*.ranges` | array of [start, end] pairs | required if list present | Windowed view into the sorted room list. Ranges MUST NOT overlap; start MUST be ≤ end. |
| `lists.*.sort` | array of strings | optional | Sort criteria applied left-to-right: `by_recency`, `by_notification_count`, `by_name`. |
| `lists.*.required_state` | array of [type, state_key] pairs | optional | State events to include in each room. `"*"` is a wildcard in either position. |
| `lists.*.timeline_limit` | integer | optional | Maximum number of timeline events to return per room. |
| `room_subscriptions` | object | optional | Explicit per-room subscriptions keyed by room ID. |
| `extensions` | object | optional | Extension requests. Each extension has an `enabled` boolean. |
| `extensions.to_device` | object | optional | Fetch pending to-device messages. Fields: `enabled`, `limit`, `since`. |
| `extensions.e2ee` | object | optional | Fetch device list changes and OTK counts. Fields: `enabled`. |
| `extensions.account_data` | object | optional | Fetch global and per-room account data. Fields: `enabled`. |
| `extensions.receipts` | object | optional | Fetch read receipts. Fields: `enabled`, `rooms`. |
| `extensions.typing` | object | optional | Fetch typing notifications. Fields: `enabled`, `rooms`. |

#### Response body fields

| Field | Type | Description |
| --- | --- | --- |
| `pos` | string | New opaque position token. MUST be returned on every successful response. |
| `lists` | object | One entry per list. Contains `count` (total rooms matching the filter) and `ops` (list operations). |
| `rooms` | object | One entry per room included in the response. Keyed by room ID. |
| `extensions` | object | Extension responses. Only present for enabled extensions. |

#### List operations (`ops` array)

| Op | Description |
| --- | --- |
| `SYNC` | A range window is being sent in full. `range` and `room_ids` are populated. |
| `INVALIDATE` | A previously sent range is now invalid. `range` is populated; `room_ids` is absent. |
| `INSERT` | A single room was inserted at `index`. |
| `DELETE` | The room at `index` was removed. |
| `UPDATE` | The room at `index` changed without moving. |

#### Connection state

The server maintains per-connection state keyed by `user_id/device_id/conn_id`. This allows
the server to send only incremental updates on subsequent requests (new rooms, changed rooms,
updated ops) rather than retransmitting the full window every time.

Connection state is stored in `HomeserverRuntime::sliding_sync_connections`
(`include/merovingian/homeserver/runtime.hpp`). Connections are keyed by
`"{user_id}/{device_id}/{conn_id_or___default__}"` and track previous list windows,
rooms seen, and the last event ordering seen.
