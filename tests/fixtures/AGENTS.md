# tests/fixtures/ — Test Fixtures

Static fixtures used by the integration and complement test runners.

## Contents

| Path | Purpose |
|---|---|
| `complement/` | JSON fixture files driving `test_sync_complement_fixture.cpp` |
| `complement/client_server_v1_18.json` | Client-server API flow tests: register, login, send, sync, media |

## Complement fixture format

Each fixture file is a JSON array of steps. Each step is an object:

```json
{
  "method": "POST",
  "path": "/_matrix/client/v3/register",
  "body": { "username": "alice", "password": "hunter2" },
  "expect_status": 200,
  "expect_keys_present": ["access_token", "user_id"],
  "save_as": { "token": "access_token" }
}
```

### Supported fields

| Field | Type | Meaning |
|---|---|---|
| `method` | string | HTTP method |
| `path` | string | Request path |
| `auth_from` | string | Variable name holding the access token to use |
| `body` | object | JSON request body |
| `raw_body` | string | Raw (non-JSON) request body |
| `content_type` | string | Sets `Content-Type` header; required for media uploads |
| `expect_status` | integer | Expected HTTP status code |
| `expect_keys_present` | array of strings | Keys that must appear in the JSON response body |
| `save_as` | object | Maps variable name → JSON path in response to save for later steps |
| `save_mxc_media_id` | object | Like `save_as` but extracts the media ID from an MXC URI |

## Rules

- Fixture steps test complete flows end-to-end, not individual endpoints.
- If an endpoint changes its response format, update the fixture **and** cite the spec section.
- Do not add large binary blobs to fixture files — use `raw_body` with short placeholder bytes.
