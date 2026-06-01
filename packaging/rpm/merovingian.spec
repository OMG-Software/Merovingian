Name:           merovingian
Version:        0.4.56
Release:        1%{?dist}
Summary:        Secure Matrix Protocol homeserver

License:        GPL-3.0-or-later
URL:            https://github.com/OMG-Software/Merovingian
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  clang
BuildRequires:  meson
BuildRequires:  ninja-build
BuildRequires:  pkgconf-pkg-config
BuildRequires:  git
BuildRequires:  openssl-devel
BuildRequires:  libsodium-devel
BuildRequires:  libpq-devel
BuildRequires:  libcurl-devel
BuildRequires:  catch-devel
BuildRequires:  perl
BuildRequires:  bison
BuildRequires:  flex
BuildRequires:  m4
BuildRequires:  systemd-rpm-macros

%description
Merovingian is an alpha Matrix Protocol homeserver focused on secure
implementation, runtime hardening, and auditable dependency boundaries.

%prep
%autosetup

%build
%meson \
    --wrap-mode=forcefallback \
    -Dhardening=true \
    -Dbuild_tests=false \
    -Dbuild_fuzz=false \
    -Dcpp_link_args='-pie' \
    -Dc_link_args='-pie'
%meson_build

%install
%meson_install --skip-subprojects
install -D -m 0644 packaging/systemd/merovingian.service \
    %{buildroot}%{_unitdir}/merovingian.service
install -d -m 0755 %{buildroot}%{_sysconfdir}/merovingian
install -m 0644 config/merovingian.conf.example \
    %{buildroot}%{_sysconfdir}/merovingian/merovingian.conf.example

%pre
# Create merovingian group if it does not exist
if ! getent group merovingian >/dev/null 2>&1; then
    groupadd -r merovingian
fi
# Create merovingian user if it does not exist
if ! getent passwd merovingian >/dev/null 2>&1; then
    useradd -r -g merovingian -d /var/lib/merovingian \
            -s /sbin/nologin \
            -c "Merovingian homeserver" \
            merovingian
fi

%post
%systemd_post merovingian.service
install -d -o merovingian -g merovingian -m 0750 /var/lib/merovingian
install -d -o merovingian -g merovingian -m 0750 /var/log/merovingian
# Generate a registration token on first install. Never overwrite an existing token.
TOKEN_FILE=%{_sysconfdir}/merovingian/registration-token
if [ ! -f "${TOKEN_FILE}" ]; then
    openssl rand -base64 48 > "${TOKEN_FILE}"
    chmod 0640 "${TOKEN_FILE}"
    chown root:merovingian "${TOKEN_FILE}"
fi

%preun
%systemd_preun merovingian.service

%postun
%systemd_postun_with_restart merovingian.service

%files
%license LICENSE
%doc README.md docs/configuration.md docs/release-process.md
%{_bindir}/merovingian-server
%{_bindir}/merovingian-db-migrate
%{_unitdir}/merovingian.service
%dir %{_sysconfdir}/merovingian
%{_sysconfdir}/merovingian/merovingian.conf.example

%changelog
* Mon Jun 01 2026 James Chapman <claude@ping.me.uk> - 0.4.56-1
- Fix outbound federation transaction IDs for E2EE to-device delivery so restarts don't reuse IDs that remote servers deduplicate as replays.
- Fix federated profile query for local users missing a stored profile row; returns spec-shaped empty profile instead of "user not found".
- Fix inbound m.direct_to_device EDU parsing to use canonical JSON instead of raw brace searches, preserving nested encrypted payloads.
- Fix v1.18 fallback-key claim semantics so federation /user/keys/claim returns a matching fallback key after one-time keys are exhausted.

* Mon Jun 01 2026 James Chapman <claude@ping.me.uk> - 0.4.55-1
- Fix Matrix v1.18 fallback-key claim semantics so federation /user/keys/claim returns a matching fallback key after one-time keys are exhausted.
- Fix fallback-key lookup to filter by requested algorithm so mixed fallback uploads still satisfy client and federation /keys/claim requests.

* Mon Jun 01 2026 James Chapman <claude@ping.me.uk> - 0.4.54-1
- Fix Matrix v1.18 room-key backup metadata and update responses: add required count and etag fields, return RoomKeysUpdateResponse for room-key writes/deletes, and make single-session backup deletion actually remove the stored session.

* Sun May 31 2026 James Chapman <claude@ping.me.uk> - 0.4.53-1
- Fix room-key backup session lookup for percent-encoded Matrix path components so clients can retrieve Megolm backup sessions whose session IDs contain `/` immediately after batch upload.

* Sun May 31 2026 James Chapman <claude@ping.me.uk> - 0.4.52-1
- Fix data race in outbound HTTP client: a single shared libcurl easy handle was driven from multiple threads, causing spurious network_error on federation key queries and breaking E2EE (m.room_key.withheld). perform() now uses a per-thread handle.

* Sun May 31 2026 James Chapman <claude@ping.me.uk> - 0.4.51-1
- Fix m.receipt federation EDU format: add missing receipt-type nesting and wrap ts in data object (was causing Synapse 500 on every outbound transaction)

* Sun May 31 2026 James Chapman <claude@ping.me.uk> - 0.4.50-1
- Fix send_join response to return pre-join state snapshot (prevented Synapse auth_events circular reference warning)

* Sun May 31 2026 James Chapman <claude@ping.me.uk> - 0.4.49-1
- Fix make_join template including m.room.create in auth_events for room v12 (caused Synapse AssertionError on join)

* Sat May 30 2026 James Chapman <claude@ping.me.uk> - 0.4.48-1
- Fix send_join response missing members_omitted field (caused Synapse 500 on join)
- Fix make_join template depth=0 and prev_events including all room events instead of forward extremities

* Sat May 30 2026 James Chapman <claude@ping.me.uk> - 0.4.47-1
- Fix federated invite-join auth chain: populate make_join auth_events, copy auth_event_ids in send_join, store inbound invites in event graph

* Sat May 30 2026 James Chapman <claude@ping.me.uk> - 0.4.46-1
- Fix PDU dispatch to include invited users in room members
- Add receipt endpoint POST /rooms/{roomId}/receipt/{receiptType}/{eventId}
- Add user directory search endpoint POST /user_directory/search
- Add media thumbnail endpoints GET /_matrix/media/v3/thumbnail/ and v1
- Add key backup batch PUT endpoint PUT /room_keys/keys
- Filter runtime startup to only add join/invite memberships to room->members

* Sat May 30 2026 James Chapman <claude@ping.me.uk> - 0.4.45-1
- Fix auth_events to include only spec-required events per event type
- Deduplicate createRoom preset events when client provides initial_state

* Sat May 30 2026 James Chapman <claude@ping.me.uk> - 0.4.44-1
- Omit room creators from m.room.power_levels content.users in room v12 (MSC4289)
- Combine and deduplicate trusted_private_chat additional_creators per spec v1.16
- Key outbound federation EDUs by edu_type so Synapse accepts the transaction

* Sat May 30 2026 James Chapman <claude@ping.me.uk> - 0.4.43-1
- Support joining remote room version 12 rooms via server_name/via parameters (MSC4291)

* Sat May 30 2026 James Chapman <claude@ping.me.uk> - 0.4.42-1
- Fix send_join auth_chain to include only state events (walk auth_events graph)
- Document build.py as the recommended build entry point

* Fri May 29 2026 James Chapman <claude@ping.me.uk> - 0.4.41-1
- Add unified build.py script for Linux, BSD, and WSL builds, replacing build-wsl.ps1

* Fri May 29 2026 James Chapman <claude@ping.me.uk> - 0.4.40-1
- Accept v12 (MSC4291) room IDs in matrix_id_is_valid; the colon requirement
  rejected hash-based room IDs without a :server suffix, causing send_join
  to fail with 400 Bad Request

* Fri May 29 2026 James Chapman <claude@ping.me.uk> - 0.4.39-1
- Implement Matrix room version 12 (MSC4291 room IDs as create-event hashes,
  MSC4289 privileged room creators), fixing Synapse send_join BadSignatureError

* Fri May 29 2026 James Chapman <claude@ping.me.uk> - 0.4.38-1
- Emit m.room.encryption state event for private/trusted_private_chat presets
- Add federation event-signing diagnostic logging for BadSignatureError triage

* Fri May 29 2026 James Chapman <claude@ping.me.uk> - 0.4.36-1
- Fix /sync returning incomplete timeline events and missing state events

* Fri May 29 2026 James Chapman <claude@ping.me.uk> - 0.4.35-1
- Add ccache and build caching to GitHub Actions CI workflows

* Fri May 29 2026 James Chapman <claude@ping.me.uk> - 0.4.34-1
- Add GET /account/3pid and GET /pushers returning empty arrays for Element settings
- Fix GET /rooms/{roomId}/members returning empty chunk for locally-joined users
- Fix outbound federation invite BadSignatureError by pruning event before signing

* Fri May 29 2026 James Chapman <claude@ping.me.uk> - 0.4.33-1
- Add comprehensive Matrix v1.18 Client-Server API conformance test suite (221 scenarios)

* Thu May 28 2026 James Chapman <claude@ping.me.uk> - 0.4.32-1
- Fix DELETE /room_keys/version not removing backup, causing infinite Element retry loop

* Thu May 28 2026 James Chapman <claude@ping.me.uk> - 0.4.31-1
- Fix POST /room_keys/version returning empty body instead of {"version":"1"}

* Thu May 28 2026 James Chapman <claude@ping.me.uk> - 0.4.30-1
- Fix federation join state events invisible to incremental sync (stream_ordering == 0)
- Fix cross-signing key upload losing self_signing and user_signing keys

* Thu May 28 2026 James Chapman <claude@ping.me.uk> - 0.4.29-1
- Fix make_join validation rejecting templates that omit the origin field (removed in room version 4+)

* Thu May 28 2026 James Chapman <claude@ping.me.uk> - 0.4.28-1
- Fix federation /send returning HTTP 403 for whole transaction on single PDU sig failure
- Fix incremental /sync emitting stale room data on every long-poll timeout re-dispatch

* Thu May 28 2026 James Chapman <claude@ping.me.uk> - 0.4.27-1
- Fix off-by-one in /sync next_batch token causing infinite empty-sync loop

* Wed May 27 2026 James Chapman <claude@ping.me.uk> - 0.4.26-1
- Strip event_id from inbound PDU signing payload for room versions using reference-hash event IDs, fixing Synapse signature verification failure

* Wed May 27 2026 James Chapman <claude@ping.me.uk> - 0.4.25-1
- Compute and attach content hash (hashes.sha256) before signing the join event in the remote join path, fixing Synapse send_join rejection with "Malformed hashes"

* Wed May 27 2026 James Chapman <claude@ping.me.uk> - 0.4.24-1
- Bring createRoom in line with Matrix v1.18, including preset-derived state,
  room aliases, and correct outbound invite room versions
- Refine runtime locking around remote federation join I/O and serve key
  publication without serializing unrelated requests

* Wed May 27 2026 James Chapman <claude@ping.me.uk> - 0.4.23-1
- Move request serialization into the runtime and release the mutex before remote join discovery/make_join/send_join so unrelated requests no longer block behind federation I/O
- Advertise room versions 10, 11, and 12 in make_join; use the room_version from the response to select the correct signing policy
- Generate m.room.create, m.room.member, m.room.power_levels, and m.room.join_rules during create_room so send_join returns a valid auth chain (fixes Synapse "No create event in state" rejection)
- Derive room version policy for event composition from the stored m.room.create event instead of hardcoding version 12

* Wed May 27 2026 James Chapman <claude@ping.me.uk> - 0.4.22-1
- Serve /_matrix/key/v2/server lock-free from atomic cache to prevent Synapse ServerKeyFetcher timeout under concurrent make_join lock contention

* Wed May 27 2026 James Chapman <claude@ping.me.uk> - 0.4.21-1
- Populate old_verify_keys in /_matrix/key/v2/server with superseded signing keys

* Wed May 27 2026 James Chapman <claude@ping.me.uk> - 0.4.20-1
- Derive Ed25519 signing key_id from public key bytes to bypass stale notary caches (BadSignatureError fix)
- Ignore legacy ed25519:auto keys and generate fresh derived-format keypair on startup
- Set valid_until_ts to now+7d on new keys; use actual key_id in outbound X-Matrix headers

* Wed May 27 2026 James Chapman <claude@ping.me.uk> - 0.4.19-1
- Derive Ed25519 signing key_id from public key bytes (ed25519:<8 hex chars>) to bypass stale notary caches
- Ignore legacy ed25519:auto keys on startup and generate a fresh derived-format keypair instead
- Set valid_until_ts to now+7d on new keys so federation peers re-fetch periodically
- Use the actual stored key_id in every outbound X-Matrix header
- Add runtime diagnostic logging to federation signing pipeline to surface signing-key mismatches and payload build failures
- Log key lifecycle events (loaded vs generated) in ensure_runtime_server_signing_key for ops visibility

* Tue May 26 2026 James Chapman <claude@ping.me.uk> - 0.4.18-1
- Fail closed when outbound federation membership signing is not initialized
- Reject unusable persisted signing secrets when starting federation dispatch
- Preserve the exact encoded federation request target on the wire for signature-sensitive requests
- Add the client-server publicRooms directory route so Matrix clients stop failing with M_UNRECOGNIZED after login
- Split the old vertical_slice homeserver umbrella header into implementation-matched interfaces

* Wed May 27 2026 James Chapman <claude@ping.me.uk> - 0.4.17-1
- Store Ed25519 signing key secret as base64 to prevent null-byte truncation on SQLite/PostgreSQL reload

* Wed May 27 2026 James Chapman <claude@ping.me.uk> - 0.4.16-1
- Persist server Ed25519 signing key secret across restarts so outbound federation requests use a stable identity

* Tue May 26 2026 James Chapman <claude@ping.me.uk> - 0.4.14-1
- Percent-encode outbound federation membership path components before signing

* Tue May 26 2026 James Chapman <claude@ping.me.uk> - 0.4.13-1
- Persist inbound federation invite stripped state and surface it in /sync so remote DMs from Synapse render correctly in Matrix clients

* Tue May 26 2026 James Chapman <claude@ping.me.uk> - 0.4.12-1
- Bump project and packaging metadata to 0.4.12 for a fresh main latest build

* Tue May 26 2026 James Chapman <claude@ping.me.uk> - 0.4.11-1
- Log the merovingian-server version during startup

* Tue May 26 2026 James Chapman <claude@ping.me.uk> - 0.4.10-1
- Persist inbound federation join membership for remote event delivery
- Sign and persist inbound federation invites for client sync
- Send outbound federation invites for remote createRoom invitees

* Mon May 25 2026 James Chapman <claude@ping.me.uk> - 0.4.9-1
- Add live Synapse federation integration tests against matrix.ping.me.uk

* Mon May 25 2026 James Chapman <claude@ping.me.uk> - 0.4.8-1
- Fix runtime_lock held during /sync long-poll blocking federation dispatch

* Mon May 25 2026 James Chapman <claude@ping.me.uk> - 0.4.6-1
- Fix federation transaction response to return spec-required JSON {"pdus":{}}

* Mon May 25 2026 James Chapman <claude@ping.me.uk> - 0.4.5-1
- Add v1.18 conformance fixtures for client-server and federation
- Fix DispatchWorker overwrite and empty transaction_id bugs

* Sun May 24 2026 James Chapman <claude@ping.me.uk> - 0.4.4-1
- Wire inbound EDU sink for all five EDU types (typing, receipt, presence, to-device, device_list_update)
- Wire outbound membership into join_room for remote rooms (make_join → sign → send_join)
- Wire device list update route and record_device_list_change
- Add outbound EDU dispatch for typing notifications and read receipts
- Add PUT /presence/{userId}/status route

* Sun May 24 2026 James Chapman <claude@ping.me.uk> - 0.4.3-1
- Fix inbound PDU sync visibility (stream_ordering and sync notification for federation events)
- Wire outbound PDU dispatch from local events to remote servers via DispatchWorker

* Sun May 24 2026 James Chapman <claude@ping.me.uk> - 0.4.2-1
- Fix federation invite path parsing (v1/v2 invite routes no longer emit spurious membership_path.rejected)
- Add im.nheko.summary room summary endpoints for Nheko compatibility

* Sat May 23 2026 James Chapman <claude@ping.me.uk> - 0.4.1-1
- Fix room join returning 500 when user is already a member in the persistent store but absent from the in-memory member list

* Sat May 23 2026 James Chapman <claude@ping.me.uk> - 0.4.0-1
- Add POST /rooms/{roomId}/leave and /read_markers client-server routes
- Add structured debug logging to federation, media, platform, and HTTP modules
- Fix platform library linkage in merovingian-db-migrate

* Fri May 22 2026 James Chapman <claude@ping.me.uk> - 0.3.6-1
- Add client-server room messages and typing routes

* Fri May 22 2026 James Chapman <claude@ping.me.uk> - 0.3.5-1
- Add inbound federation event-graph routes: event/{eventId}, state/{roomId}, state_ids/{roomId}, and get_missing_events/{roomId}

* Fri May 22 2026 James Chapman <claude@ping.me.uk> - 0.3.4-1
- Add inbound federation query/profile route
- Add inbound federation E2EE key routes: user/keys/query, user/keys/claim, and user/devices

* Fri May 22 2026 James Chapman <claude@ping.me.uk> - 0.3.3-1
- Complete federation joins/leaves/invites/backfill/PDU delivery/event ingestion
- Add real X-Matrix header parsing and TLS-bound origin validation
- Wire remote key rotation with live Ed25519 fetch and cache
- Wire all FederationRuntimeState callbacks into the production runtime
- Extend PostgreSQL restart-survival tests to cover all persisted data types

* Thu May 21 2026 James Chapman <claude@ping.me.uk> - 0.3.2-1
- HTML character encoding fix

* Thu May 21 2026 James Chapman <claude@ping.me.uk> - 0.3.1-1
- Add redaction-aware debug diagnostics across HTTP dispatch, client-server auth, joins, room events, persistence, and federation membership flows

* Thu May 21 2026 James Chapman <claude@ping.me.uk> - 0.3.0-1
- Add Matrix UI-auth challenge for POST /register (returns 401 with flows/session when auth field absent)
- Add POST /account/password endpoint for authenticated password change
- Add PUT /profile/{userId}/displayname and avatar_url endpoints
- Move GET /profile/{userId} before the auth gate (unauthenticated per Matrix spec)
- Fix GET /profile/{userId}/{keyName} to return only the requested field (404 for unset/unknown fields)
- Extend client-server v1.18 conformance fixture with profile negative cases, unknown-room state, and password-change coverage

* Thu May 21 2026 James Chapman <claude@ping.me.uk> - 0.2.17-1
- Add durable media blob persistence, policy-rule hydration, and hardened media processing boundaries
- Add remote media ingest boundary, thumbnail metadata, and media repository restart coverage

* Thu May 21 2026 James Chapman <claude@ping.me.uk> - 0.2.16-1
- Promote beta client-server v1.18 endpoint coverage with auth/device runtime behavior and conformance fixtures
- Add refresh-token rotation, global logout, single-device fetch/delete, spec-shaped room send/state aliases, and media adapter coverage

* Thu May 21 2026 James Chapman <claude@ping.me.uk> - 0.2.15-1
- Return 404 for the whole org.matrix.msc2965 OIDC discovery namespace
- Add GET /voip/turnServer stub returning an empty object
- Add POST /join/{roomIdOrAlias} join-by-id endpoint
- Add PUT/GET /user/{userId}/account_data/{type} for global account data

* Thu May 21 2026 James Chapman <claude@ping.me.uk> - 0.2.14-1
- Raise the client API body limit to 64 KiB so E2EE key uploads are not rejected with 413
- Add GET /profile/{userId} and GET /_matrix/media/v3/config stubs
- Return 404 for the org.matrix.msc2965 OIDC auth_metadata probe

* Thu May 21 2026 James Chapman <claude@ping.me.uk> - 0.2.13-1
- Fix the Windows-to-WSL build launch chain to use scripts/build-wsl.sh
- Re-extract stale curl packagefiles and normalize the staged WSL make shim

* Wed May 20 2026 James Chapman <claude@ping.me.uk> - 0.2.12-1
- Add POST /user/{userId}/filter and GET /user/{userId}/filter/{filterId} so Cinny can store and retrieve sync filters

* Wed May 20 2026 James Chapman <claude@ping.me.uk> - 0.2.11-1
- Add GET /capabilities and GET /pushrules/ stubs so Cinny and Element can complete post-login initialisation

* Wed May 20 2026 James Chapman <claude@ping.me.uk> - 0.2.10-1
- Add OPTIONS preflight handler and /.well-known/matrix/client endpoint

* Wed May 20 2026 James Chapman <claude@ping.me.uk> - 0.2.9-1
- Fix login returning HTTP 400 instead of 403 for unknown user and bad credentials

* Wed May 20 2026 James Chapman <claude@ping.me.uk> - 0.2.8-1
- Fix malformed INSERT SQL in login and register boundary plans

* Wed May 20 2026 James Chapman <claude@ping.me.uk> - 0.2.7-1
- Bump version to 0.2.7

* Wed May 20 2026 James Chapman <claude@ping.me.uk> - 0.2.6-1
- Generate /etc/merovingian/registration-token on first install
- Default config search path baked in via MEROVINGIAN_SYSCONFDIR at build time

* Wed May 20 2026 James Chapman <james@merovingian-homeserver.example> - 0.2.5-1
- Move the default internal federation listener away from public port 8448

* Wed May 20 2026 James Chapman <james@merovingian-homeserver.example> - 0.2.4-1
- Add explanatory comments to the example configuration

* Wed May 20 2026 James Chapman <james@merovingian-homeserver.example> - 0.2.3-1
- Add static Linux fallback tarball to rolling package publication
- Fix rolling latest release replacement

* Wed May 20 2026 James Chapman <james@merovingian-homeserver.example> - 0.2.2-1
- Switch .deb build to Ubuntu with dynamic security library linking
- Declare libssl3, libsodium23, libpq5 as runtime deps in .deb package

* Tue May 19 2026 James Chapman <james@merovingian-homeserver.example> - 0.2.1-1
- Add distro packaging: .deb, .rpm, FreeBSD .pkg via CI
- Statically link application deps; remove shared-lib Requires
- Restore -fPIE and -Wl,-z,noexecstack; PIE supplied per-platform via cpp_link_args
