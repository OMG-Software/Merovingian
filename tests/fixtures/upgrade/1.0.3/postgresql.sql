--
-- PostgreSQL database dump
--


-- Dumped from database version 16.15 (Ubuntu 16.15-0ubuntu0.24.04.1)
-- Dumped by pg_dump version 16.15 (Ubuntu 16.15-0ubuntu0.24.04.1)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: access_tokens; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.access_tokens (
    user_id text NOT NULL,
    device_id text NOT NULL,
    token_hash text NOT NULL,
    revoked text NOT NULL,
    expires_at text DEFAULT ''::text NOT NULL,
    predecessor_refresh_hash text DEFAULT ''::text NOT NULL
);


--
-- Name: account_data; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.account_data (
    user_id text NOT NULL,
    event_type text NOT NULL,
    json text NOT NULL,
    stream_id text DEFAULT '0'::text NOT NULL
);


--
-- Name: account_threepids; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.account_threepids (
    user_id text NOT NULL,
    medium text NOT NULL,
    address text NOT NULL,
    country text DEFAULT ''::text NOT NULL,
    id_server text DEFAULT ''::text NOT NULL,
    added_at_ms text DEFAULT '0'::text NOT NULL,
    validated_at_ms text DEFAULT '0'::text NOT NULL,
    bound text DEFAULT '0'::text NOT NULL,
    client_secret text DEFAULT ''::text NOT NULL,
    sid text DEFAULT ''::text NOT NULL
);


--
-- Name: admin_actions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.admin_actions (
    admin_user_id text NOT NULL,
    action text NOT NULL,
    target text NOT NULL
);


--
-- Name: appservice_directory; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.appservice_directory (
    appservice_id text NOT NULL,
    network_id text NOT NULL,
    room_id text NOT NULL
);


--
-- Name: appservice_outbox; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.appservice_outbox (
    appservice_id text NOT NULL,
    stream_ordering text NOT NULL,
    event_id text NOT NULL
);


--
-- Name: appservice_txn_cursor; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.appservice_txn_cursor (
    appservice_id text NOT NULL,
    next_txn_id text DEFAULT '1'::text NOT NULL,
    delivered_stream_ordering text DEFAULT '0'::text NOT NULL,
    pending_txn_id text DEFAULT '0'::text NOT NULL,
    pending_stream_ordering text DEFAULT '0'::text NOT NULL
);


--
-- Name: audit_log; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.audit_log (
    category text NOT NULL,
    event_type text NOT NULL,
    actor text NOT NULL,
    target text NOT NULL,
    reason text NOT NULL,
    created_at_ms text DEFAULT '0'::text NOT NULL
);


--
-- Name: client_txn_ids; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.client_txn_ids (
    user_id text NOT NULL,
    room_id text NOT NULL,
    event_type text NOT NULL,
    txn_id text NOT NULL,
    event_id text NOT NULL,
    device_id text DEFAULT ''::text NOT NULL,
    created_at_ms text DEFAULT '0'::text NOT NULL
);


--
-- Name: cross_signing_keys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.cross_signing_keys (
    user_id text NOT NULL,
    key_type text NOT NULL,
    json text NOT NULL
);


--
-- Name: current_state; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.current_state (
    room_id text NOT NULL,
    event_type text NOT NULL,
    state_key text NOT NULL,
    event_id text NOT NULL
);


--
-- Name: deferred_pdus; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.deferred_pdus (
    event_id text NOT NULL,
    room_id text NOT NULL,
    origin text NOT NULL,
    pdu_json text NOT NULL,
    received_at_ms text DEFAULT '0'::text NOT NULL,
    attempts text DEFAULT '0'::text NOT NULL
);


--
-- Name: device_keys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.device_keys (
    user_id text NOT NULL,
    device_id text NOT NULL,
    json text NOT NULL
);


--
-- Name: device_list_changes; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.device_list_changes (
    stream_id text NOT NULL,
    observer_user_id text NOT NULL,
    subject_user_id text NOT NULL,
    change_type text DEFAULT 'changed'::text NOT NULL
);


--
-- Name: devices; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.devices (
    user_id text NOT NULL,
    device_id text NOT NULL,
    display_name text NOT NULL
);


--
-- Name: event_auth; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.event_auth (
    event_id text NOT NULL,
    auth_event_id text NOT NULL
);


--
-- Name: event_edges; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.event_edges (
    event_id text NOT NULL,
    prev_event_id text NOT NULL
);


--
-- Name: event_json; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.event_json (
    event_id text NOT NULL,
    json text NOT NULL
);


--
-- Name: event_signatures; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.event_signatures (
    event_id text NOT NULL,
    server_name text NOT NULL,
    key_id text NOT NULL,
    signature text NOT NULL
);


--
-- Name: event_state_groups; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.event_state_groups (
    event_id text NOT NULL,
    state_group_id text NOT NULL
);


--
-- Name: event_stream_watermark; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.event_stream_watermark (
    singleton integer NOT NULL,
    watermark text DEFAULT '0'::text NOT NULL,
    CONSTRAINT event_stream_watermark_singleton_check CHECK ((singleton = 1))
);


--
-- Name: events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.events (
    event_id text NOT NULL,
    room_id text NOT NULL,
    sender_user_id text NOT NULL,
    json text NOT NULL,
    depth text NOT NULL,
    stream_ordering text DEFAULT '0'::text NOT NULL,
    status text DEFAULT 'accepted'::text NOT NULL
);


--
-- Name: fallback_keys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.fallback_keys (
    user_id text NOT NULL,
    device_id text NOT NULL,
    key_id text NOT NULL,
    json text NOT NULL
);


--
-- Name: federation_destinations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.federation_destinations (
    server_name text NOT NULL,
    state text NOT NULL,
    retry_after_ts text NOT NULL,
    last_success_ts text NOT NULL,
    consecutive_failures text NOT NULL
);


--
-- Name: federation_transactions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.federation_transactions (
    transaction_id text NOT NULL,
    server_name text NOT NULL,
    json text NOT NULL,
    method text NOT NULL,
    target text NOT NULL,
    origin text NOT NULL,
    origin_server_ts text NOT NULL,
    body text NOT NULL,
    retry_count text NOT NULL,
    next_retry_ts text NOT NULL
);


--
-- Name: filters; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.filters (
    user_id text NOT NULL,
    filter_id text NOT NULL,
    json text NOT NULL
);


--
-- Name: forward_extremities; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.forward_extremities (
    room_id text NOT NULL,
    event_id text NOT NULL
);


--
-- Name: invites; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.invites (
    room_id text NOT NULL,
    user_id text NOT NULL,
    sender_user_id text NOT NULL,
    event_id text DEFAULT ''::text NOT NULL,
    signed_event_json text DEFAULT ''::text NOT NULL,
    invite_state_json text DEFAULT '[]'::text NOT NULL,
    stream_ordering text DEFAULT '0'::text NOT NULL,
    resident_server text DEFAULT ''::text NOT NULL
);


--
-- Name: key_backup_sessions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.key_backup_sessions (
    user_id text NOT NULL,
    version text NOT NULL,
    room_id text NOT NULL,
    session_id text NOT NULL,
    json text NOT NULL
);


--
-- Name: key_backup_version_counters; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.key_backup_version_counters (
    user_id text NOT NULL,
    last_version text NOT NULL
);


--
-- Name: key_backup_versions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.key_backup_versions (
    user_id text NOT NULL,
    version text NOT NULL,
    json text NOT NULL
);


--
-- Name: key_backups; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.key_backups (
    user_id text NOT NULL,
    version text NOT NULL,
    json text NOT NULL
);


--
-- Name: key_signatures; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.key_signatures (
    signer_user_id text NOT NULL,
    target_user_id text NOT NULL,
    target_device_id text NOT NULL,
    json text NOT NULL
);


--
-- Name: login_tokens; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.login_tokens (
    user_id text NOT NULL,
    token_hash text NOT NULL,
    expires_at text DEFAULT '0'::text NOT NULL,
    used text DEFAULT 'false'::text NOT NULL
);


--
-- Name: media; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.media (
    media_id text NOT NULL,
    owner_user_id text NOT NULL,
    content_type text NOT NULL,
    size_bytes text NOT NULL,
    hash_algorithm text NOT NULL,
    digest text NOT NULL,
    quarantined text NOT NULL,
    removed text NOT NULL,
    legacy_endpoint_visible text DEFAULT 'true'::text NOT NULL,
    upload_name text DEFAULT ''::text NOT NULL
);


--
-- Name: media_blobs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.media_blobs (
    storage_id text NOT NULL,
    hash_algorithm text NOT NULL,
    digest text NOT NULL,
    size_bytes text NOT NULL,
    bytes bytea NOT NULL,
    ref_count text NOT NULL
);


--
-- Name: media_pending_uploads; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.media_pending_uploads (
    media_id text NOT NULL,
    owner_user_id text NOT NULL,
    created_at_ms text NOT NULL,
    expires_at_ms text NOT NULL
);


--
-- Name: membership; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.membership (
    room_id text NOT NULL,
    user_id text NOT NULL,
    membership text DEFAULT 'join'::text NOT NULL,
    stream_ordering text DEFAULT '0'::text NOT NULL
);


--
-- Name: notifications; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.notifications (
    user_id text NOT NULL,
    room_id text NOT NULL,
    event_id text NOT NULL,
    stream_ordering text DEFAULT '0'::text NOT NULL,
    ts text DEFAULT '0'::text NOT NULL,
    actions text DEFAULT '[]'::text NOT NULL,
    profile_tag text DEFAULT ''::text NOT NULL,
    highlight text DEFAULT 'false'::text NOT NULL
);


--
-- Name: one_time_keys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.one_time_keys (
    user_id text NOT NULL,
    device_id text NOT NULL,
    key_id text NOT NULL,
    json text NOT NULL
);


--
-- Name: openid_tokens; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.openid_tokens (
    user_id text NOT NULL,
    token_hash text NOT NULL,
    expires_at text DEFAULT '0'::text NOT NULL
);


--
-- Name: policy_rules; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.policy_rules (
    rule_id text NOT NULL,
    scope text NOT NULL,
    entity text NOT NULL,
    action text NOT NULL,
    reason text NOT NULL
);


--
-- Name: presence_state; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.presence_state (
    user_id text NOT NULL,
    stream_id text DEFAULT '0'::text NOT NULL,
    presence text DEFAULT 'offline'::text NOT NULL,
    status_msg text DEFAULT ''::text NOT NULL,
    last_active_ago text DEFAULT '0'::text NOT NULL,
    currently_active text DEFAULT 'false'::text NOT NULL
);


--
-- Name: profiles; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.profiles (
    user_id text NOT NULL,
    displayname text DEFAULT ''::text NOT NULL,
    avatar_url text DEFAULT ''::text NOT NULL,
    fields_json text DEFAULT '{}'::text NOT NULL
);


--
-- Name: push_rules; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.push_rules (
    user_id text NOT NULL,
    rule_id text NOT NULL,
    json text NOT NULL
);


--
-- Name: pushers; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.pushers (
    user_id text NOT NULL,
    app_id text NOT NULL,
    pushkey text NOT NULL,
    kind text NOT NULL,
    app_display_name text DEFAULT ''::text NOT NULL,
    device_display_name text DEFAULT ''::text NOT NULL,
    profile_tag text DEFAULT ''::text NOT NULL,
    lang text DEFAULT ''::text NOT NULL,
    data_url text DEFAULT ''::text NOT NULL,
    data_format text DEFAULT ''::text NOT NULL,
    data_extra_json text DEFAULT ''::text NOT NULL,
    device_id text DEFAULT ''::text NOT NULL
);


--
-- Name: rate_limits; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.rate_limits (
    scope text NOT NULL,
    key text NOT NULL,
    count text NOT NULL,
    reset_ts text NOT NULL
);


--
-- Name: receipts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.receipts (
    room_id text NOT NULL,
    receipt_type text NOT NULL,
    user_id text NOT NULL,
    thread_id text DEFAULT ''::text NOT NULL,
    event_id text NOT NULL,
    ts text DEFAULT '0'::text NOT NULL,
    stream_id text DEFAULT '0'::text NOT NULL
);


--
-- Name: refresh_tokens; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.refresh_tokens (
    token_hash text NOT NULL,
    user_id text NOT NULL,
    device_id text NOT NULL,
    revoked text NOT NULL,
    expires_at text DEFAULT ''::text NOT NULL,
    predecessor_hash text DEFAULT ''::text NOT NULL,
    issued_at_ms text DEFAULT '0'::text NOT NULL
);


--
-- Name: remote_media; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.remote_media (
    server_name text NOT NULL,
    media_id text NOT NULL,
    content_type text NOT NULL,
    size_bytes text NOT NULL,
    quarantined text NOT NULL,
    local_media_id text DEFAULT ''::text NOT NULL,
    fetched_at_ms text DEFAULT '0'::text NOT NULL
);


--
-- Name: room_account_data; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.room_account_data (
    user_id text NOT NULL,
    room_id text NOT NULL,
    event_type text NOT NULL,
    stream_id text DEFAULT '0'::text NOT NULL,
    json text NOT NULL
);


--
-- Name: room_aliases; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.room_aliases (
    room_alias text NOT NULL,
    room_id text NOT NULL,
    creator_user_id text DEFAULT ''::text NOT NULL
);


--
-- Name: room_versions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.room_versions (
    room_id text NOT NULL,
    version text NOT NULL
);


--
-- Name: rooms; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.rooms (
    room_id text NOT NULL,
    creator_user_id text NOT NULL,
    directory_public text DEFAULT 'false'::text NOT NULL
);


--
-- Name: schema_migrations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.schema_migrations (
    version text NOT NULL,
    name text NOT NULL,
    direction text NOT NULL
);


--
-- Name: server_signing_keys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.server_signing_keys (
    server_name text NOT NULL,
    key_id text NOT NULL,
    public_key text NOT NULL,
    valid_until_ts text NOT NULL,
    secret_key bytea DEFAULT '\x'::bytea NOT NULL,
    expired_ts text DEFAULT ''::text NOT NULL
);


--
-- Name: state_group_edges; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.state_group_edges (
    state_group_id text NOT NULL,
    prev_state_group_id text NOT NULL
);


--
-- Name: state_group_state; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.state_group_state (
    state_group_id text NOT NULL,
    event_type text NOT NULL,
    state_key text NOT NULL,
    event_id text NOT NULL
);


--
-- Name: state_groups; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.state_groups (
    state_group_id text NOT NULL,
    room_id text NOT NULL,
    parent_state_group_id text DEFAULT ''::text NOT NULL,
    delta_depth text DEFAULT '0'::text NOT NULL
);


--
-- Name: state_transitions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.state_transitions (
    room_id text NOT NULL,
    event_type text NOT NULL,
    state_key text NOT NULL,
    event_id text NOT NULL,
    previous_event_id text DEFAULT ''::text NOT NULL
);


--
-- Name: stream_token_epoch; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.stream_token_epoch (
    singleton integer NOT NULL,
    epoch text NOT NULL,
    CONSTRAINT stream_token_epoch_singleton_check CHECK ((singleton = 1))
);


--
-- Name: sync_stream_watermark; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sync_stream_watermark (
    singleton integer NOT NULL,
    watermark text DEFAULT '0'::text NOT NULL,
    CONSTRAINT sync_stream_watermark_singleton_check CHECK ((singleton = 1))
);


--
-- Name: to_device_messages; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.to_device_messages (
    stream_id text NOT NULL,
    sender_user_id text NOT NULL,
    target_user_id text NOT NULL,
    target_device_id text DEFAULT ''::text NOT NULL,
    message_type text NOT NULL,
    content text NOT NULL,
    created_at_ms text DEFAULT '0'::text NOT NULL
);


--
-- Name: users; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.users (
    user_id text NOT NULL,
    password_hash text NOT NULL,
    locked text NOT NULL,
    suspended text NOT NULL,
    admin text NOT NULL,
    deactivated text DEFAULT 'false'::text NOT NULL
);


--
-- Data for Name: access_tokens; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.access_tokens (user_id, device_id, token_hash, revoked, expires_at, predecessor_refresh_hash) VALUES ('@alice:example.org', 'UPGRADE1', 'token-hash:v4:533f4f909b4e855e4cfd0a9b2a4bb74a178e19cc8751485a59999226f2638960', 'false', '', '');
INSERT INTO public.access_tokens (user_id, device_id, token_hash, revoked, expires_at, predecessor_refresh_hash) VALUES ('@bob:example.org', 'UPGRADE2', 'token-hash:v4:37e940791d2f4eeda9c794035450d3807f7384ca47bed4dd1c580e1f53204c19', 'false', '', '');


--
-- Data for Name: account_data; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.account_data (user_id, event_type, json, stream_id) VALUES ('@alice:example.org', 'org.merovingian.upgrade', '{"fixture": "0.11.13"}', '9');


--
-- Data for Name: account_threepids; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: admin_actions; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: appservice_directory; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: appservice_outbox; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: appservice_txn_cursor; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: audit_log; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.audit_log (category, event_type, actor, target, reason, created_at_ms) VALUES ('admin', 'runtime.started', 'server', 'homeserver', 'startup', '1794844862997');
INSERT INTO public.audit_log (category, event_type, actor, target, reason, created_at_ms) VALUES ('auth', 'auth.user_registered', '@alice:example.org', '@alice:example.org', 'created', '1794844863317');
INSERT INTO public.audit_log (category, event_type, actor, target, reason, created_at_ms) VALUES ('auth', 'auth.login', '@alice:example.org', 'UPGRADE1', 'accepted', '1794844863350');
INSERT INTO public.audit_log (category, event_type, actor, target, reason, created_at_ms) VALUES ('auth', 'auth.user_registered', '@bob:example.org', '@bob:example.org', 'created', '1794844863412');
INSERT INTO public.audit_log (category, event_type, actor, target, reason, created_at_ms) VALUES ('auth', 'auth.login', '@bob:example.org', 'UPGRADE2', 'accepted', '1794844863444');
INSERT INTO public.audit_log (category, event_type, actor, target, reason, created_at_ms) VALUES ('admin', 'room.created', '@alice:example.org', '!C7Cym0uRg_x2vckbuDPCwO4QgdsxfXpDiOi1WoH89NY', 'created', '1794844863468');
INSERT INTO public.audit_log (category, event_type, actor, target, reason, created_at_ms) VALUES ('admin', 'room.invited', '@alice:example.org', '@bob:example.org', '!C7Cym0uRg_x2vckbuDPCwO4QgdsxfXpDiOi1WoH89NY', '1794844863474');
INSERT INTO public.audit_log (category, event_type, actor, target, reason, created_at_ms) VALUES ('admin', 'room.joined', '@bob:example.org', '!C7Cym0uRg_x2vckbuDPCwO4QgdsxfXpDiOi1WoH89NY', 'joined', '1794844863479');
INSERT INTO public.audit_log (category, event_type, actor, target, reason, created_at_ms) VALUES ('admin', 'room.event_sent', '@alice:example.org', '!C7Cym0uRg_x2vckbuDPCwO4QgdsxfXpDiOi1WoH89NY', 'stored', '1794844863482');
INSERT INTO public.audit_log (category, event_type, actor, target, reason, created_at_ms) VALUES ('admin', 'room.event_sent', '@alice:example.org', '!C7Cym0uRg_x2vckbuDPCwO4QgdsxfXpDiOi1WoH89NY', 'stored', '1794844863486');
INSERT INTO public.audit_log (category, event_type, actor, target, reason, created_at_ms) VALUES ('admin', 'room.event_sent', '@alice:example.org', '!C7Cym0uRg_x2vckbuDPCwO4QgdsxfXpDiOi1WoH89NY', 'stored', '1794844863489');
INSERT INTO public.audit_log (category, event_type, actor, target, reason, created_at_ms) VALUES ('admin', 'room.event_sent', '@bob:example.org', '!C7Cym0uRg_x2vckbuDPCwO4QgdsxfXpDiOi1WoH89NY', 'stored', '1794844863493');
INSERT INTO public.audit_log (category, event_type, actor, target, reason, created_at_ms) VALUES ('admin', 'room.created', '@alice:example.org', '!WLDmyNQlQnw_RhR08m7Jk_JO2mbtD9pY5COByGjLODA', 'created', '1794844863514');
INSERT INTO public.audit_log (category, event_type, actor, target, reason, created_at_ms) VALUES ('moderation', 'media.upload_accepted', '@alice:example.org', 'eu-rBrEY7MSJKUy6o7pmMw', 'stored', '1794844863517');
INSERT INTO public.audit_log (category, event_type, actor, target, reason, created_at_ms) VALUES ('auth', 'key_api.upload_keys', '@alice:example.org', 'UPGRADE1', '[key-payload:redacted:length=697]', '1794844863523');


--
-- Data for Name: client_txn_ids; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.client_txn_ids (user_id, room_id, event_type, txn_id, event_id, device_id, created_at_ms) VALUES ('@alice:example.org', '!C7Cym0uRg_x2vckbuDPCwO4QgdsxfXpDiOi1WoH89NY', 'm.room.message', 'upgrade-txn-1', '$gbIXT6cBYsLvEAdCmvz_-Z-MLge4BnaLY_O1-PtdjGo', 'UPGRADE1', '1794844863483');
INSERT INTO public.client_txn_ids (user_id, room_id, event_type, txn_id, event_id, device_id, created_at_ms) VALUES ('@alice:example.org', '!C7Cym0uRg_x2vckbuDPCwO4QgdsxfXpDiOi1WoH89NY', 'm.room.message', 'upgrade-txn-2', '$mC5T62vlKtDEaC4l1ujmOJ3dA5q-PM-ku8SS1xRZCek', 'UPGRADE1', '1794844863487');
INSERT INTO public.client_txn_ids (user_id, room_id, event_type, txn_id, event_id, device_id, created_at_ms) VALUES ('@alice:example.org', '!C7Cym0uRg_x2vckbuDPCwO4QgdsxfXpDiOi1WoH89NY', 'm.room.message', 'upgrade-txn-3', '$h7M6qztmLUOCjFAmWrrrh-vd87KuCykZl7jvFLSK3Ds', 'UPGRADE1', '1794844863490');
INSERT INTO public.client_txn_ids (user_id, room_id, event_type, txn_id, event_id, device_id, created_at_ms) VALUES ('@bob:example.org', '!C7Cym0uRg_x2vckbuDPCwO4QgdsxfXpDiOi1WoH89NY', 'm.room.message', 'upgrade-txn-4', '$GcOCV1AahAZenbnTVGpvMmYTyB2XNFzhRLwjkRT0Cy8', 'UPGRADE2', '1794844863494');


--
-- Data for Name: cross_signing_keys; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: current_state; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.current_state (room_id, event_type, state_key, event_id) VALUES ('!C7Cym0uRg_x2vckbuDPCwO4QgdsxfXpDiOi1WoH89NY', 'm.room.create', '', '$C7Cym0uRg_x2vckbuDPCwO4QgdsxfXpDiOi1WoH89NY');
INSERT INTO public.current_state (room_id, event_type, state_key, event_id) VALUES ('!C7Cym0uRg_x2vckbuDPCwO4QgdsxfXpDiOi1WoH89NY', 'm.room.member', '@alice:example.org', '$iLFuDk8nVttbD9AqXn1viyXUEFEl_2DI7hsgkXGjXN8');
INSERT INTO public.current_state (room_id, event_type, state_key, event_id) VALUES ('!C7Cym0uRg_x2vckbuDPCwO4QgdsxfXpDiOi1WoH89NY', 'm.room.power_levels', '', '$i5rP6Kab--xLmDcMSPRUZxvyQZcPThTiofJjfrSnDtg');
INSERT INTO public.current_state (room_id, event_type, state_key, event_id) VALUES ('!C7Cym0uRg_x2vckbuDPCwO4QgdsxfXpDiOi1WoH89NY', 'm.room.join_rules', '', '$v4aPwfsZiQ4yEz5-T0kS_DWvVTqUxPRltYSFV4P8Jlk');
INSERT INTO public.current_state (room_id, event_type, state_key, event_id) VALUES ('!C7Cym0uRg_x2vckbuDPCwO4QgdsxfXpDiOi1WoH89NY', 'm.room.history_visibility', '', '$jQRkJoCECH7wDkXeK4PAzuiNM5N4-W-klgkSyuKI0Ig');
INSERT INTO public.current_state (room_id, event_type, state_key, event_id) VALUES ('!C7Cym0uRg_x2vckbuDPCwO4QgdsxfXpDiOi1WoH89NY', 'm.room.guest_access', '', '$3DxD43IUhKnopg81UbujM_TWm14GdVq22XKXiThD5Bo');
INSERT INTO public.current_state (room_id, event_type, state_key, event_id) VALUES ('!C7Cym0uRg_x2vckbuDPCwO4QgdsxfXpDiOi1WoH89NY', 'm.room.encryption', '', '$LQujV90cKOa8fkPPU4PQX7sm6KL28V0r8nKCewBnOJ8');
INSERT INTO public.current_state (room_id, event_type, state_key, event_id) VALUES ('!C7Cym0uRg_x2vckbuDPCwO4QgdsxfXpDiOi1WoH89NY', 'm.room.name', '', '$RDqWCB4mWm4fTct25NtZAh5zmiUTG_EsgfQpCS2erxw');
INSERT INTO public.current_state (room_id, event_type, state_key, event_id) VALUES ('!C7Cym0uRg_x2vckbuDPCwO4QgdsxfXpDiOi1WoH89NY', 'm.room.member', '@bob:example.org', '$wVJJm-TLQ6il0h68B5rzA97t20lkmGMK7H0O6YdHEMM');
INSERT INTO public.current_state (room_id, event_type, state_key, event_id) VALUES ('!WLDmyNQlQnw_RhR08m7Jk_JO2mbtD9pY5COByGjLODA', 'm.room.create', '', '$WLDmyNQlQnw_RhR08m7Jk_JO2mbtD9pY5COByGjLODA');
INSERT INTO public.current_state (room_id, event_type, state_key, event_id) VALUES ('!WLDmyNQlQnw_RhR08m7Jk_JO2mbtD9pY5COByGjLODA', 'm.room.member', '@alice:example.org', '$gEZRQzCXH4iD07nDrZYaWlyfDmS0tqK_R-gW6JyF32U');
INSERT INTO public.current_state (room_id, event_type, state_key, event_id) VALUES ('!WLDmyNQlQnw_RhR08m7Jk_JO2mbtD9pY5COByGjLODA', 'm.room.power_levels', '', '$PecG6aWhB2mDCM6YMk8crHbTdYzWkYUCN_ipzlMCjiI');
INSERT INTO public.current_state (room_id, event_type, state_key, event_id) VALUES ('!WLDmyNQlQnw_RhR08m7Jk_JO2mbtD9pY5COByGjLODA', 'm.room.canonical_alias', '', '$2oC-K1LNKA47eO1pqEmJrY0s6617pjOSdk68k5LiuZg');
INSERT INTO public.current_state (room_id, event_type, state_key, event_id) VALUES ('!WLDmyNQlQnw_RhR08m7Jk_JO2mbtD9pY5COByGjLODA', 'm.room.join_rules', '', '$V6yysmqZ0o9qaJiimEfXi0Ku7kIFtR9hCAC7vGSowuY');
INSERT INTO public.current_state (room_id, event_type, state_key, event_id) VALUES ('!WLDmyNQlQnw_RhR08m7Jk_JO2mbtD9pY5COByGjLODA', 'm.room.history_visibility', '', '$Lft2RjGrEuDUm8UkT3X25KYA1_81FeaFlJVeWLq8UdM');
INSERT INTO public.current_state (room_id, event_type, state_key, event_id) VALUES ('!WLDmyNQlQnw_RhR08m7Jk_JO2mbtD9pY5COByGjLODA', 'm.room.guest_access', '', '$MDEmZSZMMOOQUjEQxIXi05XzoHayhwFR6YRDMOykvoI');
INSERT INTO public.current_state (room_id, event_type, state_key, event_id) VALUES ('!WLDmyNQlQnw_RhR08m7Jk_JO2mbtD9pY5COByGjLODA', 'm.room.name', '', '$G6T266qKoHUbMYlVFKPN14wSCrqcj7ktb84OYLky32M');


--
-- Data for Name: deferred_pdus; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: device_keys; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.device_keys (user_id, device_id, json) VALUES ('@alice:example.org', 'UPGRADE1', '{"algorithms":["m.olm.v1.curve25519-aes-sha2","m.megolm.v1.aes-sha2"],"device_id":"UPGRADE1","keys":{"curve25519:UPGRADE1":"aJoAYROXT9rrYFhiSAmFkQk8DgPUrZKIq59YFaOAgQg","ed25519:UPGRADE1":"xZ6DW0uuhQKl7HY7m4J5dMmK6CWpCCrtYwps1QBYoyE"},"signatures":{"@alice:example.org":{"ed25519:UPGRADE1":"khdpySd56eC7863q/p2A8IOUUe2TQ28I4eBVO45kevqFspi6gW12BDvcz2qiB9GpsnS2zCNOxcde/LyLPA7RCw"}},"unsigned":{"device_display_name":"Upgrade fixture UPGRADE1"},"user_id":"@alice:example.org"}');


--
-- Data for Name: device_list_changes; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.device_list_changes (stream_id, observer_user_id, subject_user_id, change_type) VALUES ('2', '@bob:example.org', '@bob:example.org', 'changed');
INSERT INTO public.device_list_changes (stream_id, observer_user_id, subject_user_id, change_type) VALUES ('6', '@alice:example.org', '@bob:example.org', 'changed');
INSERT INTO public.device_list_changes (stream_id, observer_user_id, subject_user_id, change_type) VALUES ('10', '@alice:example.org', '@alice:example.org', 'changed');
INSERT INTO public.device_list_changes (stream_id, observer_user_id, subject_user_id, change_type) VALUES ('10', '@bob:example.org', '@alice:example.org', 'changed');


--
-- Data for Name: devices; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.devices (user_id, device_id, display_name) VALUES ('@alice:example.org', 'UPGRADE1', 'Upgrade fixture UPGRADE1');
INSERT INTO public.devices (user_id, device_id, display_name) VALUES ('@bob:example.org', 'UPGRADE2', 'Upgrade fixture UPGRADE2');


--
-- Data for Name: event_auth; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.event_auth (event_id, auth_event_id) VALUES ('$i5rP6Kab--xLmDcMSPRUZxvyQZcPThTiofJjfrSnDtg', '$iLFuDk8nVttbD9AqXn1viyXUEFEl_2DI7hsgkXGjXN8');
INSERT INTO public.event_auth (event_id, auth_event_id) VALUES ('$v4aPwfsZiQ4yEz5-T0kS_DWvVTqUxPRltYSFV4P8Jlk', '$iLFuDk8nVttbD9AqXn1viyXUEFEl_2DI7hsgkXGjXN8');
INSERT INTO public.event_auth (event_id, auth_event_id) VALUES ('$v4aPwfsZiQ4yEz5-T0kS_DWvVTqUxPRltYSFV4P8Jlk', '$i5rP6Kab--xLmDcMSPRUZxvyQZcPThTiofJjfrSnDtg');
INSERT INTO public.event_auth (event_id, auth_event_id) VALUES ('$jQRkJoCECH7wDkXeK4PAzuiNM5N4-W-klgkSyuKI0Ig', '$iLFuDk8nVttbD9AqXn1viyXUEFEl_2DI7hsgkXGjXN8');
INSERT INTO public.event_auth (event_id, auth_event_id) VALUES ('$jQRkJoCECH7wDkXeK4PAzuiNM5N4-W-klgkSyuKI0Ig', '$i5rP6Kab--xLmDcMSPRUZxvyQZcPThTiofJjfrSnDtg');
INSERT INTO public.event_auth (event_id, auth_event_id) VALUES ('$3DxD43IUhKnopg81UbujM_TWm14GdVq22XKXiThD5Bo', '$iLFuDk8nVttbD9AqXn1viyXUEFEl_2DI7hsgkXGjXN8');
INSERT INTO public.event_auth (event_id, auth_event_id) VALUES ('$3DxD43IUhKnopg81UbujM_TWm14GdVq22XKXiThD5Bo', '$i5rP6Kab--xLmDcMSPRUZxvyQZcPThTiofJjfrSnDtg');
INSERT INTO public.event_auth (event_id, auth_event_id) VALUES ('$LQujV90cKOa8fkPPU4PQX7sm6KL28V0r8nKCewBnOJ8', '$iLFuDk8nVttbD9AqXn1viyXUEFEl_2DI7hsgkXGjXN8');
INSERT INTO public.event_auth (event_id, auth_event_id) VALUES ('$LQujV90cKOa8fkPPU4PQX7sm6KL28V0r8nKCewBnOJ8', '$i5rP6Kab--xLmDcMSPRUZxvyQZcPThTiofJjfrSnDtg');
INSERT INTO public.event_auth (event_id, auth_event_id) VALUES ('$RDqWCB4mWm4fTct25NtZAh5zmiUTG_EsgfQpCS2erxw', '$iLFuDk8nVttbD9AqXn1viyXUEFEl_2DI7hsgkXGjXN8');
INSERT INTO public.event_auth (event_id, auth_event_id) VALUES ('$RDqWCB4mWm4fTct25NtZAh5zmiUTG_EsgfQpCS2erxw', '$i5rP6Kab--xLmDcMSPRUZxvyQZcPThTiofJjfrSnDtg');
INSERT INTO public.event_auth (event_id, auth_event_id) VALUES ('$QzTeY37FC1XCBCS9k5WSqtd_ozVW1B45OBvMLOxOFRY', '$iLFuDk8nVttbD9AqXn1viyXUEFEl_2DI7hsgkXGjXN8');
INSERT INTO public.event_auth (event_id, auth_event_id) VALUES ('$QzTeY37FC1XCBCS9k5WSqtd_ozVW1B45OBvMLOxOFRY', '$i5rP6Kab--xLmDcMSPRUZxvyQZcPThTiofJjfrSnDtg');
INSERT INTO public.event_auth (event_id, auth_event_id) VALUES ('$QzTeY37FC1XCBCS9k5WSqtd_ozVW1B45OBvMLOxOFRY', '$v4aPwfsZiQ4yEz5-T0kS_DWvVTqUxPRltYSFV4P8Jlk');
INSERT INTO public.event_auth (event_id, auth_event_id) VALUES ('$wVJJm-TLQ6il0h68B5rzA97t20lkmGMK7H0O6YdHEMM', '$i5rP6Kab--xLmDcMSPRUZxvyQZcPThTiofJjfrSnDtg');
INSERT INTO public.event_auth (event_id, auth_event_id) VALUES ('$wVJJm-TLQ6il0h68B5rzA97t20lkmGMK7H0O6YdHEMM', '$v4aPwfsZiQ4yEz5-T0kS_DWvVTqUxPRltYSFV4P8Jlk');
INSERT INTO public.event_auth (event_id, auth_event_id) VALUES ('$wVJJm-TLQ6il0h68B5rzA97t20lkmGMK7H0O6YdHEMM', '$QzTeY37FC1XCBCS9k5WSqtd_ozVW1B45OBvMLOxOFRY');
INSERT INTO public.event_auth (event_id, auth_event_id) VALUES ('$gbIXT6cBYsLvEAdCmvz_-Z-MLge4BnaLY_O1-PtdjGo', '$iLFuDk8nVttbD9AqXn1viyXUEFEl_2DI7hsgkXGjXN8');
INSERT INTO public.event_auth (event_id, auth_event_id) VALUES ('$gbIXT6cBYsLvEAdCmvz_-Z-MLge4BnaLY_O1-PtdjGo', '$i5rP6Kab--xLmDcMSPRUZxvyQZcPThTiofJjfrSnDtg');
INSERT INTO public.event_auth (event_id, auth_event_id) VALUES ('$mC5T62vlKtDEaC4l1ujmOJ3dA5q-PM-ku8SS1xRZCek', '$iLFuDk8nVttbD9AqXn1viyXUEFEl_2DI7hsgkXGjXN8');
INSERT INTO public.event_auth (event_id, auth_event_id) VALUES ('$mC5T62vlKtDEaC4l1ujmOJ3dA5q-PM-ku8SS1xRZCek', '$i5rP6Kab--xLmDcMSPRUZxvyQZcPThTiofJjfrSnDtg');
INSERT INTO public.event_auth (event_id, auth_event_id) VALUES ('$h7M6qztmLUOCjFAmWrrrh-vd87KuCykZl7jvFLSK3Ds', '$iLFuDk8nVttbD9AqXn1viyXUEFEl_2DI7hsgkXGjXN8');
INSERT INTO public.event_auth (event_id, auth_event_id) VALUES ('$h7M6qztmLUOCjFAmWrrrh-vd87KuCykZl7jvFLSK3Ds', '$i5rP6Kab--xLmDcMSPRUZxvyQZcPThTiofJjfrSnDtg');
INSERT INTO public.event_auth (event_id, auth_event_id) VALUES ('$GcOCV1AahAZenbnTVGpvMmYTyB2XNFzhRLwjkRT0Cy8', '$i5rP6Kab--xLmDcMSPRUZxvyQZcPThTiofJjfrSnDtg');
INSERT INTO public.event_auth (event_id, auth_event_id) VALUES ('$GcOCV1AahAZenbnTVGpvMmYTyB2XNFzhRLwjkRT0Cy8', '$wVJJm-TLQ6il0h68B5rzA97t20lkmGMK7H0O6YdHEMM');
INSERT INTO public.event_auth (event_id, auth_event_id) VALUES ('$PecG6aWhB2mDCM6YMk8crHbTdYzWkYUCN_ipzlMCjiI', '$gEZRQzCXH4iD07nDrZYaWlyfDmS0tqK_R-gW6JyF32U');
INSERT INTO public.event_auth (event_id, auth_event_id) VALUES ('$2oC-K1LNKA47eO1pqEmJrY0s6617pjOSdk68k5LiuZg', '$gEZRQzCXH4iD07nDrZYaWlyfDmS0tqK_R-gW6JyF32U');
INSERT INTO public.event_auth (event_id, auth_event_id) VALUES ('$2oC-K1LNKA47eO1pqEmJrY0s6617pjOSdk68k5LiuZg', '$PecG6aWhB2mDCM6YMk8crHbTdYzWkYUCN_ipzlMCjiI');
INSERT INTO public.event_auth (event_id, auth_event_id) VALUES ('$V6yysmqZ0o9qaJiimEfXi0Ku7kIFtR9hCAC7vGSowuY', '$gEZRQzCXH4iD07nDrZYaWlyfDmS0tqK_R-gW6JyF32U');
INSERT INTO public.event_auth (event_id, auth_event_id) VALUES ('$V6yysmqZ0o9qaJiimEfXi0Ku7kIFtR9hCAC7vGSowuY', '$PecG6aWhB2mDCM6YMk8crHbTdYzWkYUCN_ipzlMCjiI');
INSERT INTO public.event_auth (event_id, auth_event_id) VALUES ('$Lft2RjGrEuDUm8UkT3X25KYA1_81FeaFlJVeWLq8UdM', '$gEZRQzCXH4iD07nDrZYaWlyfDmS0tqK_R-gW6JyF32U');
INSERT INTO public.event_auth (event_id, auth_event_id) VALUES ('$Lft2RjGrEuDUm8UkT3X25KYA1_81FeaFlJVeWLq8UdM', '$PecG6aWhB2mDCM6YMk8crHbTdYzWkYUCN_ipzlMCjiI');
INSERT INTO public.event_auth (event_id, auth_event_id) VALUES ('$MDEmZSZMMOOQUjEQxIXi05XzoHayhwFR6YRDMOykvoI', '$gEZRQzCXH4iD07nDrZYaWlyfDmS0tqK_R-gW6JyF32U');
INSERT INTO public.event_auth (event_id, auth_event_id) VALUES ('$MDEmZSZMMOOQUjEQxIXi05XzoHayhwFR6YRDMOykvoI', '$PecG6aWhB2mDCM6YMk8crHbTdYzWkYUCN_ipzlMCjiI');
INSERT INTO public.event_auth (event_id, auth_event_id) VALUES ('$G6T266qKoHUbMYlVFKPN14wSCrqcj7ktb84OYLky32M', '$gEZRQzCXH4iD07nDrZYaWlyfDmS0tqK_R-gW6JyF32U');
INSERT INTO public.event_auth (event_id, auth_event_id) VALUES ('$G6T266qKoHUbMYlVFKPN14wSCrqcj7ktb84OYLky32M', '$PecG6aWhB2mDCM6YMk8crHbTdYzWkYUCN_ipzlMCjiI');


--
-- Data for Name: event_edges; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.event_edges (event_id, prev_event_id) VALUES ('$iLFuDk8nVttbD9AqXn1viyXUEFEl_2DI7hsgkXGjXN8', '$C7Cym0uRg_x2vckbuDPCwO4QgdsxfXpDiOi1WoH89NY');
INSERT INTO public.event_edges (event_id, prev_event_id) VALUES ('$i5rP6Kab--xLmDcMSPRUZxvyQZcPThTiofJjfrSnDtg', '$iLFuDk8nVttbD9AqXn1viyXUEFEl_2DI7hsgkXGjXN8');
INSERT INTO public.event_edges (event_id, prev_event_id) VALUES ('$v4aPwfsZiQ4yEz5-T0kS_DWvVTqUxPRltYSFV4P8Jlk', '$i5rP6Kab--xLmDcMSPRUZxvyQZcPThTiofJjfrSnDtg');
INSERT INTO public.event_edges (event_id, prev_event_id) VALUES ('$jQRkJoCECH7wDkXeK4PAzuiNM5N4-W-klgkSyuKI0Ig', '$v4aPwfsZiQ4yEz5-T0kS_DWvVTqUxPRltYSFV4P8Jlk');
INSERT INTO public.event_edges (event_id, prev_event_id) VALUES ('$3DxD43IUhKnopg81UbujM_TWm14GdVq22XKXiThD5Bo', '$jQRkJoCECH7wDkXeK4PAzuiNM5N4-W-klgkSyuKI0Ig');
INSERT INTO public.event_edges (event_id, prev_event_id) VALUES ('$LQujV90cKOa8fkPPU4PQX7sm6KL28V0r8nKCewBnOJ8', '$3DxD43IUhKnopg81UbujM_TWm14GdVq22XKXiThD5Bo');
INSERT INTO public.event_edges (event_id, prev_event_id) VALUES ('$RDqWCB4mWm4fTct25NtZAh5zmiUTG_EsgfQpCS2erxw', '$LQujV90cKOa8fkPPU4PQX7sm6KL28V0r8nKCewBnOJ8');
INSERT INTO public.event_edges (event_id, prev_event_id) VALUES ('$QzTeY37FC1XCBCS9k5WSqtd_ozVW1B45OBvMLOxOFRY', '$RDqWCB4mWm4fTct25NtZAh5zmiUTG_EsgfQpCS2erxw');
INSERT INTO public.event_edges (event_id, prev_event_id) VALUES ('$wVJJm-TLQ6il0h68B5rzA97t20lkmGMK7H0O6YdHEMM', '$QzTeY37FC1XCBCS9k5WSqtd_ozVW1B45OBvMLOxOFRY');
INSERT INTO public.event_edges (event_id, prev_event_id) VALUES ('$gbIXT6cBYsLvEAdCmvz_-Z-MLge4BnaLY_O1-PtdjGo', '$wVJJm-TLQ6il0h68B5rzA97t20lkmGMK7H0O6YdHEMM');
INSERT INTO public.event_edges (event_id, prev_event_id) VALUES ('$mC5T62vlKtDEaC4l1ujmOJ3dA5q-PM-ku8SS1xRZCek', '$gbIXT6cBYsLvEAdCmvz_-Z-MLge4BnaLY_O1-PtdjGo');
INSERT INTO public.event_edges (event_id, prev_event_id) VALUES ('$h7M6qztmLUOCjFAmWrrrh-vd87KuCykZl7jvFLSK3Ds', '$mC5T62vlKtDEaC4l1ujmOJ3dA5q-PM-ku8SS1xRZCek');
INSERT INTO public.event_edges (event_id, prev_event_id) VALUES ('$GcOCV1AahAZenbnTVGpvMmYTyB2XNFzhRLwjkRT0Cy8', '$h7M6qztmLUOCjFAmWrrrh-vd87KuCykZl7jvFLSK3Ds');
INSERT INTO public.event_edges (event_id, prev_event_id) VALUES ('$gEZRQzCXH4iD07nDrZYaWlyfDmS0tqK_R-gW6JyF32U', '$WLDmyNQlQnw_RhR08m7Jk_JO2mbtD9pY5COByGjLODA');
INSERT INTO public.event_edges (event_id, prev_event_id) VALUES ('$PecG6aWhB2mDCM6YMk8crHbTdYzWkYUCN_ipzlMCjiI', '$gEZRQzCXH4iD07nDrZYaWlyfDmS0tqK_R-gW6JyF32U');
INSERT INTO public.event_edges (event_id, prev_event_id) VALUES ('$2oC-K1LNKA47eO1pqEmJrY0s6617pjOSdk68k5LiuZg', '$PecG6aWhB2mDCM6YMk8crHbTdYzWkYUCN_ipzlMCjiI');
INSERT INTO public.event_edges (event_id, prev_event_id) VALUES ('$V6yysmqZ0o9qaJiimEfXi0Ku7kIFtR9hCAC7vGSowuY', '$2oC-K1LNKA47eO1pqEmJrY0s6617pjOSdk68k5LiuZg');
INSERT INTO public.event_edges (event_id, prev_event_id) VALUES ('$Lft2RjGrEuDUm8UkT3X25KYA1_81FeaFlJVeWLq8UdM', '$V6yysmqZ0o9qaJiimEfXi0Ku7kIFtR9hCAC7vGSowuY');
INSERT INTO public.event_edges (event_id, prev_event_id) VALUES ('$MDEmZSZMMOOQUjEQxIXi05XzoHayhwFR6YRDMOykvoI', '$Lft2RjGrEuDUm8UkT3X25KYA1_81FeaFlJVeWLq8UdM');
INSERT INTO public.event_edges (event_id, prev_event_id) VALUES ('$G6T266qKoHUbMYlVFKPN14wSCrqcj7ktb84OYLky32M', '$MDEmZSZMMOOQUjEQxIXi05XzoHayhwFR6YRDMOykvoI');


--
-- Data for Name: event_json; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: event_signatures; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.event_signatures (event_id, server_name, key_id, signature) VALUES ('$C7Cym0uRg_x2vckbuDPCwO4QgdsxfXpDiOi1WoH89NY', 'example.org', 'ed25519:76d6613f', '3frnQABSc2K4/37LcTVL4b0IiCRWhvkzuxzVTSqRQtpaIDqIx1gfPNtaqD6tflS6HbHGDQFvKHeuEZOk1gY9AQ');
INSERT INTO public.event_signatures (event_id, server_name, key_id, signature) VALUES ('$iLFuDk8nVttbD9AqXn1viyXUEFEl_2DI7hsgkXGjXN8', 'example.org', 'ed25519:76d6613f', 'jFuZOKy4ewxJYHWCb9SKxDFhKaVUFBCBq8NQtFnYD+UKtyEVzioaDqEfRS75XpBf+eJf30pei2wi5QO507mNAg');
INSERT INTO public.event_signatures (event_id, server_name, key_id, signature) VALUES ('$i5rP6Kab--xLmDcMSPRUZxvyQZcPThTiofJjfrSnDtg', 'example.org', 'ed25519:76d6613f', '9Ya2JwLzuQDA1nZrZKnvbCwYLx7v6BtdoRXKatBWFSMC6aXktuxuMiazcc/2qntlcZDRvHAM+eJKVpPoMscVDQ');
INSERT INTO public.event_signatures (event_id, server_name, key_id, signature) VALUES ('$v4aPwfsZiQ4yEz5-T0kS_DWvVTqUxPRltYSFV4P8Jlk', 'example.org', 'ed25519:76d6613f', 'LWYtQ01lNNgR6yxoy4iVxydEYTXAydCCNZU9Lo5QJCd8hhov30fNObIMeCpQkjWynhKc+xFsj0cWMUiv7Gh+Bw');
INSERT INTO public.event_signatures (event_id, server_name, key_id, signature) VALUES ('$jQRkJoCECH7wDkXeK4PAzuiNM5N4-W-klgkSyuKI0Ig', 'example.org', 'ed25519:76d6613f', 'zpusmcvsriZtMqnVBtMI0uFKTGFNMqHkC9tIR00WJAFTTqnl5n+wpEyypeFxhuR6JJMZLZp2kPbVEny0xikhCw');
INSERT INTO public.event_signatures (event_id, server_name, key_id, signature) VALUES ('$3DxD43IUhKnopg81UbujM_TWm14GdVq22XKXiThD5Bo', 'example.org', 'ed25519:76d6613f', 'Ox1jSZc8TlPxsi51n4x39UKVR2O/bDtKtgaHxXd2bo1J5ezwy9aOpezQoSGX8cGa5RARdnR2r9N/he0XmisnCg');
INSERT INTO public.event_signatures (event_id, server_name, key_id, signature) VALUES ('$LQujV90cKOa8fkPPU4PQX7sm6KL28V0r8nKCewBnOJ8', 'example.org', 'ed25519:76d6613f', 'yey6hQSQYCBHDCovmGoILewHu58iLc3K8LlA95SmhOA5yH4/f4Auo2oGmwBKCNOLQ2L8bbqUzynWoyZy0OYqAA');
INSERT INTO public.event_signatures (event_id, server_name, key_id, signature) VALUES ('$RDqWCB4mWm4fTct25NtZAh5zmiUTG_EsgfQpCS2erxw', 'example.org', 'ed25519:76d6613f', 'gfX0vOva648wvwThP7IggMyqxCksfZjo7mPmH+9/RE3lyf8RaQaH2GQKGB6Ad9nbuDl0H+8hPUeDfGIw3E3dDQ');
INSERT INTO public.event_signatures (event_id, server_name, key_id, signature) VALUES ('$QzTeY37FC1XCBCS9k5WSqtd_ozVW1B45OBvMLOxOFRY', 'example.org', 'ed25519:76d6613f', 'bRSdsgOyEaKnxNVQTbr+CSm4IZTkJ7S82mbptEc+mt6ywg2gYpqNKXbWdGskABIYoH66floDHymiT3RnAJwZCA');
INSERT INTO public.event_signatures (event_id, server_name, key_id, signature) VALUES ('$wVJJm-TLQ6il0h68B5rzA97t20lkmGMK7H0O6YdHEMM', 'example.org', 'ed25519:76d6613f', 'cz1hP8TbklKANszH+xcEbfBx/FS9eh5fxN4Hwnjxdn8qtRCL6hP77BAp6sF2FmlG7P8pkoOq8v7w76J0udX1Ag');
INSERT INTO public.event_signatures (event_id, server_name, key_id, signature) VALUES ('$gbIXT6cBYsLvEAdCmvz_-Z-MLge4BnaLY_O1-PtdjGo', 'example.org', 'ed25519:76d6613f', 'QXpHWG51uFHmhLxnCvfM+bvpKTtmqVSsltF1/q7wQlpBoQmaLaPiRBhtCTVHOxvET/4Q7RlqhhD2Bfam/ZEUAw');
INSERT INTO public.event_signatures (event_id, server_name, key_id, signature) VALUES ('$mC5T62vlKtDEaC4l1ujmOJ3dA5q-PM-ku8SS1xRZCek', 'example.org', 'ed25519:76d6613f', 'qFvolB96ql4o6ApfoP+SWYcMbDI7FfQYa7qKiFwgM8LcdTtIL9unkj0bi3+a2b1Z/G8G+PdF+Q4CixMfkFNEDg');
INSERT INTO public.event_signatures (event_id, server_name, key_id, signature) VALUES ('$h7M6qztmLUOCjFAmWrrrh-vd87KuCykZl7jvFLSK3Ds', 'example.org', 'ed25519:76d6613f', 'jVD/fxDVi44OlM0xryZwEeZkV+OQq4C/qvY2oSB6hTaQtq2UPfKYQcdy8fJGi0mAGtbGPSeKCBl0rqmkd53uAw');
INSERT INTO public.event_signatures (event_id, server_name, key_id, signature) VALUES ('$GcOCV1AahAZenbnTVGpvMmYTyB2XNFzhRLwjkRT0Cy8', 'example.org', 'ed25519:76d6613f', '0Ej0RJCDtIzH5ISMF6PKtdBQKl20J5E1Tq5Ud9dSJVxuh7Xc9zt1R2p1eTdYnaEKMqRSelx1DmE5AarEdFG8CA');
INSERT INTO public.event_signatures (event_id, server_name, key_id, signature) VALUES ('$WLDmyNQlQnw_RhR08m7Jk_JO2mbtD9pY5COByGjLODA', 'example.org', 'ed25519:76d6613f', '0kLHXj9ow1MkrnOT1KYeb69Hdk/W0uDxZhTNw4Nz0YHODNfKcHqCsZ1yGJLA4vE2EaC8QBfaekTd9Fq+kALTBw');
INSERT INTO public.event_signatures (event_id, server_name, key_id, signature) VALUES ('$gEZRQzCXH4iD07nDrZYaWlyfDmS0tqK_R-gW6JyF32U', 'example.org', 'ed25519:76d6613f', '9bfA6431NNhLsvcAJ0dRJ4Ruqql1cFl6A7XmwaBLT2CQNji5Xpd/+HczGIT4E+Kft0IIkH8FfrdHUETK/IaRCw');
INSERT INTO public.event_signatures (event_id, server_name, key_id, signature) VALUES ('$PecG6aWhB2mDCM6YMk8crHbTdYzWkYUCN_ipzlMCjiI', 'example.org', 'ed25519:76d6613f', 'j/PZ2/oF/fNiLaXx44nkSEg4AN7HgpdD66Y1gsPkmLQKRNJBwHl4SPodxJy0Dsc3nWgwqJfFOqlZH/a5JwGDCg');
INSERT INTO public.event_signatures (event_id, server_name, key_id, signature) VALUES ('$2oC-K1LNKA47eO1pqEmJrY0s6617pjOSdk68k5LiuZg', 'example.org', 'ed25519:76d6613f', 'itC4d6HfjT7XS9dOyL5PyP8e0s7hv6EwfBHNT8oH8bHS70+Xo+Zt8jeRFYZtYsdm6DTqYRdiVTrDL6q6msvtAg');
INSERT INTO public.event_signatures (event_id, server_name, key_id, signature) VALUES ('$V6yysmqZ0o9qaJiimEfXi0Ku7kIFtR9hCAC7vGSowuY', 'example.org', 'ed25519:76d6613f', '20xjkZeHqAE/2mlNEwtqENmyEusYotibPGAPn0A3ntL90O1t33MYoyWHL9baYuHCglqtxIVPyAXYptllhVZxAA');
INSERT INTO public.event_signatures (event_id, server_name, key_id, signature) VALUES ('$Lft2RjGrEuDUm8UkT3X25KYA1_81FeaFlJVeWLq8UdM', 'example.org', 'ed25519:76d6613f', 'tEAp2KuW8C+AVb18hpUq6FF3kQ1U75ayzWMPUx/DHPipAfajQ6MnQe8Ts3gqIo6MJg5ZXe9T6ASN2MPAQ7qFDg');
INSERT INTO public.event_signatures (event_id, server_name, key_id, signature) VALUES ('$MDEmZSZMMOOQUjEQxIXi05XzoHayhwFR6YRDMOykvoI', 'example.org', 'ed25519:76d6613f', 'fB5PjFjkA/TR7+hXy8/+MQeWh5VRA+aGLS+6Q2zHL2pGCBLPS+cX1+jqlweSKifxGnWtOM8tPH6GZhZ3BFXDCw');
INSERT INTO public.event_signatures (event_id, server_name, key_id, signature) VALUES ('$G6T266qKoHUbMYlVFKPN14wSCrqcj7ktb84OYLky32M', 'example.org', 'ed25519:76d6613f', 'yCI4HRCLRor9+l4NIlnbUWiiel/Fn1WhOMsSeRQVn9RTV3zOn2DAlTKaFDyTz8NeBM/B9hcb1UGLVtWDMBiGCQ');


--
-- Data for Name: event_state_groups; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.event_state_groups (event_id, state_group_id) VALUES ('$C7Cym0uRg_x2vckbuDPCwO4QgdsxfXpDiOi1WoH89NY', 'sg:$C7Cym0uRg_x2vckbuDPCwO4QgdsxfXpDiOi1WoH89NY');
INSERT INTO public.event_state_groups (event_id, state_group_id) VALUES ('$iLFuDk8nVttbD9AqXn1viyXUEFEl_2DI7hsgkXGjXN8', 'sg:$iLFuDk8nVttbD9AqXn1viyXUEFEl_2DI7hsgkXGjXN8');
INSERT INTO public.event_state_groups (event_id, state_group_id) VALUES ('$i5rP6Kab--xLmDcMSPRUZxvyQZcPThTiofJjfrSnDtg', 'sg:$i5rP6Kab--xLmDcMSPRUZxvyQZcPThTiofJjfrSnDtg');
INSERT INTO public.event_state_groups (event_id, state_group_id) VALUES ('$v4aPwfsZiQ4yEz5-T0kS_DWvVTqUxPRltYSFV4P8Jlk', 'sg:$v4aPwfsZiQ4yEz5-T0kS_DWvVTqUxPRltYSFV4P8Jlk');
INSERT INTO public.event_state_groups (event_id, state_group_id) VALUES ('$jQRkJoCECH7wDkXeK4PAzuiNM5N4-W-klgkSyuKI0Ig', 'sg:$jQRkJoCECH7wDkXeK4PAzuiNM5N4-W-klgkSyuKI0Ig');
INSERT INTO public.event_state_groups (event_id, state_group_id) VALUES ('$3DxD43IUhKnopg81UbujM_TWm14GdVq22XKXiThD5Bo', 'sg:$3DxD43IUhKnopg81UbujM_TWm14GdVq22XKXiThD5Bo');
INSERT INTO public.event_state_groups (event_id, state_group_id) VALUES ('$LQujV90cKOa8fkPPU4PQX7sm6KL28V0r8nKCewBnOJ8', 'sg:$LQujV90cKOa8fkPPU4PQX7sm6KL28V0r8nKCewBnOJ8');
INSERT INTO public.event_state_groups (event_id, state_group_id) VALUES ('$RDqWCB4mWm4fTct25NtZAh5zmiUTG_EsgfQpCS2erxw', 'sg:$RDqWCB4mWm4fTct25NtZAh5zmiUTG_EsgfQpCS2erxw');
INSERT INTO public.event_state_groups (event_id, state_group_id) VALUES ('$QzTeY37FC1XCBCS9k5WSqtd_ozVW1B45OBvMLOxOFRY', 'sg:$QzTeY37FC1XCBCS9k5WSqtd_ozVW1B45OBvMLOxOFRY');
INSERT INTO public.event_state_groups (event_id, state_group_id) VALUES ('$wVJJm-TLQ6il0h68B5rzA97t20lkmGMK7H0O6YdHEMM', 'sg:$wVJJm-TLQ6il0h68B5rzA97t20lkmGMK7H0O6YdHEMM');
INSERT INTO public.event_state_groups (event_id, state_group_id) VALUES ('$gbIXT6cBYsLvEAdCmvz_-Z-MLge4BnaLY_O1-PtdjGo', 'sg:$wVJJm-TLQ6il0h68B5rzA97t20lkmGMK7H0O6YdHEMM');
INSERT INTO public.event_state_groups (event_id, state_group_id) VALUES ('$mC5T62vlKtDEaC4l1ujmOJ3dA5q-PM-ku8SS1xRZCek', 'sg:$wVJJm-TLQ6il0h68B5rzA97t20lkmGMK7H0O6YdHEMM');
INSERT INTO public.event_state_groups (event_id, state_group_id) VALUES ('$h7M6qztmLUOCjFAmWrrrh-vd87KuCykZl7jvFLSK3Ds', 'sg:$wVJJm-TLQ6il0h68B5rzA97t20lkmGMK7H0O6YdHEMM');
INSERT INTO public.event_state_groups (event_id, state_group_id) VALUES ('$GcOCV1AahAZenbnTVGpvMmYTyB2XNFzhRLwjkRT0Cy8', 'sg:$wVJJm-TLQ6il0h68B5rzA97t20lkmGMK7H0O6YdHEMM');
INSERT INTO public.event_state_groups (event_id, state_group_id) VALUES ('$WLDmyNQlQnw_RhR08m7Jk_JO2mbtD9pY5COByGjLODA', 'sg:$WLDmyNQlQnw_RhR08m7Jk_JO2mbtD9pY5COByGjLODA');
INSERT INTO public.event_state_groups (event_id, state_group_id) VALUES ('$gEZRQzCXH4iD07nDrZYaWlyfDmS0tqK_R-gW6JyF32U', 'sg:$gEZRQzCXH4iD07nDrZYaWlyfDmS0tqK_R-gW6JyF32U');
INSERT INTO public.event_state_groups (event_id, state_group_id) VALUES ('$PecG6aWhB2mDCM6YMk8crHbTdYzWkYUCN_ipzlMCjiI', 'sg:$PecG6aWhB2mDCM6YMk8crHbTdYzWkYUCN_ipzlMCjiI');
INSERT INTO public.event_state_groups (event_id, state_group_id) VALUES ('$2oC-K1LNKA47eO1pqEmJrY0s6617pjOSdk68k5LiuZg', 'sg:$2oC-K1LNKA47eO1pqEmJrY0s6617pjOSdk68k5LiuZg');
INSERT INTO public.event_state_groups (event_id, state_group_id) VALUES ('$V6yysmqZ0o9qaJiimEfXi0Ku7kIFtR9hCAC7vGSowuY', 'sg:$V6yysmqZ0o9qaJiimEfXi0Ku7kIFtR9hCAC7vGSowuY');
INSERT INTO public.event_state_groups (event_id, state_group_id) VALUES ('$Lft2RjGrEuDUm8UkT3X25KYA1_81FeaFlJVeWLq8UdM', 'sg:$Lft2RjGrEuDUm8UkT3X25KYA1_81FeaFlJVeWLq8UdM');
INSERT INTO public.event_state_groups (event_id, state_group_id) VALUES ('$MDEmZSZMMOOQUjEQxIXi05XzoHayhwFR6YRDMOykvoI', 'sg:$MDEmZSZMMOOQUjEQxIXi05XzoHayhwFR6YRDMOykvoI');
INSERT INTO public.event_state_groups (event_id, state_group_id) VALUES ('$G6T266qKoHUbMYlVFKPN14wSCrqcj7ktb84OYLky32M', 'sg:$G6T266qKoHUbMYlVFKPN14wSCrqcj7ktb84OYLky32M');


--
-- Data for Name: event_stream_watermark; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.event_stream_watermark (singleton, watermark) VALUES (1, '26');


--
-- Data for Name: events; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.events (event_id, room_id, sender_user_id, json, depth, stream_ordering, status) VALUES ('$C7Cym0uRg_x2vckbuDPCwO4QgdsxfXpDiOi1WoH89NY', '!C7Cym0uRg_x2vckbuDPCwO4QgdsxfXpDiOi1WoH89NY', '@alice:example.org', '{"auth_events":[],"content":{"room_version":"12"},"depth":1,"hashes":{"sha256":"ukIzSXsuaLcnKGrLS+GZdhoFOlOuSA/0UMlSw9nrgzA"},"origin_server_ts":1794844863448,"prev_events":[],"sender":"@alice:example.org","signatures":{"example.org":{"ed25519:76d6613f":"3frnQABSc2K4/37LcTVL4b0IiCRWhvkzuxzVTSqRQtpaIDqIx1gfPNtaqD6tflS6HbHGDQFvKHeuEZOk1gY9AQ"}},"state_key":"","type":"m.room.create"}', '1', '1', 'accepted');
INSERT INTO public.events (event_id, room_id, sender_user_id, json, depth, stream_ordering, status) VALUES ('$iLFuDk8nVttbD9AqXn1viyXUEFEl_2DI7hsgkXGjXN8', '!C7Cym0uRg_x2vckbuDPCwO4QgdsxfXpDiOi1WoH89NY', '@alice:example.org', '{"auth_events":[],"content":{"displayname":"Alice Upgrade","membership":"join"},"depth":2,"hashes":{"sha256":"8A2gIEu0GzYtN2aGqWDl39PwQM7Xf9qsTKGnUiCziOo"},"origin_server_ts":1794844863452,"prev_events":["$C7Cym0uRg_x2vckbuDPCwO4QgdsxfXpDiOi1WoH89NY"],"room_id":"!C7Cym0uRg_x2vckbuDPCwO4QgdsxfXpDiOi1WoH89NY","sender":"@alice:example.org","signatures":{"example.org":{"ed25519:76d6613f":"jFuZOKy4ewxJYHWCb9SKxDFhKaVUFBCBq8NQtFnYD+UKtyEVzioaDqEfRS75XpBf+eJf30pei2wi5QO507mNAg"}},"state_key":"@alice:example.org","type":"m.room.member"}', '2', '2', 'accepted');
INSERT INTO public.events (event_id, room_id, sender_user_id, json, depth, stream_ordering, status) VALUES ('$i5rP6Kab--xLmDcMSPRUZxvyQZcPThTiofJjfrSnDtg', '!C7Cym0uRg_x2vckbuDPCwO4QgdsxfXpDiOi1WoH89NY', '@alice:example.org', '{"auth_events":["$iLFuDk8nVttbD9AqXn1viyXUEFEl_2DI7hsgkXGjXN8"],"content":{"ban":50,"events":{"m.room.tombstone":150},"events_default":0,"invite":50,"kick":50,"redact":50,"state_default":50,"users":{},"users_default":0},"depth":3,"hashes":{"sha256":"FtybYJrEQHsaBRUNVnvseKDUPMdqpQ5MrijDyGn/dFU"},"origin_server_ts":1794844863455,"prev_events":["$iLFuDk8nVttbD9AqXn1viyXUEFEl_2DI7hsgkXGjXN8"],"room_id":"!C7Cym0uRg_x2vckbuDPCwO4QgdsxfXpDiOi1WoH89NY","sender":"@alice:example.org","signatures":{"example.org":{"ed25519:76d6613f":"9Ya2JwLzuQDA1nZrZKnvbCwYLx7v6BtdoRXKatBWFSMC6aXktuxuMiazcc/2qntlcZDRvHAM+eJKVpPoMscVDQ"}},"state_key":"","type":"m.room.power_levels"}', '3', '4', 'accepted');
INSERT INTO public.events (event_id, room_id, sender_user_id, json, depth, stream_ordering, status) VALUES ('$v4aPwfsZiQ4yEz5-T0kS_DWvVTqUxPRltYSFV4P8Jlk', '!C7Cym0uRg_x2vckbuDPCwO4QgdsxfXpDiOi1WoH89NY', '@alice:example.org', '{"auth_events":["$iLFuDk8nVttbD9AqXn1viyXUEFEl_2DI7hsgkXGjXN8","$i5rP6Kab--xLmDcMSPRUZxvyQZcPThTiofJjfrSnDtg"],"content":{"join_rule":"invite"},"depth":4,"hashes":{"sha256":"X0Afy9IeLAyzLieQ3+gaXSiYv7EgExqMxVdC00dKZ9E"},"origin_server_ts":1794844863457,"prev_events":["$i5rP6Kab--xLmDcMSPRUZxvyQZcPThTiofJjfrSnDtg"],"room_id":"!C7Cym0uRg_x2vckbuDPCwO4QgdsxfXpDiOi1WoH89NY","sender":"@alice:example.org","signatures":{"example.org":{"ed25519:76d6613f":"LWYtQ01lNNgR6yxoy4iVxydEYTXAydCCNZU9Lo5QJCd8hhov30fNObIMeCpQkjWynhKc+xFsj0cWMUiv7Gh+Bw"}},"state_key":"","type":"m.room.join_rules"}', '4', '5', 'accepted');
INSERT INTO public.events (event_id, room_id, sender_user_id, json, depth, stream_ordering, status) VALUES ('$jQRkJoCECH7wDkXeK4PAzuiNM5N4-W-klgkSyuKI0Ig', '!C7Cym0uRg_x2vckbuDPCwO4QgdsxfXpDiOi1WoH89NY', '@alice:example.org', '{"auth_events":["$iLFuDk8nVttbD9AqXn1viyXUEFEl_2DI7hsgkXGjXN8","$i5rP6Kab--xLmDcMSPRUZxvyQZcPThTiofJjfrSnDtg"],"content":{"history_visibility":"shared"},"depth":5,"hashes":{"sha256":"eDH3ElCu4q1EVxOIlwnLXIEWwLP8QD64jdQJwmRXt68"},"origin_server_ts":1794844863459,"prev_events":["$v4aPwfsZiQ4yEz5-T0kS_DWvVTqUxPRltYSFV4P8Jlk"],"room_id":"!C7Cym0uRg_x2vckbuDPCwO4QgdsxfXpDiOi1WoH89NY","sender":"@alice:example.org","signatures":{"example.org":{"ed25519:76d6613f":"zpusmcvsriZtMqnVBtMI0uFKTGFNMqHkC9tIR00WJAFTTqnl5n+wpEyypeFxhuR6JJMZLZp2kPbVEny0xikhCw"}},"state_key":"","type":"m.room.history_visibility"}', '5', '6', 'accepted');
INSERT INTO public.events (event_id, room_id, sender_user_id, json, depth, stream_ordering, status) VALUES ('$3DxD43IUhKnopg81UbujM_TWm14GdVq22XKXiThD5Bo', '!C7Cym0uRg_x2vckbuDPCwO4QgdsxfXpDiOi1WoH89NY', '@alice:example.org', '{"auth_events":["$iLFuDk8nVttbD9AqXn1viyXUEFEl_2DI7hsgkXGjXN8","$i5rP6Kab--xLmDcMSPRUZxvyQZcPThTiofJjfrSnDtg"],"content":{"guest_access":"can_join"},"depth":6,"hashes":{"sha256":"d3Vm0bnFOKntl1bI6w02yiF8/91+SGx8FuNg46lmu4g"},"origin_server_ts":1794844863461,"prev_events":["$jQRkJoCECH7wDkXeK4PAzuiNM5N4-W-klgkSyuKI0Ig"],"room_id":"!C7Cym0uRg_x2vckbuDPCwO4QgdsxfXpDiOi1WoH89NY","sender":"@alice:example.org","signatures":{"example.org":{"ed25519:76d6613f":"Ox1jSZc8TlPxsi51n4x39UKVR2O/bDtKtgaHxXd2bo1J5ezwy9aOpezQoSGX8cGa5RARdnR2r9N/he0XmisnCg"}},"state_key":"","type":"m.room.guest_access"}', '6', '7', 'accepted');
INSERT INTO public.events (event_id, room_id, sender_user_id, json, depth, stream_ordering, status) VALUES ('$LQujV90cKOa8fkPPU4PQX7sm6KL28V0r8nKCewBnOJ8', '!C7Cym0uRg_x2vckbuDPCwO4QgdsxfXpDiOi1WoH89NY', '@alice:example.org', '{"auth_events":["$iLFuDk8nVttbD9AqXn1viyXUEFEl_2DI7hsgkXGjXN8","$i5rP6Kab--xLmDcMSPRUZxvyQZcPThTiofJjfrSnDtg"],"content":{"algorithm":"m.megolm.v1.aes-sha2"},"depth":7,"hashes":{"sha256":"4CelsPBgavq/meNLZT9RkEarQ3D6DXTkVZFIwDBug60"},"origin_server_ts":1794844863464,"prev_events":["$3DxD43IUhKnopg81UbujM_TWm14GdVq22XKXiThD5Bo"],"room_id":"!C7Cym0uRg_x2vckbuDPCwO4QgdsxfXpDiOi1WoH89NY","sender":"@alice:example.org","signatures":{"example.org":{"ed25519:76d6613f":"yey6hQSQYCBHDCovmGoILewHu58iLc3K8LlA95SmhOA5yH4/f4Auo2oGmwBKCNOLQ2L8bbqUzynWoyZy0OYqAA"}},"state_key":"","type":"m.room.encryption"}', '7', '8', 'accepted');
INSERT INTO public.events (event_id, room_id, sender_user_id, json, depth, stream_ordering, status) VALUES ('$RDqWCB4mWm4fTct25NtZAh5zmiUTG_EsgfQpCS2erxw', '!C7Cym0uRg_x2vckbuDPCwO4QgdsxfXpDiOi1WoH89NY', '@alice:example.org', '{"auth_events":["$iLFuDk8nVttbD9AqXn1viyXUEFEl_2DI7hsgkXGjXN8","$i5rP6Kab--xLmDcMSPRUZxvyQZcPThTiofJjfrSnDtg"],"content":{"name":"Upgrade Room"},"depth":8,"hashes":{"sha256":"6NStMj7U7YomSwV7ENPL+MBSSxVBCP0qPBVo51PAm54"},"origin_server_ts":1794844863466,"prev_events":["$LQujV90cKOa8fkPPU4PQX7sm6KL28V0r8nKCewBnOJ8"],"room_id":"!C7Cym0uRg_x2vckbuDPCwO4QgdsxfXpDiOi1WoH89NY","sender":"@alice:example.org","signatures":{"example.org":{"ed25519:76d6613f":"gfX0vOva648wvwThP7IggMyqxCksfZjo7mPmH+9/RE3lyf8RaQaH2GQKGB6Ad9nbuDl0H+8hPUeDfGIw3E3dDQ"}},"state_key":"","type":"m.room.name"}', '8', '9', 'accepted');
INSERT INTO public.events (event_id, room_id, sender_user_id, json, depth, stream_ordering, status) VALUES ('$QzTeY37FC1XCBCS9k5WSqtd_ozVW1B45OBvMLOxOFRY', '!C7Cym0uRg_x2vckbuDPCwO4QgdsxfXpDiOi1WoH89NY', '@alice:example.org', '{"auth_events":["$iLFuDk8nVttbD9AqXn1viyXUEFEl_2DI7hsgkXGjXN8","$i5rP6Kab--xLmDcMSPRUZxvyQZcPThTiofJjfrSnDtg","$v4aPwfsZiQ4yEz5-T0kS_DWvVTqUxPRltYSFV4P8Jlk"],"content":{"membership":"invite"},"depth":9,"hashes":{"sha256":"sjUHm4r1CbS/JXJwBwbQUGIV7/0M53udfCPcYviFkF0"},"origin_server_ts":1794844863469,"prev_events":["$RDqWCB4mWm4fTct25NtZAh5zmiUTG_EsgfQpCS2erxw"],"room_id":"!C7Cym0uRg_x2vckbuDPCwO4QgdsxfXpDiOi1WoH89NY","sender":"@alice:example.org","signatures":{"example.org":{"ed25519:76d6613f":"bRSdsgOyEaKnxNVQTbr+CSm4IZTkJ7S82mbptEc+mt6ywg2gYpqNKXbWdGskABIYoH66floDHymiT3RnAJwZCA"}},"state_key":"@bob:example.org","type":"m.room.member"}', '9', '10', 'accepted');
INSERT INTO public.events (event_id, room_id, sender_user_id, json, depth, stream_ordering, status) VALUES ('$wVJJm-TLQ6il0h68B5rzA97t20lkmGMK7H0O6YdHEMM', '!C7Cym0uRg_x2vckbuDPCwO4QgdsxfXpDiOi1WoH89NY', '@bob:example.org', '{"auth_events":["$i5rP6Kab--xLmDcMSPRUZxvyQZcPThTiofJjfrSnDtg","$v4aPwfsZiQ4yEz5-T0kS_DWvVTqUxPRltYSFV4P8Jlk","$QzTeY37FC1XCBCS9k5WSqtd_ozVW1B45OBvMLOxOFRY"],"content":{"membership":"join"},"depth":10,"hashes":{"sha256":"YHZrm5GlQ1gT6uJDyj4JRyVUKnBbaNc5asBNz33ioms"},"origin_server_ts":1794844863475,"prev_events":["$QzTeY37FC1XCBCS9k5WSqtd_ozVW1B45OBvMLOxOFRY"],"room_id":"!C7Cym0uRg_x2vckbuDPCwO4QgdsxfXpDiOi1WoH89NY","sender":"@bob:example.org","signatures":{"example.org":{"ed25519:76d6613f":"cz1hP8TbklKANszH+xcEbfBx/FS9eh5fxN4Hwnjxdn8qtRCL6hP77BAp6sF2FmlG7P8pkoOq8v7w76J0udX1Ag"}},"state_key":"@bob:example.org","type":"m.room.member"}', '10', '12', 'accepted');
INSERT INTO public.events (event_id, room_id, sender_user_id, json, depth, stream_ordering, status) VALUES ('$gbIXT6cBYsLvEAdCmvz_-Z-MLge4BnaLY_O1-PtdjGo', '!C7Cym0uRg_x2vckbuDPCwO4QgdsxfXpDiOi1WoH89NY', '@alice:example.org', '{"auth_events":["$iLFuDk8nVttbD9AqXn1viyXUEFEl_2DI7hsgkXGjXN8","$i5rP6Kab--xLmDcMSPRUZxvyQZcPThTiofJjfrSnDtg"],"content":{"body":"upgrade message 1","msgtype":"m.text"},"depth":11,"hashes":{"sha256":"Vl/8CSiisu6XsaNl3H27wdujyobKJhrB1SBq7fSsscc"},"origin_server_ts":1794844863480,"prev_events":["$wVJJm-TLQ6il0h68B5rzA97t20lkmGMK7H0O6YdHEMM"],"room_id":"!C7Cym0uRg_x2vckbuDPCwO4QgdsxfXpDiOi1WoH89NY","sender":"@alice:example.org","signatures":{"example.org":{"ed25519:76d6613f":"QXpHWG51uFHmhLxnCvfM+bvpKTtmqVSsltF1/q7wQlpBoQmaLaPiRBhtCTVHOxvET/4Q7RlqhhD2Bfam/ZEUAw"}},"type":"m.room.message"}', '11', '14', 'accepted');
INSERT INTO public.events (event_id, room_id, sender_user_id, json, depth, stream_ordering, status) VALUES ('$mC5T62vlKtDEaC4l1ujmOJ3dA5q-PM-ku8SS1xRZCek', '!C7Cym0uRg_x2vckbuDPCwO4QgdsxfXpDiOi1WoH89NY', '@alice:example.org', '{"auth_events":["$iLFuDk8nVttbD9AqXn1viyXUEFEl_2DI7hsgkXGjXN8","$i5rP6Kab--xLmDcMSPRUZxvyQZcPThTiofJjfrSnDtg"],"content":{"body":"upgrade message 2","msgtype":"m.text"},"depth":12,"hashes":{"sha256":"vdLJp+90spZ3AZRQ2IAMLvitqfNC/h25ABSoubMLW9o"},"origin_server_ts":1794844863484,"prev_events":["$gbIXT6cBYsLvEAdCmvz_-Z-MLge4BnaLY_O1-PtdjGo"],"room_id":"!C7Cym0uRg_x2vckbuDPCwO4QgdsxfXpDiOi1WoH89NY","sender":"@alice:example.org","signatures":{"example.org":{"ed25519:76d6613f":"qFvolB96ql4o6ApfoP+SWYcMbDI7FfQYa7qKiFwgM8LcdTtIL9unkj0bi3+a2b1Z/G8G+PdF+Q4CixMfkFNEDg"}},"type":"m.room.message"}', '12', '15', 'accepted');
INSERT INTO public.events (event_id, room_id, sender_user_id, json, depth, stream_ordering, status) VALUES ('$h7M6qztmLUOCjFAmWrrrh-vd87KuCykZl7jvFLSK3Ds', '!C7Cym0uRg_x2vckbuDPCwO4QgdsxfXpDiOi1WoH89NY', '@alice:example.org', '{"auth_events":["$iLFuDk8nVttbD9AqXn1viyXUEFEl_2DI7hsgkXGjXN8","$i5rP6Kab--xLmDcMSPRUZxvyQZcPThTiofJjfrSnDtg"],"content":{"body":"upgrade message 3","msgtype":"m.text"},"depth":13,"hashes":{"sha256":"9E410+O1F9fy18uEx0d+xHruRsFgt79awbugTv5iqvo"},"origin_server_ts":1794844863488,"prev_events":["$mC5T62vlKtDEaC4l1ujmOJ3dA5q-PM-ku8SS1xRZCek"],"room_id":"!C7Cym0uRg_x2vckbuDPCwO4QgdsxfXpDiOi1WoH89NY","sender":"@alice:example.org","signatures":{"example.org":{"ed25519:76d6613f":"jVD/fxDVi44OlM0xryZwEeZkV+OQq4C/qvY2oSB6hTaQtq2UPfKYQcdy8fJGi0mAGtbGPSeKCBl0rqmkd53uAw"}},"type":"m.room.message"}', '13', '16', 'accepted');
INSERT INTO public.events (event_id, room_id, sender_user_id, json, depth, stream_ordering, status) VALUES ('$GcOCV1AahAZenbnTVGpvMmYTyB2XNFzhRLwjkRT0Cy8', '!C7Cym0uRg_x2vckbuDPCwO4QgdsxfXpDiOi1WoH89NY', '@bob:example.org', '{"auth_events":["$i5rP6Kab--xLmDcMSPRUZxvyQZcPThTiofJjfrSnDtg","$wVJJm-TLQ6il0h68B5rzA97t20lkmGMK7H0O6YdHEMM"],"content":{"body":"reply from bob","msgtype":"m.text"},"depth":14,"hashes":{"sha256":"8BHGFi/vfvzAQvL8UvYZHq01NV4hWo+xXY9IW8vqrNg"},"origin_server_ts":1794844863491,"prev_events":["$h7M6qztmLUOCjFAmWrrrh-vd87KuCykZl7jvFLSK3Ds"],"room_id":"!C7Cym0uRg_x2vckbuDPCwO4QgdsxfXpDiOi1WoH89NY","sender":"@bob:example.org","signatures":{"example.org":{"ed25519:76d6613f":"0Ej0RJCDtIzH5ISMF6PKtdBQKl20J5E1Tq5Ud9dSJVxuh7Xc9zt1R2p1eTdYnaEKMqRSelx1DmE5AarEdFG8CA"}},"type":"m.room.message"}', '14', '17', 'accepted');
INSERT INTO public.events (event_id, room_id, sender_user_id, json, depth, stream_ordering, status) VALUES ('$WLDmyNQlQnw_RhR08m7Jk_JO2mbtD9pY5COByGjLODA', '!WLDmyNQlQnw_RhR08m7Jk_JO2mbtD9pY5COByGjLODA', '@alice:example.org', '{"auth_events":[],"content":{"room_version":"12"},"depth":1,"hashes":{"sha256":"amReiy3Oq8u2hvqvO5WU0J45yPU/Z4CnJUyWy3xXlNc"},"origin_server_ts":1794844863495,"prev_events":[],"sender":"@alice:example.org","signatures":{"example.org":{"ed25519:76d6613f":"0kLHXj9ow1MkrnOT1KYeb69Hdk/W0uDxZhTNw4Nz0YHODNfKcHqCsZ1yGJLA4vE2EaC8QBfaekTd9Fq+kALTBw"}},"state_key":"","type":"m.room.create"}', '1', '18', 'accepted');
INSERT INTO public.events (event_id, room_id, sender_user_id, json, depth, stream_ordering, status) VALUES ('$gEZRQzCXH4iD07nDrZYaWlyfDmS0tqK_R-gW6JyF32U', '!WLDmyNQlQnw_RhR08m7Jk_JO2mbtD9pY5COByGjLODA', '@alice:example.org', '{"auth_events":[],"content":{"displayname":"Alice Upgrade","membership":"join"},"depth":2,"hashes":{"sha256":"rtx4neMEAic2lzzpqx49fl+VBIvCEvL7sPKT5KtE7Ls"},"origin_server_ts":1794844863497,"prev_events":["$WLDmyNQlQnw_RhR08m7Jk_JO2mbtD9pY5COByGjLODA"],"room_id":"!WLDmyNQlQnw_RhR08m7Jk_JO2mbtD9pY5COByGjLODA","sender":"@alice:example.org","signatures":{"example.org":{"ed25519:76d6613f":"9bfA6431NNhLsvcAJ0dRJ4Ruqql1cFl6A7XmwaBLT2CQNji5Xpd/+HczGIT4E+Kft0IIkH8FfrdHUETK/IaRCw"}},"state_key":"@alice:example.org","type":"m.room.member"}', '2', '19', 'accepted');
INSERT INTO public.events (event_id, room_id, sender_user_id, json, depth, stream_ordering, status) VALUES ('$PecG6aWhB2mDCM6YMk8crHbTdYzWkYUCN_ipzlMCjiI', '!WLDmyNQlQnw_RhR08m7Jk_JO2mbtD9pY5COByGjLODA', '@alice:example.org', '{"auth_events":["$gEZRQzCXH4iD07nDrZYaWlyfDmS0tqK_R-gW6JyF32U"],"content":{"ban":50,"events":{"m.room.tombstone":150},"events_default":0,"invite":50,"kick":50,"redact":50,"state_default":50,"users":{},"users_default":0},"depth":3,"hashes":{"sha256":"yZDVwHFW+YhhT1biiT35RacPmcxSWcuu2J8QXUdf/lw"},"origin_server_ts":1794844863500,"prev_events":["$gEZRQzCXH4iD07nDrZYaWlyfDmS0tqK_R-gW6JyF32U"],"room_id":"!WLDmyNQlQnw_RhR08m7Jk_JO2mbtD9pY5COByGjLODA","sender":"@alice:example.org","signatures":{"example.org":{"ed25519:76d6613f":"j/PZ2/oF/fNiLaXx44nkSEg4AN7HgpdD66Y1gsPkmLQKRNJBwHl4SPodxJy0Dsc3nWgwqJfFOqlZH/a5JwGDCg"}},"state_key":"","type":"m.room.power_levels"}', '3', '21', 'accepted');
INSERT INTO public.events (event_id, room_id, sender_user_id, json, depth, stream_ordering, status) VALUES ('$2oC-K1LNKA47eO1pqEmJrY0s6617pjOSdk68k5LiuZg', '!WLDmyNQlQnw_RhR08m7Jk_JO2mbtD9pY5COByGjLODA', '@alice:example.org', '{"auth_events":["$gEZRQzCXH4iD07nDrZYaWlyfDmS0tqK_R-gW6JyF32U","$PecG6aWhB2mDCM6YMk8crHbTdYzWkYUCN_ipzlMCjiI"],"content":{"alias":"#upgrade-public:example.org"},"depth":4,"hashes":{"sha256":"AtPWemAN0xoJA3FQ4zN3a+LcfNHs9Lq/5LhFox/Wx30"},"origin_server_ts":1794844863502,"prev_events":["$PecG6aWhB2mDCM6YMk8crHbTdYzWkYUCN_ipzlMCjiI"],"room_id":"!WLDmyNQlQnw_RhR08m7Jk_JO2mbtD9pY5COByGjLODA","sender":"@alice:example.org","signatures":{"example.org":{"ed25519:76d6613f":"itC4d6HfjT7XS9dOyL5PyP8e0s7hv6EwfBHNT8oH8bHS70+Xo+Zt8jeRFYZtYsdm6DTqYRdiVTrDL6q6msvtAg"}},"state_key":"","type":"m.room.canonical_alias"}', '4', '22', 'accepted');
INSERT INTO public.events (event_id, room_id, sender_user_id, json, depth, stream_ordering, status) VALUES ('$V6yysmqZ0o9qaJiimEfXi0Ku7kIFtR9hCAC7vGSowuY', '!WLDmyNQlQnw_RhR08m7Jk_JO2mbtD9pY5COByGjLODA', '@alice:example.org', '{"auth_events":["$gEZRQzCXH4iD07nDrZYaWlyfDmS0tqK_R-gW6JyF32U","$PecG6aWhB2mDCM6YMk8crHbTdYzWkYUCN_ipzlMCjiI"],"content":{"join_rule":"public"},"depth":5,"hashes":{"sha256":"tlurMOyhg28NSfFRtQWAAG/PMbgA8PyNKNxhQ4Cfpwk"},"origin_server_ts":1794844863504,"prev_events":["$2oC-K1LNKA47eO1pqEmJrY0s6617pjOSdk68k5LiuZg"],"room_id":"!WLDmyNQlQnw_RhR08m7Jk_JO2mbtD9pY5COByGjLODA","sender":"@alice:example.org","signatures":{"example.org":{"ed25519:76d6613f":"20xjkZeHqAE/2mlNEwtqENmyEusYotibPGAPn0A3ntL90O1t33MYoyWHL9baYuHCglqtxIVPyAXYptllhVZxAA"}},"state_key":"","type":"m.room.join_rules"}', '5', '23', 'accepted');
INSERT INTO public.events (event_id, room_id, sender_user_id, json, depth, stream_ordering, status) VALUES ('$Lft2RjGrEuDUm8UkT3X25KYA1_81FeaFlJVeWLq8UdM', '!WLDmyNQlQnw_RhR08m7Jk_JO2mbtD9pY5COByGjLODA', '@alice:example.org', '{"auth_events":["$gEZRQzCXH4iD07nDrZYaWlyfDmS0tqK_R-gW6JyF32U","$PecG6aWhB2mDCM6YMk8crHbTdYzWkYUCN_ipzlMCjiI"],"content":{"history_visibility":"shared"},"depth":6,"hashes":{"sha256":"mdMuLqxz219YJ/n0NZRO685BByJ8U3pP1dXf8KV9dv8"},"origin_server_ts":1794844863507,"prev_events":["$V6yysmqZ0o9qaJiimEfXi0Ku7kIFtR9hCAC7vGSowuY"],"room_id":"!WLDmyNQlQnw_RhR08m7Jk_JO2mbtD9pY5COByGjLODA","sender":"@alice:example.org","signatures":{"example.org":{"ed25519:76d6613f":"tEAp2KuW8C+AVb18hpUq6FF3kQ1U75ayzWMPUx/DHPipAfajQ6MnQe8Ts3gqIo6MJg5ZXe9T6ASN2MPAQ7qFDg"}},"state_key":"","type":"m.room.history_visibility"}', '6', '24', 'accepted');
INSERT INTO public.events (event_id, room_id, sender_user_id, json, depth, stream_ordering, status) VALUES ('$MDEmZSZMMOOQUjEQxIXi05XzoHayhwFR6YRDMOykvoI', '!WLDmyNQlQnw_RhR08m7Jk_JO2mbtD9pY5COByGjLODA', '@alice:example.org', '{"auth_events":["$gEZRQzCXH4iD07nDrZYaWlyfDmS0tqK_R-gW6JyF32U","$PecG6aWhB2mDCM6YMk8crHbTdYzWkYUCN_ipzlMCjiI"],"content":{"guest_access":"forbidden"},"depth":7,"hashes":{"sha256":"inDn0YnyX8TXjn6JrzQSjTXUq1S4o5LOOqr66VRdIHo"},"origin_server_ts":1794844863509,"prev_events":["$Lft2RjGrEuDUm8UkT3X25KYA1_81FeaFlJVeWLq8UdM"],"room_id":"!WLDmyNQlQnw_RhR08m7Jk_JO2mbtD9pY5COByGjLODA","sender":"@alice:example.org","signatures":{"example.org":{"ed25519:76d6613f":"fB5PjFjkA/TR7+hXy8/+MQeWh5VRA+aGLS+6Q2zHL2pGCBLPS+cX1+jqlweSKifxGnWtOM8tPH6GZhZ3BFXDCw"}},"state_key":"","type":"m.room.guest_access"}', '7', '25', 'accepted');
INSERT INTO public.events (event_id, room_id, sender_user_id, json, depth, stream_ordering, status) VALUES ('$G6T266qKoHUbMYlVFKPN14wSCrqcj7ktb84OYLky32M', '!WLDmyNQlQnw_RhR08m7Jk_JO2mbtD9pY5COByGjLODA', '@alice:example.org', '{"auth_events":["$gEZRQzCXH4iD07nDrZYaWlyfDmS0tqK_R-gW6JyF32U","$PecG6aWhB2mDCM6YMk8crHbTdYzWkYUCN_ipzlMCjiI"],"content":{"name":"Upgrade Public"},"depth":8,"hashes":{"sha256":"qloB0h2f4DXFVXg3IEA5Kn83TU386BH5OIXAOJ7/D2U"},"origin_server_ts":1794844863512,"prev_events":["$MDEmZSZMMOOQUjEQxIXi05XzoHayhwFR6YRDMOykvoI"],"room_id":"!WLDmyNQlQnw_RhR08m7Jk_JO2mbtD9pY5COByGjLODA","sender":"@alice:example.org","signatures":{"example.org":{"ed25519:76d6613f":"yCI4HRCLRor9+l4NIlnbUWiiel/Fn1WhOMsSeRQVn9RTV3zOn2DAlTKaFDyTz8NeBM/B9hcb1UGLVtWDMBiGCQ"}},"state_key":"","type":"m.room.name"}', '8', '26', 'accepted');


--
-- Data for Name: fallback_keys; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: federation_destinations; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: federation_transactions; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: filters; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: forward_extremities; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.forward_extremities (room_id, event_id) VALUES ('!C7Cym0uRg_x2vckbuDPCwO4QgdsxfXpDiOi1WoH89NY', '$GcOCV1AahAZenbnTVGpvMmYTyB2XNFzhRLwjkRT0Cy8');
INSERT INTO public.forward_extremities (room_id, event_id) VALUES ('!WLDmyNQlQnw_RhR08m7Jk_JO2mbtD9pY5COByGjLODA', '$G6T266qKoHUbMYlVFKPN14wSCrqcj7ktb84OYLky32M');


--
-- Data for Name: invites; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: key_backup_sessions; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: key_backup_version_counters; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: key_backup_versions; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: key_backups; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: key_signatures; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: login_tokens; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: media; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.media (media_id, owner_user_id, content_type, size_bytes, hash_algorithm, digest, quarantined, removed, legacy_endpoint_visible, upload_name) VALUES ('eu-rBrEY7MSJKUy6o7pmMw', '@alice:example.org', 'text/plain', '340', 'blake2b', '9070012d53f92cf3bbfd1c8987cb29cf9ba6d7b9804e90883c9912e0e6c83288', 'false', 'false', 'false', 'upgrade-fixture.txt');


--
-- Data for Name: media_blobs; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.media_blobs (storage_id, hash_algorithm, digest, size_bytes, bytes, ref_count) VALUES ('blob_9070012d53f92cf3bbfd1c8987cb29cf9ba6d7b9804e90883c9912e0e6c83288_340', 'blake2b', '9070012d53f92cf3bbfd1c8987cb29cf9ba6d7b9804e90883c9912e0e6c83288', '340', '\x6d65726f76696e6769616e20757067726164652066697874757265206d656469610a6d65726f76696e6769616e20757067726164652066697874757265206d656469610a6d65726f76696e6769616e20757067726164652066697874757265206d656469610a6d65726f76696e6769616e20757067726164652066697874757265206d656469610a6d65726f76696e6769616e20757067726164652066697874757265206d656469610a6d65726f76696e6769616e20757067726164652066697874757265206d656469610a6d65726f76696e6769616e20757067726164652066697874757265206d656469610a6d65726f76696e6769616e20757067726164652066697874757265206d656469610a6d65726f76696e6769616e20757067726164652066697874757265206d656469610a6d65726f76696e6769616e20757067726164652066697874757265206d656469610a', '1');


--
-- Data for Name: media_pending_uploads; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: membership; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.membership (room_id, user_id, membership, stream_ordering) VALUES ('!C7Cym0uRg_x2vckbuDPCwO4QgdsxfXpDiOi1WoH89NY', '@alice:example.org', 'join', '3');
INSERT INTO public.membership (room_id, user_id, membership, stream_ordering) VALUES ('!C7Cym0uRg_x2vckbuDPCwO4QgdsxfXpDiOi1WoH89NY', '@bob:example.org', 'join', '13');
INSERT INTO public.membership (room_id, user_id, membership, stream_ordering) VALUES ('!WLDmyNQlQnw_RhR08m7Jk_JO2mbtD9pY5COByGjLODA', '@alice:example.org', 'join', '20');


--
-- Data for Name: notifications; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.notifications (user_id, room_id, event_id, stream_ordering, ts, actions, profile_tag, highlight) VALUES ('@bob:example.org', '!C7Cym0uRg_x2vckbuDPCwO4QgdsxfXpDiOi1WoH89NY', '$QzTeY37FC1XCBCS9k5WSqtd_ozVW1B45OBvMLOxOFRY', '10', '1794844863469', '["notify",{"set_tweak":"sound","value":"default"}]', '', 'false');
INSERT INTO public.notifications (user_id, room_id, event_id, stream_ordering, ts, actions, profile_tag, highlight) VALUES ('@bob:example.org', '!C7Cym0uRg_x2vckbuDPCwO4QgdsxfXpDiOi1WoH89NY', '$gbIXT6cBYsLvEAdCmvz_-Z-MLge4BnaLY_O1-PtdjGo', '14', '1794844863480', '["notify",{"set_tweak":"sound","value":"default"}]', '', 'false');
INSERT INTO public.notifications (user_id, room_id, event_id, stream_ordering, ts, actions, profile_tag, highlight) VALUES ('@bob:example.org', '!C7Cym0uRg_x2vckbuDPCwO4QgdsxfXpDiOi1WoH89NY', '$mC5T62vlKtDEaC4l1ujmOJ3dA5q-PM-ku8SS1xRZCek', '15', '1794844863484', '["notify",{"set_tweak":"sound","value":"default"}]', '', 'false');
INSERT INTO public.notifications (user_id, room_id, event_id, stream_ordering, ts, actions, profile_tag, highlight) VALUES ('@bob:example.org', '!C7Cym0uRg_x2vckbuDPCwO4QgdsxfXpDiOi1WoH89NY', '$h7M6qztmLUOCjFAmWrrrh-vd87KuCykZl7jvFLSK3Ds', '16', '1794844863488', '["notify",{"set_tweak":"sound","value":"default"}]', '', 'false');
INSERT INTO public.notifications (user_id, room_id, event_id, stream_ordering, ts, actions, profile_tag, highlight) VALUES ('@alice:example.org', '!C7Cym0uRg_x2vckbuDPCwO4QgdsxfXpDiOi1WoH89NY', '$GcOCV1AahAZenbnTVGpvMmYTyB2XNFzhRLwjkRT0Cy8', '17', '1794844863491', '["notify",{"set_tweak":"sound","value":"default"}]', '', 'false');


--
-- Data for Name: one_time_keys; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.one_time_keys (user_id, device_id, key_id, json) VALUES ('@alice:example.org', 'UPGRADE1', 'signed_curve25519:AAAAAQ', '{"key":"0kBH0U8cIYy+UylyqqSe4teHLhfX/hYBgpiZZlNp4zk","signatures":{"@alice:example.org":{"ed25519:UPGRADE1":"kAxIom4YQ7T7Q2laPSclXDUngDWrsn4yPReEKDnH+1YVJhB2s8Mdy3x4YtyxOMw8e1c/K6C2UeGeeSyOXuS6CA"}}}');


--
-- Data for Name: openid_tokens; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: policy_rules; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: presence_state; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.presence_state (user_id, stream_id, presence, status_msg, last_active_ago, currently_active) VALUES ('@alice:example.org', '11', 'online', '', '0', 'true');


--
-- Data for Name: profiles; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.profiles (user_id, displayname, avatar_url, fields_json) VALUES ('@bob:example.org', '', '', '{}');
INSERT INTO public.profiles (user_id, displayname, avatar_url, fields_json) VALUES ('@alice:example.org', 'Alice Upgrade', '', '{}');


--
-- Data for Name: push_rules; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: pushers; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.pushers (user_id, app_id, pushkey, kind, app_display_name, device_display_name, profile_tag, lang, data_url, data_format, data_extra_json, device_id) VALUES ('@alice:example.org', 'org.merovingian.upgrade', 'upgrade-pushkey', 'http', 'Upgrade Fixture App', 'Upgrade Fixture Device', '', 'en', 'https://push.example.org/_matrix/push/v1/notify', '', '', 'UPGRADE1');


--
-- Data for Name: rate_limits; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: receipts; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: refresh_tokens; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: remote_media; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: room_account_data; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: room_aliases; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.room_aliases (room_alias, room_id, creator_user_id) VALUES ('#upgrade-public:example.org', '!WLDmyNQlQnw_RhR08m7Jk_JO2mbtD9pY5COByGjLODA', '@alice:example.org');


--
-- Data for Name: room_versions; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: rooms; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.rooms (room_id, creator_user_id, directory_public) VALUES ('!C7Cym0uRg_x2vckbuDPCwO4QgdsxfXpDiOi1WoH89NY', '@alice:example.org', 'false');
INSERT INTO public.rooms (room_id, creator_user_id, directory_public) VALUES ('!WLDmyNQlQnw_RhR08m7Jk_JO2mbtD9pY5COByGjLODA', '@alice:example.org', 'true');


--
-- Data for Name: schema_migrations; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.schema_migrations (version, name, direction) VALUES ('1', 'initial_schema', 'upgrade');


--
-- Data for Name: server_signing_keys; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.server_signing_keys (server_name, key_id, public_key, valid_until_ts, secret_key, expired_ts) VALUES ('example.org', 'ed25519:76d6613f', 'dtZhP3rtHU2B+6kXQ1k+RAaRli8kwXxGvn41qUywvBs', '1795449662996', '\x736563726574626f783a76313a547949436e37714f635477584838525842785a542b7559504242395a44492f695973474c505a533072554c6963656d392b565a566b726143364d7972747532304d42324a586457696b7965304f3878316651524c4e484171364e46397530507530684b53504c556252454e395271423439454a334478524657724b6e6b4e69644665754566434b456c7851', '');


--
-- Data for Name: state_group_edges; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: state_group_state; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.state_group_state (state_group_id, event_type, state_key, event_id) VALUES ('sg:$C7Cym0uRg_x2vckbuDPCwO4QgdsxfXpDiOi1WoH89NY', 'm.room.create', '', '$C7Cym0uRg_x2vckbuDPCwO4QgdsxfXpDiOi1WoH89NY');
INSERT INTO public.state_group_state (state_group_id, event_type, state_key, event_id) VALUES ('sg:$iLFuDk8nVttbD9AqXn1viyXUEFEl_2DI7hsgkXGjXN8', 'm.room.member', '@alice:example.org', '$iLFuDk8nVttbD9AqXn1viyXUEFEl_2DI7hsgkXGjXN8');
INSERT INTO public.state_group_state (state_group_id, event_type, state_key, event_id) VALUES ('sg:$i5rP6Kab--xLmDcMSPRUZxvyQZcPThTiofJjfrSnDtg', 'm.room.power_levels', '', '$i5rP6Kab--xLmDcMSPRUZxvyQZcPThTiofJjfrSnDtg');
INSERT INTO public.state_group_state (state_group_id, event_type, state_key, event_id) VALUES ('sg:$v4aPwfsZiQ4yEz5-T0kS_DWvVTqUxPRltYSFV4P8Jlk', 'm.room.join_rules', '', '$v4aPwfsZiQ4yEz5-T0kS_DWvVTqUxPRltYSFV4P8Jlk');
INSERT INTO public.state_group_state (state_group_id, event_type, state_key, event_id) VALUES ('sg:$jQRkJoCECH7wDkXeK4PAzuiNM5N4-W-klgkSyuKI0Ig', 'm.room.history_visibility', '', '$jQRkJoCECH7wDkXeK4PAzuiNM5N4-W-klgkSyuKI0Ig');
INSERT INTO public.state_group_state (state_group_id, event_type, state_key, event_id) VALUES ('sg:$3DxD43IUhKnopg81UbujM_TWm14GdVq22XKXiThD5Bo', 'm.room.guest_access', '', '$3DxD43IUhKnopg81UbujM_TWm14GdVq22XKXiThD5Bo');
INSERT INTO public.state_group_state (state_group_id, event_type, state_key, event_id) VALUES ('sg:$LQujV90cKOa8fkPPU4PQX7sm6KL28V0r8nKCewBnOJ8', 'm.room.encryption', '', '$LQujV90cKOa8fkPPU4PQX7sm6KL28V0r8nKCewBnOJ8');
INSERT INTO public.state_group_state (state_group_id, event_type, state_key, event_id) VALUES ('sg:$RDqWCB4mWm4fTct25NtZAh5zmiUTG_EsgfQpCS2erxw', 'm.room.name', '', '$RDqWCB4mWm4fTct25NtZAh5zmiUTG_EsgfQpCS2erxw');
INSERT INTO public.state_group_state (state_group_id, event_type, state_key, event_id) VALUES ('sg:$QzTeY37FC1XCBCS9k5WSqtd_ozVW1B45OBvMLOxOFRY', 'm.room.member', '@bob:example.org', '$QzTeY37FC1XCBCS9k5WSqtd_ozVW1B45OBvMLOxOFRY');
INSERT INTO public.state_group_state (state_group_id, event_type, state_key, event_id) VALUES ('sg:$wVJJm-TLQ6il0h68B5rzA97t20lkmGMK7H0O6YdHEMM', 'm.room.member', '@bob:example.org', '$wVJJm-TLQ6il0h68B5rzA97t20lkmGMK7H0O6YdHEMM');
INSERT INTO public.state_group_state (state_group_id, event_type, state_key, event_id) VALUES ('sg:$WLDmyNQlQnw_RhR08m7Jk_JO2mbtD9pY5COByGjLODA', 'm.room.create', '', '$WLDmyNQlQnw_RhR08m7Jk_JO2mbtD9pY5COByGjLODA');
INSERT INTO public.state_group_state (state_group_id, event_type, state_key, event_id) VALUES ('sg:$gEZRQzCXH4iD07nDrZYaWlyfDmS0tqK_R-gW6JyF32U', 'm.room.member', '@alice:example.org', '$gEZRQzCXH4iD07nDrZYaWlyfDmS0tqK_R-gW6JyF32U');
INSERT INTO public.state_group_state (state_group_id, event_type, state_key, event_id) VALUES ('sg:$PecG6aWhB2mDCM6YMk8crHbTdYzWkYUCN_ipzlMCjiI', 'm.room.power_levels', '', '$PecG6aWhB2mDCM6YMk8crHbTdYzWkYUCN_ipzlMCjiI');
INSERT INTO public.state_group_state (state_group_id, event_type, state_key, event_id) VALUES ('sg:$2oC-K1LNKA47eO1pqEmJrY0s6617pjOSdk68k5LiuZg', 'm.room.canonical_alias', '', '$2oC-K1LNKA47eO1pqEmJrY0s6617pjOSdk68k5LiuZg');
INSERT INTO public.state_group_state (state_group_id, event_type, state_key, event_id) VALUES ('sg:$V6yysmqZ0o9qaJiimEfXi0Ku7kIFtR9hCAC7vGSowuY', 'm.room.join_rules', '', '$V6yysmqZ0o9qaJiimEfXi0Ku7kIFtR9hCAC7vGSowuY');
INSERT INTO public.state_group_state (state_group_id, event_type, state_key, event_id) VALUES ('sg:$Lft2RjGrEuDUm8UkT3X25KYA1_81FeaFlJVeWLq8UdM', 'm.room.history_visibility', '', '$Lft2RjGrEuDUm8UkT3X25KYA1_81FeaFlJVeWLq8UdM');
INSERT INTO public.state_group_state (state_group_id, event_type, state_key, event_id) VALUES ('sg:$MDEmZSZMMOOQUjEQxIXi05XzoHayhwFR6YRDMOykvoI', 'm.room.guest_access', '', '$MDEmZSZMMOOQUjEQxIXi05XzoHayhwFR6YRDMOykvoI');
INSERT INTO public.state_group_state (state_group_id, event_type, state_key, event_id) VALUES ('sg:$G6T266qKoHUbMYlVFKPN14wSCrqcj7ktb84OYLky32M', 'm.room.name', '', '$G6T266qKoHUbMYlVFKPN14wSCrqcj7ktb84OYLky32M');


--
-- Data for Name: state_groups; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.state_groups (state_group_id, room_id, parent_state_group_id, delta_depth) VALUES ('sg:$C7Cym0uRg_x2vckbuDPCwO4QgdsxfXpDiOi1WoH89NY', '!C7Cym0uRg_x2vckbuDPCwO4QgdsxfXpDiOi1WoH89NY', '', '0');
INSERT INTO public.state_groups (state_group_id, room_id, parent_state_group_id, delta_depth) VALUES ('sg:$iLFuDk8nVttbD9AqXn1viyXUEFEl_2DI7hsgkXGjXN8', '!C7Cym0uRg_x2vckbuDPCwO4QgdsxfXpDiOi1WoH89NY', 'sg:$C7Cym0uRg_x2vckbuDPCwO4QgdsxfXpDiOi1WoH89NY', '1');
INSERT INTO public.state_groups (state_group_id, room_id, parent_state_group_id, delta_depth) VALUES ('sg:$i5rP6Kab--xLmDcMSPRUZxvyQZcPThTiofJjfrSnDtg', '!C7Cym0uRg_x2vckbuDPCwO4QgdsxfXpDiOi1WoH89NY', 'sg:$iLFuDk8nVttbD9AqXn1viyXUEFEl_2DI7hsgkXGjXN8', '2');
INSERT INTO public.state_groups (state_group_id, room_id, parent_state_group_id, delta_depth) VALUES ('sg:$v4aPwfsZiQ4yEz5-T0kS_DWvVTqUxPRltYSFV4P8Jlk', '!C7Cym0uRg_x2vckbuDPCwO4QgdsxfXpDiOi1WoH89NY', 'sg:$i5rP6Kab--xLmDcMSPRUZxvyQZcPThTiofJjfrSnDtg', '3');
INSERT INTO public.state_groups (state_group_id, room_id, parent_state_group_id, delta_depth) VALUES ('sg:$jQRkJoCECH7wDkXeK4PAzuiNM5N4-W-klgkSyuKI0Ig', '!C7Cym0uRg_x2vckbuDPCwO4QgdsxfXpDiOi1WoH89NY', 'sg:$v4aPwfsZiQ4yEz5-T0kS_DWvVTqUxPRltYSFV4P8Jlk', '4');
INSERT INTO public.state_groups (state_group_id, room_id, parent_state_group_id, delta_depth) VALUES ('sg:$3DxD43IUhKnopg81UbujM_TWm14GdVq22XKXiThD5Bo', '!C7Cym0uRg_x2vckbuDPCwO4QgdsxfXpDiOi1WoH89NY', 'sg:$jQRkJoCECH7wDkXeK4PAzuiNM5N4-W-klgkSyuKI0Ig', '5');
INSERT INTO public.state_groups (state_group_id, room_id, parent_state_group_id, delta_depth) VALUES ('sg:$LQujV90cKOa8fkPPU4PQX7sm6KL28V0r8nKCewBnOJ8', '!C7Cym0uRg_x2vckbuDPCwO4QgdsxfXpDiOi1WoH89NY', 'sg:$3DxD43IUhKnopg81UbujM_TWm14GdVq22XKXiThD5Bo', '6');
INSERT INTO public.state_groups (state_group_id, room_id, parent_state_group_id, delta_depth) VALUES ('sg:$RDqWCB4mWm4fTct25NtZAh5zmiUTG_EsgfQpCS2erxw', '!C7Cym0uRg_x2vckbuDPCwO4QgdsxfXpDiOi1WoH89NY', 'sg:$LQujV90cKOa8fkPPU4PQX7sm6KL28V0r8nKCewBnOJ8', '7');
INSERT INTO public.state_groups (state_group_id, room_id, parent_state_group_id, delta_depth) VALUES ('sg:$QzTeY37FC1XCBCS9k5WSqtd_ozVW1B45OBvMLOxOFRY', '!C7Cym0uRg_x2vckbuDPCwO4QgdsxfXpDiOi1WoH89NY', 'sg:$RDqWCB4mWm4fTct25NtZAh5zmiUTG_EsgfQpCS2erxw', '8');
INSERT INTO public.state_groups (state_group_id, room_id, parent_state_group_id, delta_depth) VALUES ('sg:$wVJJm-TLQ6il0h68B5rzA97t20lkmGMK7H0O6YdHEMM', '!C7Cym0uRg_x2vckbuDPCwO4QgdsxfXpDiOi1WoH89NY', 'sg:$QzTeY37FC1XCBCS9k5WSqtd_ozVW1B45OBvMLOxOFRY', '9');
INSERT INTO public.state_groups (state_group_id, room_id, parent_state_group_id, delta_depth) VALUES ('sg:$WLDmyNQlQnw_RhR08m7Jk_JO2mbtD9pY5COByGjLODA', '!WLDmyNQlQnw_RhR08m7Jk_JO2mbtD9pY5COByGjLODA', '', '0');
INSERT INTO public.state_groups (state_group_id, room_id, parent_state_group_id, delta_depth) VALUES ('sg:$gEZRQzCXH4iD07nDrZYaWlyfDmS0tqK_R-gW6JyF32U', '!WLDmyNQlQnw_RhR08m7Jk_JO2mbtD9pY5COByGjLODA', 'sg:$WLDmyNQlQnw_RhR08m7Jk_JO2mbtD9pY5COByGjLODA', '1');
INSERT INTO public.state_groups (state_group_id, room_id, parent_state_group_id, delta_depth) VALUES ('sg:$PecG6aWhB2mDCM6YMk8crHbTdYzWkYUCN_ipzlMCjiI', '!WLDmyNQlQnw_RhR08m7Jk_JO2mbtD9pY5COByGjLODA', 'sg:$gEZRQzCXH4iD07nDrZYaWlyfDmS0tqK_R-gW6JyF32U', '2');
INSERT INTO public.state_groups (state_group_id, room_id, parent_state_group_id, delta_depth) VALUES ('sg:$2oC-K1LNKA47eO1pqEmJrY0s6617pjOSdk68k5LiuZg', '!WLDmyNQlQnw_RhR08m7Jk_JO2mbtD9pY5COByGjLODA', 'sg:$PecG6aWhB2mDCM6YMk8crHbTdYzWkYUCN_ipzlMCjiI', '3');
INSERT INTO public.state_groups (state_group_id, room_id, parent_state_group_id, delta_depth) VALUES ('sg:$V6yysmqZ0o9qaJiimEfXi0Ku7kIFtR9hCAC7vGSowuY', '!WLDmyNQlQnw_RhR08m7Jk_JO2mbtD9pY5COByGjLODA', 'sg:$2oC-K1LNKA47eO1pqEmJrY0s6617pjOSdk68k5LiuZg', '4');
INSERT INTO public.state_groups (state_group_id, room_id, parent_state_group_id, delta_depth) VALUES ('sg:$Lft2RjGrEuDUm8UkT3X25KYA1_81FeaFlJVeWLq8UdM', '!WLDmyNQlQnw_RhR08m7Jk_JO2mbtD9pY5COByGjLODA', 'sg:$V6yysmqZ0o9qaJiimEfXi0Ku7kIFtR9hCAC7vGSowuY', '5');
INSERT INTO public.state_groups (state_group_id, room_id, parent_state_group_id, delta_depth) VALUES ('sg:$MDEmZSZMMOOQUjEQxIXi05XzoHayhwFR6YRDMOykvoI', '!WLDmyNQlQnw_RhR08m7Jk_JO2mbtD9pY5COByGjLODA', 'sg:$Lft2RjGrEuDUm8UkT3X25KYA1_81FeaFlJVeWLq8UdM', '6');
INSERT INTO public.state_groups (state_group_id, room_id, parent_state_group_id, delta_depth) VALUES ('sg:$G6T266qKoHUbMYlVFKPN14wSCrqcj7ktb84OYLky32M', '!WLDmyNQlQnw_RhR08m7Jk_JO2mbtD9pY5COByGjLODA', 'sg:$MDEmZSZMMOOQUjEQxIXi05XzoHayhwFR6YRDMOykvoI', '7');


--
-- Data for Name: state_transitions; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.state_transitions (room_id, event_type, state_key, event_id, previous_event_id) VALUES ('!C7Cym0uRg_x2vckbuDPCwO4QgdsxfXpDiOi1WoH89NY', 'm.room.create', '', '$C7Cym0uRg_x2vckbuDPCwO4QgdsxfXpDiOi1WoH89NY', '');
INSERT INTO public.state_transitions (room_id, event_type, state_key, event_id, previous_event_id) VALUES ('!C7Cym0uRg_x2vckbuDPCwO4QgdsxfXpDiOi1WoH89NY', 'm.room.member', '@alice:example.org', '$iLFuDk8nVttbD9AqXn1viyXUEFEl_2DI7hsgkXGjXN8', '');
INSERT INTO public.state_transitions (room_id, event_type, state_key, event_id, previous_event_id) VALUES ('!C7Cym0uRg_x2vckbuDPCwO4QgdsxfXpDiOi1WoH89NY', 'm.room.power_levels', '', '$i5rP6Kab--xLmDcMSPRUZxvyQZcPThTiofJjfrSnDtg', '');
INSERT INTO public.state_transitions (room_id, event_type, state_key, event_id, previous_event_id) VALUES ('!C7Cym0uRg_x2vckbuDPCwO4QgdsxfXpDiOi1WoH89NY', 'm.room.join_rules', '', '$v4aPwfsZiQ4yEz5-T0kS_DWvVTqUxPRltYSFV4P8Jlk', '');
INSERT INTO public.state_transitions (room_id, event_type, state_key, event_id, previous_event_id) VALUES ('!C7Cym0uRg_x2vckbuDPCwO4QgdsxfXpDiOi1WoH89NY', 'm.room.history_visibility', '', '$jQRkJoCECH7wDkXeK4PAzuiNM5N4-W-klgkSyuKI0Ig', '');
INSERT INTO public.state_transitions (room_id, event_type, state_key, event_id, previous_event_id) VALUES ('!C7Cym0uRg_x2vckbuDPCwO4QgdsxfXpDiOi1WoH89NY', 'm.room.guest_access', '', '$3DxD43IUhKnopg81UbujM_TWm14GdVq22XKXiThD5Bo', '');
INSERT INTO public.state_transitions (room_id, event_type, state_key, event_id, previous_event_id) VALUES ('!C7Cym0uRg_x2vckbuDPCwO4QgdsxfXpDiOi1WoH89NY', 'm.room.encryption', '', '$LQujV90cKOa8fkPPU4PQX7sm6KL28V0r8nKCewBnOJ8', '');
INSERT INTO public.state_transitions (room_id, event_type, state_key, event_id, previous_event_id) VALUES ('!C7Cym0uRg_x2vckbuDPCwO4QgdsxfXpDiOi1WoH89NY', 'm.room.name', '', '$RDqWCB4mWm4fTct25NtZAh5zmiUTG_EsgfQpCS2erxw', '');
INSERT INTO public.state_transitions (room_id, event_type, state_key, event_id, previous_event_id) VALUES ('!C7Cym0uRg_x2vckbuDPCwO4QgdsxfXpDiOi1WoH89NY', 'm.room.member', '@bob:example.org', '$QzTeY37FC1XCBCS9k5WSqtd_ozVW1B45OBvMLOxOFRY', '');
INSERT INTO public.state_transitions (room_id, event_type, state_key, event_id, previous_event_id) VALUES ('!C7Cym0uRg_x2vckbuDPCwO4QgdsxfXpDiOi1WoH89NY', 'm.room.member', '@bob:example.org', '$wVJJm-TLQ6il0h68B5rzA97t20lkmGMK7H0O6YdHEMM', '$QzTeY37FC1XCBCS9k5WSqtd_ozVW1B45OBvMLOxOFRY');
INSERT INTO public.state_transitions (room_id, event_type, state_key, event_id, previous_event_id) VALUES ('!WLDmyNQlQnw_RhR08m7Jk_JO2mbtD9pY5COByGjLODA', 'm.room.create', '', '$WLDmyNQlQnw_RhR08m7Jk_JO2mbtD9pY5COByGjLODA', '');
INSERT INTO public.state_transitions (room_id, event_type, state_key, event_id, previous_event_id) VALUES ('!WLDmyNQlQnw_RhR08m7Jk_JO2mbtD9pY5COByGjLODA', 'm.room.member', '@alice:example.org', '$gEZRQzCXH4iD07nDrZYaWlyfDmS0tqK_R-gW6JyF32U', '');
INSERT INTO public.state_transitions (room_id, event_type, state_key, event_id, previous_event_id) VALUES ('!WLDmyNQlQnw_RhR08m7Jk_JO2mbtD9pY5COByGjLODA', 'm.room.power_levels', '', '$PecG6aWhB2mDCM6YMk8crHbTdYzWkYUCN_ipzlMCjiI', '');
INSERT INTO public.state_transitions (room_id, event_type, state_key, event_id, previous_event_id) VALUES ('!WLDmyNQlQnw_RhR08m7Jk_JO2mbtD9pY5COByGjLODA', 'm.room.canonical_alias', '', '$2oC-K1LNKA47eO1pqEmJrY0s6617pjOSdk68k5LiuZg', '');
INSERT INTO public.state_transitions (room_id, event_type, state_key, event_id, previous_event_id) VALUES ('!WLDmyNQlQnw_RhR08m7Jk_JO2mbtD9pY5COByGjLODA', 'm.room.join_rules', '', '$V6yysmqZ0o9qaJiimEfXi0Ku7kIFtR9hCAC7vGSowuY', '');
INSERT INTO public.state_transitions (room_id, event_type, state_key, event_id, previous_event_id) VALUES ('!WLDmyNQlQnw_RhR08m7Jk_JO2mbtD9pY5COByGjLODA', 'm.room.history_visibility', '', '$Lft2RjGrEuDUm8UkT3X25KYA1_81FeaFlJVeWLq8UdM', '');
INSERT INTO public.state_transitions (room_id, event_type, state_key, event_id, previous_event_id) VALUES ('!WLDmyNQlQnw_RhR08m7Jk_JO2mbtD9pY5COByGjLODA', 'm.room.guest_access', '', '$MDEmZSZMMOOQUjEQxIXi05XzoHayhwFR6YRDMOykvoI', '');
INSERT INTO public.state_transitions (room_id, event_type, state_key, event_id, previous_event_id) VALUES ('!WLDmyNQlQnw_RhR08m7Jk_JO2mbtD9pY5COByGjLODA', 'm.room.name', '', '$G6T266qKoHUbMYlVFKPN14wSCrqcj7ktb84OYLky32M', '');


--
-- Data for Name: stream_token_epoch; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.stream_token_epoch (singleton, epoch) VALUES (1, '16567766508683932441');


--
-- Data for Name: sync_stream_watermark; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.sync_stream_watermark (singleton, watermark) VALUES (1, '11');


--
-- Data for Name: to_device_messages; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: users; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.users (user_id, password_hash, locked, suspended, admin, deactivated) VALUES ('@alice:example.org', 'password-hash:v2:$argon2id$v=19$m=65536,t=2,p=1$BZ7AtwwKDlS7ACuBTaSqRQ$XMFrVx+V7GGaglCHcA/1Mgjsi/uugNpiLnUEzc0YLhE', 'false', 'false', 'false', 'false');
INSERT INTO public.users (user_id, password_hash, locked, suspended, admin, deactivated) VALUES ('@bob:example.org', 'password-hash:v2:$argon2id$v=19$m=65536,t=2,p=1$jshxQqXojCFoET4WBT2BbA$jT1sZbXil+kpLLG3uDqhY9U4ZAIe5UEASLUYOsIByg0', 'false', 'false', 'false', 'false');


--
-- Name: access_tokens access_tokens_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.access_tokens
    ADD CONSTRAINT access_tokens_pkey PRIMARY KEY (token_hash);


--
-- Name: account_data account_data_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.account_data
    ADD CONSTRAINT account_data_pkey PRIMARY KEY (user_id, event_type);


--
-- Name: account_threepids account_threepids_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.account_threepids
    ADD CONSTRAINT account_threepids_pkey PRIMARY KEY (user_id, medium, address);


--
-- Name: appservice_directory appservice_directory_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.appservice_directory
    ADD CONSTRAINT appservice_directory_pkey PRIMARY KEY (appservice_id, network_id, room_id);


--
-- Name: appservice_outbox appservice_outbox_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.appservice_outbox
    ADD CONSTRAINT appservice_outbox_pkey PRIMARY KEY (appservice_id, stream_ordering);


--
-- Name: appservice_txn_cursor appservice_txn_cursor_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.appservice_txn_cursor
    ADD CONSTRAINT appservice_txn_cursor_pkey PRIMARY KEY (appservice_id);


--
-- Name: client_txn_ids client_txn_ids_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.client_txn_ids
    ADD CONSTRAINT client_txn_ids_pkey PRIMARY KEY (user_id, device_id, room_id, event_type, txn_id);


--
-- Name: cross_signing_keys cross_signing_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cross_signing_keys
    ADD CONSTRAINT cross_signing_keys_pkey PRIMARY KEY (user_id, key_type);


--
-- Name: current_state current_state_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.current_state
    ADD CONSTRAINT current_state_pkey PRIMARY KEY (room_id, event_type, state_key);


--
-- Name: deferred_pdus deferred_pdus_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.deferred_pdus
    ADD CONSTRAINT deferred_pdus_pkey PRIMARY KEY (event_id);


--
-- Name: device_keys device_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.device_keys
    ADD CONSTRAINT device_keys_pkey PRIMARY KEY (user_id, device_id);


--
-- Name: device_list_changes device_list_changes_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.device_list_changes
    ADD CONSTRAINT device_list_changes_pkey PRIMARY KEY (stream_id, observer_user_id, subject_user_id);


--
-- Name: devices devices_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.devices
    ADD CONSTRAINT devices_pkey PRIMARY KEY (user_id, device_id);


--
-- Name: event_auth event_auth_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.event_auth
    ADD CONSTRAINT event_auth_pkey PRIMARY KEY (event_id, auth_event_id);


--
-- Name: event_edges event_edges_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.event_edges
    ADD CONSTRAINT event_edges_pkey PRIMARY KEY (event_id, prev_event_id);


--
-- Name: event_json event_json_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.event_json
    ADD CONSTRAINT event_json_pkey PRIMARY KEY (event_id);


--
-- Name: event_signatures event_signatures_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.event_signatures
    ADD CONSTRAINT event_signatures_pkey PRIMARY KEY (event_id, server_name, key_id);


--
-- Name: event_state_groups event_state_groups_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.event_state_groups
    ADD CONSTRAINT event_state_groups_pkey PRIMARY KEY (event_id);


--
-- Name: event_stream_watermark event_stream_watermark_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.event_stream_watermark
    ADD CONSTRAINT event_stream_watermark_pkey PRIMARY KEY (singleton);


--
-- Name: events events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.events
    ADD CONSTRAINT events_pkey PRIMARY KEY (event_id);


--
-- Name: fallback_keys fallback_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.fallback_keys
    ADD CONSTRAINT fallback_keys_pkey PRIMARY KEY (user_id, device_id, key_id);


--
-- Name: federation_destinations federation_destinations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.federation_destinations
    ADD CONSTRAINT federation_destinations_pkey PRIMARY KEY (server_name);


--
-- Name: federation_transactions federation_transactions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.federation_transactions
    ADD CONSTRAINT federation_transactions_pkey PRIMARY KEY (transaction_id);


--
-- Name: filters filters_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.filters
    ADD CONSTRAINT filters_pkey PRIMARY KEY (user_id, filter_id);


--
-- Name: forward_extremities forward_extremities_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.forward_extremities
    ADD CONSTRAINT forward_extremities_pkey PRIMARY KEY (room_id, event_id);


--
-- Name: invites invites_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.invites
    ADD CONSTRAINT invites_pkey PRIMARY KEY (room_id, user_id);


--
-- Name: key_backup_sessions key_backup_sessions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.key_backup_sessions
    ADD CONSTRAINT key_backup_sessions_pkey PRIMARY KEY (user_id, version, room_id, session_id);


--
-- Name: key_backup_version_counters key_backup_version_counters_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.key_backup_version_counters
    ADD CONSTRAINT key_backup_version_counters_pkey PRIMARY KEY (user_id);


--
-- Name: key_backup_versions key_backup_versions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.key_backup_versions
    ADD CONSTRAINT key_backup_versions_pkey PRIMARY KEY (user_id, version);


--
-- Name: key_backups key_backups_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.key_backups
    ADD CONSTRAINT key_backups_pkey PRIMARY KEY (user_id, version);


--
-- Name: key_signatures key_signatures_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.key_signatures
    ADD CONSTRAINT key_signatures_pkey PRIMARY KEY (signer_user_id, target_user_id, target_device_id);


--
-- Name: login_tokens login_tokens_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.login_tokens
    ADD CONSTRAINT login_tokens_pkey PRIMARY KEY (token_hash);


--
-- Name: media_blobs media_blobs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.media_blobs
    ADD CONSTRAINT media_blobs_pkey PRIMARY KEY (storage_id);


--
-- Name: media_pending_uploads media_pending_uploads_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.media_pending_uploads
    ADD CONSTRAINT media_pending_uploads_pkey PRIMARY KEY (media_id);


--
-- Name: media media_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.media
    ADD CONSTRAINT media_pkey PRIMARY KEY (media_id);


--
-- Name: membership membership_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.membership
    ADD CONSTRAINT membership_pkey PRIMARY KEY (room_id, user_id);


--
-- Name: notifications notifications_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.notifications
    ADD CONSTRAINT notifications_pkey PRIMARY KEY (user_id, event_id);


--
-- Name: one_time_keys one_time_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.one_time_keys
    ADD CONSTRAINT one_time_keys_pkey PRIMARY KEY (user_id, device_id, key_id);


--
-- Name: openid_tokens openid_tokens_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.openid_tokens
    ADD CONSTRAINT openid_tokens_pkey PRIMARY KEY (token_hash);


--
-- Name: policy_rules policy_rules_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.policy_rules
    ADD CONSTRAINT policy_rules_pkey PRIMARY KEY (rule_id);


--
-- Name: presence_state presence_state_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.presence_state
    ADD CONSTRAINT presence_state_pkey PRIMARY KEY (user_id);


--
-- Name: profiles profiles_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.profiles
    ADD CONSTRAINT profiles_pkey PRIMARY KEY (user_id);


--
-- Name: push_rules push_rules_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.push_rules
    ADD CONSTRAINT push_rules_pkey PRIMARY KEY (user_id, rule_id);


--
-- Name: pushers pushers_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.pushers
    ADD CONSTRAINT pushers_pkey PRIMARY KEY (user_id, app_id, pushkey);


--
-- Name: rate_limits rate_limits_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.rate_limits
    ADD CONSTRAINT rate_limits_pkey PRIMARY KEY (scope, key);


--
-- Name: receipts receipts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.receipts
    ADD CONSTRAINT receipts_pkey PRIMARY KEY (room_id, receipt_type, user_id, thread_id);


--
-- Name: refresh_tokens refresh_tokens_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.refresh_tokens
    ADD CONSTRAINT refresh_tokens_pkey PRIMARY KEY (token_hash);


--
-- Name: remote_media remote_media_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.remote_media
    ADD CONSTRAINT remote_media_pkey PRIMARY KEY (server_name, media_id);


--
-- Name: room_account_data room_account_data_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.room_account_data
    ADD CONSTRAINT room_account_data_pkey PRIMARY KEY (user_id, room_id, event_type);


--
-- Name: room_aliases room_aliases_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.room_aliases
    ADD CONSTRAINT room_aliases_pkey PRIMARY KEY (room_alias);


--
-- Name: room_versions room_versions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.room_versions
    ADD CONSTRAINT room_versions_pkey PRIMARY KEY (room_id);


--
-- Name: rooms rooms_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.rooms
    ADD CONSTRAINT rooms_pkey PRIMARY KEY (room_id);


--
-- Name: schema_migrations schema_migrations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.schema_migrations
    ADD CONSTRAINT schema_migrations_pkey PRIMARY KEY (version);


--
-- Name: server_signing_keys server_signing_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.server_signing_keys
    ADD CONSTRAINT server_signing_keys_pkey PRIMARY KEY (server_name, key_id);


--
-- Name: state_group_edges state_group_edges_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.state_group_edges
    ADD CONSTRAINT state_group_edges_pkey PRIMARY KEY (state_group_id, prev_state_group_id);


--
-- Name: state_group_state state_group_state_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.state_group_state
    ADD CONSTRAINT state_group_state_pkey PRIMARY KEY (state_group_id, event_type, state_key);


--
-- Name: state_groups state_groups_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.state_groups
    ADD CONSTRAINT state_groups_pkey PRIMARY KEY (state_group_id);


--
-- Name: state_transitions state_transitions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.state_transitions
    ADD CONSTRAINT state_transitions_pkey PRIMARY KEY (room_id, event_type, state_key, event_id);


--
-- Name: stream_token_epoch stream_token_epoch_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.stream_token_epoch
    ADD CONSTRAINT stream_token_epoch_pkey PRIMARY KEY (singleton);


--
-- Name: sync_stream_watermark sync_stream_watermark_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sync_stream_watermark
    ADD CONSTRAINT sync_stream_watermark_pkey PRIMARY KEY (singleton);


--
-- Name: to_device_messages to_device_messages_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.to_device_messages
    ADD CONSTRAINT to_device_messages_pkey PRIMARY KEY (stream_id, target_user_id, target_device_id);


--
-- Name: users users_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (user_id);


--
-- Name: event_edges_prev_event_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX event_edges_prev_event_id ON public.event_edges USING btree (prev_event_id);


--
-- Name: idx_access_tokens_user_device; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_access_tokens_user_device ON public.access_tokens USING btree (user_id, device_id);


--
-- Name: idx_deferred_pdus_room_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_deferred_pdus_room_id ON public.deferred_pdus USING btree (room_id);


--
-- Name: idx_events_room_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_events_room_id ON public.events USING btree (room_id);


--
-- Name: idx_media_pending_uploads_owner; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_media_pending_uploads_owner ON public.media_pending_uploads USING btree (owner_user_id);


--
-- Name: idx_refresh_tokens_predecessor; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_refresh_tokens_predecessor ON public.refresh_tokens USING btree (predecessor_hash);


--
-- Name: idx_refresh_tokens_user_device; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_refresh_tokens_user_device ON public.refresh_tokens USING btree (user_id, device_id);


--
-- Name: idx_state_groups_room_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_state_groups_room_id ON public.state_groups USING btree (room_id);


--
-- Name: idx_to_device_messages_recipient_age; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_to_device_messages_recipient_age ON public.to_device_messages USING btree (target_user_id, target_device_id, created_at_ms);


--
-- Name: key_backup_sessions key_backup_sessions_user_id_version_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.key_backup_sessions
    ADD CONSTRAINT key_backup_sessions_user_id_version_fkey FOREIGN KEY (user_id, version) REFERENCES public.key_backup_versions(user_id, version) ON DELETE CASCADE;


--
-- PostgreSQL database dump complete
--


