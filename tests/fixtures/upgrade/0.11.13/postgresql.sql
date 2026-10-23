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
    expires_at text DEFAULT ''::text NOT NULL
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
-- Name: audit_log; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.audit_log (
    category text NOT NULL,
    event_type text NOT NULL,
    actor text NOT NULL,
    target text NOT NULL,
    reason text NOT NULL
);


--
-- Name: client_txn_ids; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.client_txn_ids (
    user_id text NOT NULL,
    room_id text NOT NULL,
    event_type text NOT NULL,
    txn_id text NOT NULL,
    event_id text NOT NULL
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
    stream_ordering text DEFAULT '0'::text NOT NULL
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
-- Name: invites; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.invites (
    room_id text NOT NULL,
    user_id text NOT NULL,
    sender_user_id text NOT NULL,
    event_id text DEFAULT ''::text NOT NULL,
    signed_event_json text DEFAULT ''::text NOT NULL,
    invite_state_json text DEFAULT '[]'::text NOT NULL,
    stream_ordering text DEFAULT '0'::text NOT NULL
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
    removed text NOT NULL
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
    avatar_url text DEFAULT ''::text NOT NULL
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
    data_extra_json text DEFAULT ''::text NOT NULL
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
-- Name: refresh_tokens; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.refresh_tokens (
    token_hash text NOT NULL,
    user_id text NOT NULL,
    device_id text NOT NULL,
    revoked text NOT NULL,
    expires_at text DEFAULT ''::text NOT NULL
);


--
-- Name: remote_media; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.remote_media (
    server_name text NOT NULL,
    media_id text NOT NULL,
    content_type text NOT NULL,
    size_bytes text NOT NULL,
    quarantined text NOT NULL
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
    room_id text NOT NULL
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
    creator_user_id text NOT NULL
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
    secret_key bytea DEFAULT '\x'::bytea NOT NULL
);


--
-- Name: state_group_edges; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.state_group_edges (
    state_group_id text NOT NULL,
    prev_state_group_id text NOT NULL
);


--
-- Name: state_groups; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.state_groups (
    state_group_id text NOT NULL,
    room_id text NOT NULL
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
    content text NOT NULL
);


--
-- Name: users; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.users (
    user_id text NOT NULL,
    password_hash text NOT NULL,
    locked text NOT NULL,
    suspended text NOT NULL,
    admin text NOT NULL
);


--
-- Data for Name: access_tokens; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.access_tokens (user_id, device_id, token_hash, revoked, expires_at) VALUES ('@alice:example.org', 'UPGRADE1', 'token-hash:v4:5b3e79a9ed77c1a1e1d2993d00161e25b2dc6dcf417083445ee5d8fc3e2588f9', 'false', '');
INSERT INTO public.access_tokens (user_id, device_id, token_hash, revoked, expires_at) VALUES ('@bob:example.org', 'UPGRADE2', 'token-hash:v4:e9e6bf219ffd9d63e8a79e67bd11f0e1fd7e8ccdcd33b2e98ea3244aad0644fe', 'false', '');


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
-- Data for Name: audit_log; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.audit_log (category, event_type, actor, target, reason) VALUES ('admin', 'runtime.started', 'server', 'homeserver', 'startup');
INSERT INTO public.audit_log (category, event_type, actor, target, reason) VALUES ('admin', 'runtime.started', 'server', 'homeserver', 'startup');
INSERT INTO public.audit_log (category, event_type, actor, target, reason) VALUES ('auth', 'auth.user_registered', '@alice:example.org', '@alice:example.org', 'created');
INSERT INTO public.audit_log (category, event_type, actor, target, reason) VALUES ('auth', 'auth.login', '@alice:example.org', 'UPGRADE1', 'accepted');
INSERT INTO public.audit_log (category, event_type, actor, target, reason) VALUES ('auth', 'auth.user_registered', '@bob:example.org', '@bob:example.org', 'created');
INSERT INTO public.audit_log (category, event_type, actor, target, reason) VALUES ('auth', 'auth.login', '@bob:example.org', 'UPGRADE2', 'accepted');
INSERT INTO public.audit_log (category, event_type, actor, target, reason) VALUES ('admin', 'room.created', '@alice:example.org', '!PW80ohbgl9Y-TuRoQMsk1IQrNVbWabrWmKGlGXaEuas', 'created');
INSERT INTO public.audit_log (category, event_type, actor, target, reason) VALUES ('admin', 'room.invited', '@alice:example.org', '@bob:example.org', '!PW80ohbgl9Y-TuRoQMsk1IQrNVbWabrWmKGlGXaEuas');
INSERT INTO public.audit_log (category, event_type, actor, target, reason) VALUES ('admin', 'room.joined', '@bob:example.org', '!PW80ohbgl9Y-TuRoQMsk1IQrNVbWabrWmKGlGXaEuas', 'joined');
INSERT INTO public.audit_log (category, event_type, actor, target, reason) VALUES ('admin', 'room.event_sent', '@alice:example.org', '!PW80ohbgl9Y-TuRoQMsk1IQrNVbWabrWmKGlGXaEuas', 'stored');
INSERT INTO public.audit_log (category, event_type, actor, target, reason) VALUES ('admin', 'room.event_sent', '@alice:example.org', '!PW80ohbgl9Y-TuRoQMsk1IQrNVbWabrWmKGlGXaEuas', 'stored');
INSERT INTO public.audit_log (category, event_type, actor, target, reason) VALUES ('admin', 'room.event_sent', '@alice:example.org', '!PW80ohbgl9Y-TuRoQMsk1IQrNVbWabrWmKGlGXaEuas', 'stored');
INSERT INTO public.audit_log (category, event_type, actor, target, reason) VALUES ('admin', 'room.event_sent', '@bob:example.org', '!PW80ohbgl9Y-TuRoQMsk1IQrNVbWabrWmKGlGXaEuas', 'stored');
INSERT INTO public.audit_log (category, event_type, actor, target, reason) VALUES ('admin', 'room.created', '@alice:example.org', '!Ic8TlLD2IJRkiuVOQLk3Sa2aMgGqQqAh0lCVfPvuopM', 'created');
INSERT INTO public.audit_log (category, event_type, actor, target, reason) VALUES ('moderation', 'media.upload_accepted', '@alice:example.org', 'm1_9070012d53f9', 'stored');
INSERT INTO public.audit_log (category, event_type, actor, target, reason) VALUES ('auth', 'key_api.upload_keys', '@alice:example.org', 'UPGRADE1', '[key-payload:redacted:length=697]');


--
-- Data for Name: client_txn_ids; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.client_txn_ids (user_id, room_id, event_type, txn_id, event_id) VALUES ('@alice:example.org', '!PW80ohbgl9Y-TuRoQMsk1IQrNVbWabrWmKGlGXaEuas', 'm.room.message', 'upgrade-txn-1', '$LV4ggre4BtqcB7IaQzzNVhNlikCp0kBd7moi5iROKfo');
INSERT INTO public.client_txn_ids (user_id, room_id, event_type, txn_id, event_id) VALUES ('@alice:example.org', '!PW80ohbgl9Y-TuRoQMsk1IQrNVbWabrWmKGlGXaEuas', 'm.room.message', 'upgrade-txn-2', '$Z0ytL9BlIFISIxrt2eTCRTJ7R7f42onZZRbe_2ImK5M');
INSERT INTO public.client_txn_ids (user_id, room_id, event_type, txn_id, event_id) VALUES ('@alice:example.org', '!PW80ohbgl9Y-TuRoQMsk1IQrNVbWabrWmKGlGXaEuas', 'm.room.message', 'upgrade-txn-3', '$fLDkIkIn-ph02yfxRRffhu_AX3_wwIgZDH_Vr-YrKns');
INSERT INTO public.client_txn_ids (user_id, room_id, event_type, txn_id, event_id) VALUES ('@bob:example.org', '!PW80ohbgl9Y-TuRoQMsk1IQrNVbWabrWmKGlGXaEuas', 'm.room.message', 'upgrade-txn-4', '$f2hX4Ca1BCVBlAJnBXCuINGRj3sqDsb-RWYp61-O3zY');


--
-- Data for Name: cross_signing_keys; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: current_state; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.current_state (room_id, event_type, state_key, event_id) VALUES ('!PW80ohbgl9Y-TuRoQMsk1IQrNVbWabrWmKGlGXaEuas', 'm.room.create', '', '$PW80ohbgl9Y-TuRoQMsk1IQrNVbWabrWmKGlGXaEuas');
INSERT INTO public.current_state (room_id, event_type, state_key, event_id) VALUES ('!PW80ohbgl9Y-TuRoQMsk1IQrNVbWabrWmKGlGXaEuas', 'm.room.member', '@alice:example.org', '$F9JMTVXgFDNGp7iFGtx2TywcZGxTOnPJ9BsAxWeCEdw');
INSERT INTO public.current_state (room_id, event_type, state_key, event_id) VALUES ('!PW80ohbgl9Y-TuRoQMsk1IQrNVbWabrWmKGlGXaEuas', 'm.room.power_levels', '', '$DHSsoabsUGpSCkU6E49p2ebYC871D2cTjt4jK9F_dPU');
INSERT INTO public.current_state (room_id, event_type, state_key, event_id) VALUES ('!PW80ohbgl9Y-TuRoQMsk1IQrNVbWabrWmKGlGXaEuas', 'm.room.join_rules', '', '$0tndBnog_7KI3K9-4Hyq8LxDck8wQESjEpNyVIYYDQs');
INSERT INTO public.current_state (room_id, event_type, state_key, event_id) VALUES ('!PW80ohbgl9Y-TuRoQMsk1IQrNVbWabrWmKGlGXaEuas', 'm.room.history_visibility', '', '$kU8vhg7WTtC-0NYMd38tEQ3g8OcQfIoa-WmSrtr7lI4');
INSERT INTO public.current_state (room_id, event_type, state_key, event_id) VALUES ('!PW80ohbgl9Y-TuRoQMsk1IQrNVbWabrWmKGlGXaEuas', 'm.room.guest_access', '', '$4-VN3QWZ4vK176ipjhrwIH_XuwoN1o_qkOyzM4tBdbk');
INSERT INTO public.current_state (room_id, event_type, state_key, event_id) VALUES ('!PW80ohbgl9Y-TuRoQMsk1IQrNVbWabrWmKGlGXaEuas', 'm.room.encryption', '', '$UDClrVbxTCAqUy48bsypr8_K628lTtk2_7Zct0xnOI0');
INSERT INTO public.current_state (room_id, event_type, state_key, event_id) VALUES ('!PW80ohbgl9Y-TuRoQMsk1IQrNVbWabrWmKGlGXaEuas', 'm.room.name', '', '$VFlheYPtLdtWHAta0334y93R9EiAhDyMDRzz8jVgr-8');
INSERT INTO public.current_state (room_id, event_type, state_key, event_id) VALUES ('!PW80ohbgl9Y-TuRoQMsk1IQrNVbWabrWmKGlGXaEuas', 'm.room.member', '@bob:example.org', '$UsILJ1Vb4ImkDlZVQzARExBIFeI-W5EKvdfPdd_HWRk');
INSERT INTO public.current_state (room_id, event_type, state_key, event_id) VALUES ('!Ic8TlLD2IJRkiuVOQLk3Sa2aMgGqQqAh0lCVfPvuopM', 'm.room.create', '', '$Ic8TlLD2IJRkiuVOQLk3Sa2aMgGqQqAh0lCVfPvuopM');
INSERT INTO public.current_state (room_id, event_type, state_key, event_id) VALUES ('!Ic8TlLD2IJRkiuVOQLk3Sa2aMgGqQqAh0lCVfPvuopM', 'm.room.member', '@alice:example.org', '$5nOxHSGI8IqOf2a_lwP8yqaSIwQs-oZK-GIB9aR1-CE');
INSERT INTO public.current_state (room_id, event_type, state_key, event_id) VALUES ('!Ic8TlLD2IJRkiuVOQLk3Sa2aMgGqQqAh0lCVfPvuopM', 'm.room.power_levels', '', '$KcUeD1n_N2qMfVYYymDEtk-bUIagq8T0fDs-Z1C22F8');
INSERT INTO public.current_state (room_id, event_type, state_key, event_id) VALUES ('!Ic8TlLD2IJRkiuVOQLk3Sa2aMgGqQqAh0lCVfPvuopM', 'm.room.canonical_alias', '', '$emYLQiGP0XWcov5YjluNNYaKcS9ypfHkwDHsGkJxc-4');
INSERT INTO public.current_state (room_id, event_type, state_key, event_id) VALUES ('!Ic8TlLD2IJRkiuVOQLk3Sa2aMgGqQqAh0lCVfPvuopM', 'm.room.join_rules', '', '$Tj9XNWsarQZusIJAuUcmQ_XIX-4_sAzVP5VUj6g2vMk');
INSERT INTO public.current_state (room_id, event_type, state_key, event_id) VALUES ('!Ic8TlLD2IJRkiuVOQLk3Sa2aMgGqQqAh0lCVfPvuopM', 'm.room.history_visibility', '', '$8AwgfgEPhgBOqsFJDIeMUZuYVxSBggibmsxwjU9MkZY');
INSERT INTO public.current_state (room_id, event_type, state_key, event_id) VALUES ('!Ic8TlLD2IJRkiuVOQLk3Sa2aMgGqQqAh0lCVfPvuopM', 'm.room.guest_access', '', '$5KAhYnMasuZPEbMdElqpPcg5xbY4tuAn4esKeyAwc4Y');
INSERT INTO public.current_state (room_id, event_type, state_key, event_id) VALUES ('!Ic8TlLD2IJRkiuVOQLk3Sa2aMgGqQqAh0lCVfPvuopM', 'm.room.name', '', '$Ddc9U0VrcERho-K0z__0oMsXraYcoMGzessOX97rP44');


--
-- Data for Name: device_keys; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.device_keys (user_id, device_id, json) VALUES ('@alice:example.org', 'UPGRADE1', '{"algorithms":["m.olm.v1.curve25519-aes-sha2","m.megolm.v1.aes-sha2"],"device_id":"UPGRADE1","keys":{"curve25519:UPGRADE1":"ag9uvLEEOhH2Yg29kvdoMa1m7j0Pz5PNZNEyaquYZ2M","ed25519:UPGRADE1":"JXXvMLXocpackvsyVVQzrD0AmZ8nHmeV95SzGGCkm5I"},"signatures":{"@alice:example.org":{"ed25519:UPGRADE1":"EU/D/eGqdxS7GzkS4264WcjtUli3zIqkzqbY70XDvSTGYcGOFIxtHzy4F1JL2TEyyeef89MaYc6pK53XfIuECA"}},"unsigned":{"device_display_name":"Upgrade fixture UPGRADE1"},"user_id":"@alice:example.org"}');


--
-- Data for Name: device_list_changes; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.device_list_changes (stream_id, observer_user_id, subject_user_id, change_type) VALUES ('1', '@alice:example.org', '@alice:example.org', 'changed');
INSERT INTO public.device_list_changes (stream_id, observer_user_id, subject_user_id, change_type) VALUES ('2', '@bob:example.org', '@bob:example.org', 'changed');
INSERT INTO public.device_list_changes (stream_id, observer_user_id, subject_user_id, change_type) VALUES ('5', '@alice:example.org', '@bob:example.org', 'changed');
INSERT INTO public.device_list_changes (stream_id, observer_user_id, subject_user_id, change_type) VALUES ('6', '@bob:example.org', '@alice:example.org', 'changed');
INSERT INTO public.device_list_changes (stream_id, observer_user_id, subject_user_id, change_type) VALUES ('10', '@bob:example.org', '@alice:example.org', 'changed');
INSERT INTO public.device_list_changes (stream_id, observer_user_id, subject_user_id, change_type) VALUES ('11', '@alice:example.org', '@alice:example.org', 'changed');


--
-- Data for Name: devices; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.devices (user_id, device_id, display_name) VALUES ('@alice:example.org', 'UPGRADE1', 'UPGRADE1');
INSERT INTO public.devices (user_id, device_id, display_name) VALUES ('@bob:example.org', 'UPGRADE2', 'UPGRADE2');


--
-- Data for Name: event_auth; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.event_auth (event_id, auth_event_id) VALUES ('$DHSsoabsUGpSCkU6E49p2ebYC871D2cTjt4jK9F_dPU', '$F9JMTVXgFDNGp7iFGtx2TywcZGxTOnPJ9BsAxWeCEdw');
INSERT INTO public.event_auth (event_id, auth_event_id) VALUES ('$0tndBnog_7KI3K9-4Hyq8LxDck8wQESjEpNyVIYYDQs', '$F9JMTVXgFDNGp7iFGtx2TywcZGxTOnPJ9BsAxWeCEdw');
INSERT INTO public.event_auth (event_id, auth_event_id) VALUES ('$0tndBnog_7KI3K9-4Hyq8LxDck8wQESjEpNyVIYYDQs', '$DHSsoabsUGpSCkU6E49p2ebYC871D2cTjt4jK9F_dPU');
INSERT INTO public.event_auth (event_id, auth_event_id) VALUES ('$kU8vhg7WTtC-0NYMd38tEQ3g8OcQfIoa-WmSrtr7lI4', '$F9JMTVXgFDNGp7iFGtx2TywcZGxTOnPJ9BsAxWeCEdw');
INSERT INTO public.event_auth (event_id, auth_event_id) VALUES ('$kU8vhg7WTtC-0NYMd38tEQ3g8OcQfIoa-WmSrtr7lI4', '$DHSsoabsUGpSCkU6E49p2ebYC871D2cTjt4jK9F_dPU');
INSERT INTO public.event_auth (event_id, auth_event_id) VALUES ('$4-VN3QWZ4vK176ipjhrwIH_XuwoN1o_qkOyzM4tBdbk', '$F9JMTVXgFDNGp7iFGtx2TywcZGxTOnPJ9BsAxWeCEdw');
INSERT INTO public.event_auth (event_id, auth_event_id) VALUES ('$4-VN3QWZ4vK176ipjhrwIH_XuwoN1o_qkOyzM4tBdbk', '$DHSsoabsUGpSCkU6E49p2ebYC871D2cTjt4jK9F_dPU');
INSERT INTO public.event_auth (event_id, auth_event_id) VALUES ('$UDClrVbxTCAqUy48bsypr8_K628lTtk2_7Zct0xnOI0', '$F9JMTVXgFDNGp7iFGtx2TywcZGxTOnPJ9BsAxWeCEdw');
INSERT INTO public.event_auth (event_id, auth_event_id) VALUES ('$UDClrVbxTCAqUy48bsypr8_K628lTtk2_7Zct0xnOI0', '$DHSsoabsUGpSCkU6E49p2ebYC871D2cTjt4jK9F_dPU');
INSERT INTO public.event_auth (event_id, auth_event_id) VALUES ('$VFlheYPtLdtWHAta0334y93R9EiAhDyMDRzz8jVgr-8', '$F9JMTVXgFDNGp7iFGtx2TywcZGxTOnPJ9BsAxWeCEdw');
INSERT INTO public.event_auth (event_id, auth_event_id) VALUES ('$VFlheYPtLdtWHAta0334y93R9EiAhDyMDRzz8jVgr-8', '$DHSsoabsUGpSCkU6E49p2ebYC871D2cTjt4jK9F_dPU');
INSERT INTO public.event_auth (event_id, auth_event_id) VALUES ('$fnF-lqLGhlyzYg4ueoTe9549wDEXJKRpI-1oN4ZFtoA', '$F9JMTVXgFDNGp7iFGtx2TywcZGxTOnPJ9BsAxWeCEdw');
INSERT INTO public.event_auth (event_id, auth_event_id) VALUES ('$fnF-lqLGhlyzYg4ueoTe9549wDEXJKRpI-1oN4ZFtoA', '$DHSsoabsUGpSCkU6E49p2ebYC871D2cTjt4jK9F_dPU');
INSERT INTO public.event_auth (event_id, auth_event_id) VALUES ('$fnF-lqLGhlyzYg4ueoTe9549wDEXJKRpI-1oN4ZFtoA', '$0tndBnog_7KI3K9-4Hyq8LxDck8wQESjEpNyVIYYDQs');
INSERT INTO public.event_auth (event_id, auth_event_id) VALUES ('$UsILJ1Vb4ImkDlZVQzARExBIFeI-W5EKvdfPdd_HWRk', '$DHSsoabsUGpSCkU6E49p2ebYC871D2cTjt4jK9F_dPU');
INSERT INTO public.event_auth (event_id, auth_event_id) VALUES ('$UsILJ1Vb4ImkDlZVQzARExBIFeI-W5EKvdfPdd_HWRk', '$0tndBnog_7KI3K9-4Hyq8LxDck8wQESjEpNyVIYYDQs');
INSERT INTO public.event_auth (event_id, auth_event_id) VALUES ('$UsILJ1Vb4ImkDlZVQzARExBIFeI-W5EKvdfPdd_HWRk', '$fnF-lqLGhlyzYg4ueoTe9549wDEXJKRpI-1oN4ZFtoA');
INSERT INTO public.event_auth (event_id, auth_event_id) VALUES ('$LV4ggre4BtqcB7IaQzzNVhNlikCp0kBd7moi5iROKfo', '$F9JMTVXgFDNGp7iFGtx2TywcZGxTOnPJ9BsAxWeCEdw');
INSERT INTO public.event_auth (event_id, auth_event_id) VALUES ('$LV4ggre4BtqcB7IaQzzNVhNlikCp0kBd7moi5iROKfo', '$DHSsoabsUGpSCkU6E49p2ebYC871D2cTjt4jK9F_dPU');
INSERT INTO public.event_auth (event_id, auth_event_id) VALUES ('$Z0ytL9BlIFISIxrt2eTCRTJ7R7f42onZZRbe_2ImK5M', '$F9JMTVXgFDNGp7iFGtx2TywcZGxTOnPJ9BsAxWeCEdw');
INSERT INTO public.event_auth (event_id, auth_event_id) VALUES ('$Z0ytL9BlIFISIxrt2eTCRTJ7R7f42onZZRbe_2ImK5M', '$DHSsoabsUGpSCkU6E49p2ebYC871D2cTjt4jK9F_dPU');
INSERT INTO public.event_auth (event_id, auth_event_id) VALUES ('$fLDkIkIn-ph02yfxRRffhu_AX3_wwIgZDH_Vr-YrKns', '$F9JMTVXgFDNGp7iFGtx2TywcZGxTOnPJ9BsAxWeCEdw');
INSERT INTO public.event_auth (event_id, auth_event_id) VALUES ('$fLDkIkIn-ph02yfxRRffhu_AX3_wwIgZDH_Vr-YrKns', '$DHSsoabsUGpSCkU6E49p2ebYC871D2cTjt4jK9F_dPU');
INSERT INTO public.event_auth (event_id, auth_event_id) VALUES ('$f2hX4Ca1BCVBlAJnBXCuINGRj3sqDsb-RWYp61-O3zY', '$DHSsoabsUGpSCkU6E49p2ebYC871D2cTjt4jK9F_dPU');
INSERT INTO public.event_auth (event_id, auth_event_id) VALUES ('$f2hX4Ca1BCVBlAJnBXCuINGRj3sqDsb-RWYp61-O3zY', '$UsILJ1Vb4ImkDlZVQzARExBIFeI-W5EKvdfPdd_HWRk');
INSERT INTO public.event_auth (event_id, auth_event_id) VALUES ('$KcUeD1n_N2qMfVYYymDEtk-bUIagq8T0fDs-Z1C22F8', '$5nOxHSGI8IqOf2a_lwP8yqaSIwQs-oZK-GIB9aR1-CE');
INSERT INTO public.event_auth (event_id, auth_event_id) VALUES ('$emYLQiGP0XWcov5YjluNNYaKcS9ypfHkwDHsGkJxc-4', '$5nOxHSGI8IqOf2a_lwP8yqaSIwQs-oZK-GIB9aR1-CE');
INSERT INTO public.event_auth (event_id, auth_event_id) VALUES ('$emYLQiGP0XWcov5YjluNNYaKcS9ypfHkwDHsGkJxc-4', '$KcUeD1n_N2qMfVYYymDEtk-bUIagq8T0fDs-Z1C22F8');
INSERT INTO public.event_auth (event_id, auth_event_id) VALUES ('$Tj9XNWsarQZusIJAuUcmQ_XIX-4_sAzVP5VUj6g2vMk', '$5nOxHSGI8IqOf2a_lwP8yqaSIwQs-oZK-GIB9aR1-CE');
INSERT INTO public.event_auth (event_id, auth_event_id) VALUES ('$Tj9XNWsarQZusIJAuUcmQ_XIX-4_sAzVP5VUj6g2vMk', '$KcUeD1n_N2qMfVYYymDEtk-bUIagq8T0fDs-Z1C22F8');
INSERT INTO public.event_auth (event_id, auth_event_id) VALUES ('$8AwgfgEPhgBOqsFJDIeMUZuYVxSBggibmsxwjU9MkZY', '$5nOxHSGI8IqOf2a_lwP8yqaSIwQs-oZK-GIB9aR1-CE');
INSERT INTO public.event_auth (event_id, auth_event_id) VALUES ('$8AwgfgEPhgBOqsFJDIeMUZuYVxSBggibmsxwjU9MkZY', '$KcUeD1n_N2qMfVYYymDEtk-bUIagq8T0fDs-Z1C22F8');
INSERT INTO public.event_auth (event_id, auth_event_id) VALUES ('$5KAhYnMasuZPEbMdElqpPcg5xbY4tuAn4esKeyAwc4Y', '$5nOxHSGI8IqOf2a_lwP8yqaSIwQs-oZK-GIB9aR1-CE');
INSERT INTO public.event_auth (event_id, auth_event_id) VALUES ('$5KAhYnMasuZPEbMdElqpPcg5xbY4tuAn4esKeyAwc4Y', '$KcUeD1n_N2qMfVYYymDEtk-bUIagq8T0fDs-Z1C22F8');
INSERT INTO public.event_auth (event_id, auth_event_id) VALUES ('$Ddc9U0VrcERho-K0z__0oMsXraYcoMGzessOX97rP44', '$5nOxHSGI8IqOf2a_lwP8yqaSIwQs-oZK-GIB9aR1-CE');
INSERT INTO public.event_auth (event_id, auth_event_id) VALUES ('$Ddc9U0VrcERho-K0z__0oMsXraYcoMGzessOX97rP44', '$KcUeD1n_N2qMfVYYymDEtk-bUIagq8T0fDs-Z1C22F8');


--
-- Data for Name: event_edges; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.event_edges (event_id, prev_event_id) VALUES ('$F9JMTVXgFDNGp7iFGtx2TywcZGxTOnPJ9BsAxWeCEdw', '$PW80ohbgl9Y-TuRoQMsk1IQrNVbWabrWmKGlGXaEuas');
INSERT INTO public.event_edges (event_id, prev_event_id) VALUES ('$DHSsoabsUGpSCkU6E49p2ebYC871D2cTjt4jK9F_dPU', '$F9JMTVXgFDNGp7iFGtx2TywcZGxTOnPJ9BsAxWeCEdw');
INSERT INTO public.event_edges (event_id, prev_event_id) VALUES ('$0tndBnog_7KI3K9-4Hyq8LxDck8wQESjEpNyVIYYDQs', '$DHSsoabsUGpSCkU6E49p2ebYC871D2cTjt4jK9F_dPU');
INSERT INTO public.event_edges (event_id, prev_event_id) VALUES ('$kU8vhg7WTtC-0NYMd38tEQ3g8OcQfIoa-WmSrtr7lI4', '$0tndBnog_7KI3K9-4Hyq8LxDck8wQESjEpNyVIYYDQs');
INSERT INTO public.event_edges (event_id, prev_event_id) VALUES ('$4-VN3QWZ4vK176ipjhrwIH_XuwoN1o_qkOyzM4tBdbk', '$kU8vhg7WTtC-0NYMd38tEQ3g8OcQfIoa-WmSrtr7lI4');
INSERT INTO public.event_edges (event_id, prev_event_id) VALUES ('$UDClrVbxTCAqUy48bsypr8_K628lTtk2_7Zct0xnOI0', '$4-VN3QWZ4vK176ipjhrwIH_XuwoN1o_qkOyzM4tBdbk');
INSERT INTO public.event_edges (event_id, prev_event_id) VALUES ('$VFlheYPtLdtWHAta0334y93R9EiAhDyMDRzz8jVgr-8', '$UDClrVbxTCAqUy48bsypr8_K628lTtk2_7Zct0xnOI0');
INSERT INTO public.event_edges (event_id, prev_event_id) VALUES ('$fnF-lqLGhlyzYg4ueoTe9549wDEXJKRpI-1oN4ZFtoA', '$VFlheYPtLdtWHAta0334y93R9EiAhDyMDRzz8jVgr-8');
INSERT INTO public.event_edges (event_id, prev_event_id) VALUES ('$UsILJ1Vb4ImkDlZVQzARExBIFeI-W5EKvdfPdd_HWRk', '$fnF-lqLGhlyzYg4ueoTe9549wDEXJKRpI-1oN4ZFtoA');
INSERT INTO public.event_edges (event_id, prev_event_id) VALUES ('$LV4ggre4BtqcB7IaQzzNVhNlikCp0kBd7moi5iROKfo', '$UsILJ1Vb4ImkDlZVQzARExBIFeI-W5EKvdfPdd_HWRk');
INSERT INTO public.event_edges (event_id, prev_event_id) VALUES ('$Z0ytL9BlIFISIxrt2eTCRTJ7R7f42onZZRbe_2ImK5M', '$LV4ggre4BtqcB7IaQzzNVhNlikCp0kBd7moi5iROKfo');
INSERT INTO public.event_edges (event_id, prev_event_id) VALUES ('$fLDkIkIn-ph02yfxRRffhu_AX3_wwIgZDH_Vr-YrKns', '$Z0ytL9BlIFISIxrt2eTCRTJ7R7f42onZZRbe_2ImK5M');
INSERT INTO public.event_edges (event_id, prev_event_id) VALUES ('$f2hX4Ca1BCVBlAJnBXCuINGRj3sqDsb-RWYp61-O3zY', '$fLDkIkIn-ph02yfxRRffhu_AX3_wwIgZDH_Vr-YrKns');
INSERT INTO public.event_edges (event_id, prev_event_id) VALUES ('$5nOxHSGI8IqOf2a_lwP8yqaSIwQs-oZK-GIB9aR1-CE', '$Ic8TlLD2IJRkiuVOQLk3Sa2aMgGqQqAh0lCVfPvuopM');
INSERT INTO public.event_edges (event_id, prev_event_id) VALUES ('$KcUeD1n_N2qMfVYYymDEtk-bUIagq8T0fDs-Z1C22F8', '$5nOxHSGI8IqOf2a_lwP8yqaSIwQs-oZK-GIB9aR1-CE');
INSERT INTO public.event_edges (event_id, prev_event_id) VALUES ('$emYLQiGP0XWcov5YjluNNYaKcS9ypfHkwDHsGkJxc-4', '$KcUeD1n_N2qMfVYYymDEtk-bUIagq8T0fDs-Z1C22F8');
INSERT INTO public.event_edges (event_id, prev_event_id) VALUES ('$Tj9XNWsarQZusIJAuUcmQ_XIX-4_sAzVP5VUj6g2vMk', '$emYLQiGP0XWcov5YjluNNYaKcS9ypfHkwDHsGkJxc-4');
INSERT INTO public.event_edges (event_id, prev_event_id) VALUES ('$8AwgfgEPhgBOqsFJDIeMUZuYVxSBggibmsxwjU9MkZY', '$Tj9XNWsarQZusIJAuUcmQ_XIX-4_sAzVP5VUj6g2vMk');
INSERT INTO public.event_edges (event_id, prev_event_id) VALUES ('$5KAhYnMasuZPEbMdElqpPcg5xbY4tuAn4esKeyAwc4Y', '$8AwgfgEPhgBOqsFJDIeMUZuYVxSBggibmsxwjU9MkZY');
INSERT INTO public.event_edges (event_id, prev_event_id) VALUES ('$Ddc9U0VrcERho-K0z__0oMsXraYcoMGzessOX97rP44', '$5KAhYnMasuZPEbMdElqpPcg5xbY4tuAn4esKeyAwc4Y');


--
-- Data for Name: event_json; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: event_signatures; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.event_signatures (event_id, server_name, key_id, signature) VALUES ('$PW80ohbgl9Y-TuRoQMsk1IQrNVbWabrWmKGlGXaEuas', 'example.org', 'ed25519:ac2d510c', 'igzjVerUpdWcamc7r+4VudAUWaoLhFjNgb0HL8zIhBQUbWlrjpQyqgKUOXee2hMkIPN+v950MCAX9zhYiCfVAg');
INSERT INTO public.event_signatures (event_id, server_name, key_id, signature) VALUES ('$F9JMTVXgFDNGp7iFGtx2TywcZGxTOnPJ9BsAxWeCEdw', 'example.org', 'ed25519:ac2d510c', 'CLkFccgtq7xL1IKZege9W49ye9KmedQJTCl34MNyLiEy0n8iIK9/8NxRNFdZj0hTBeogwyDAsNBK9HYa3IiWCw');
INSERT INTO public.event_signatures (event_id, server_name, key_id, signature) VALUES ('$DHSsoabsUGpSCkU6E49p2ebYC871D2cTjt4jK9F_dPU', 'example.org', 'ed25519:ac2d510c', 'DTeaYmKFUUzufqqFBkex9V5cEJArGOHhD4EENQ3SV8pT30J9SVGE+FohKRzLoqv9ZP638iuXj0yCZs0O8vIsDg');
INSERT INTO public.event_signatures (event_id, server_name, key_id, signature) VALUES ('$0tndBnog_7KI3K9-4Hyq8LxDck8wQESjEpNyVIYYDQs', 'example.org', 'ed25519:ac2d510c', '5BUe7nv42I6NFF60nqXrT6tz8RUjfZ2OPUvbqvX39TXQMxrsYCIOD3Zc+FAH6KkqPW4830rdIswupU8gPiCBAw');
INSERT INTO public.event_signatures (event_id, server_name, key_id, signature) VALUES ('$kU8vhg7WTtC-0NYMd38tEQ3g8OcQfIoa-WmSrtr7lI4', 'example.org', 'ed25519:ac2d510c', 'fVtzbeVR14q7SJBPsPPfjEz8pBcOn+HhgHNgAb2EyoAI037hTL6X3mjhMQtO0/cf+8IniAAY4H5ZDKQsdxphAA');
INSERT INTO public.event_signatures (event_id, server_name, key_id, signature) VALUES ('$4-VN3QWZ4vK176ipjhrwIH_XuwoN1o_qkOyzM4tBdbk', 'example.org', 'ed25519:ac2d510c', 'RnQu8cmDoPEScW8LEz9mX3t93jCLf/90Avn+twm/DY3Ya1FHfFtyIuz7dgf7M+tpj9i/AL0ZGyK2DzIu/BT0BQ');
INSERT INTO public.event_signatures (event_id, server_name, key_id, signature) VALUES ('$UDClrVbxTCAqUy48bsypr8_K628lTtk2_7Zct0xnOI0', 'example.org', 'ed25519:ac2d510c', 'uGTcu/1y5CdaFyE0C9X/H47uU25Y0lQCpItTVGeXGJu3Pi0Usc0GJkLyjkj0WPyoB0ByGE046TTqN82VbgF0CA');
INSERT INTO public.event_signatures (event_id, server_name, key_id, signature) VALUES ('$VFlheYPtLdtWHAta0334y93R9EiAhDyMDRzz8jVgr-8', 'example.org', 'ed25519:ac2d510c', 'LgfAOHBw225GdRSEChNTON81K0+So10p4I4R0VuzPTbjX4XqmfdOjQvqS6OI6LuvNGMM/L5idC8WES7NbuxuAA');
INSERT INTO public.event_signatures (event_id, server_name, key_id, signature) VALUES ('$fnF-lqLGhlyzYg4ueoTe9549wDEXJKRpI-1oN4ZFtoA', 'example.org', 'ed25519:ac2d510c', 'i2U8+CIMpY1UyqWwz73UpIi15Arfi4x+ZIRF+jt4lhnur8e6LyhhovGJgnRf/c8QQA/xoXJddgKcoCMnxyqxDA');
INSERT INTO public.event_signatures (event_id, server_name, key_id, signature) VALUES ('$UsILJ1Vb4ImkDlZVQzARExBIFeI-W5EKvdfPdd_HWRk', 'example.org', 'ed25519:ac2d510c', '5EOMMMOybDGpkWuRmSLFvwDiUeS0v4ALMyEu7ZH/TfQUMhSmTGHQFplbOxgkfT+hHffyjLitJa/WUrIxCxMtBQ');
INSERT INTO public.event_signatures (event_id, server_name, key_id, signature) VALUES ('$LV4ggre4BtqcB7IaQzzNVhNlikCp0kBd7moi5iROKfo', 'example.org', 'ed25519:ac2d510c', '/cA5ILkQxp/S0q5xU8vCmjfjPxgLSeVfj11QDIagyBn52OVMlkxki6PGSCFu73AQRcBYPBBak45+Xn5XS6MLAA');
INSERT INTO public.event_signatures (event_id, server_name, key_id, signature) VALUES ('$Z0ytL9BlIFISIxrt2eTCRTJ7R7f42onZZRbe_2ImK5M', 'example.org', 'ed25519:ac2d510c', 'Jlj/LSx7/9mB+8xphfSSKQqsQ4onfWsplUJQ8uKuWKkB3K2XBVk02blqM3D1ddk7pG/aP2Bg5hMoylrueRoOCA');
INSERT INTO public.event_signatures (event_id, server_name, key_id, signature) VALUES ('$fLDkIkIn-ph02yfxRRffhu_AX3_wwIgZDH_Vr-YrKns', 'example.org', 'ed25519:ac2d510c', '3MAsxQdqO1JFP14ouJ5ptxKp/9ZyX2ReJw9un0tL7Hl69548gDfF5cKgSamYzDS/2hnC77MMAD9kQATmYyoJAg');
INSERT INTO public.event_signatures (event_id, server_name, key_id, signature) VALUES ('$f2hX4Ca1BCVBlAJnBXCuINGRj3sqDsb-RWYp61-O3zY', 'example.org', 'ed25519:ac2d510c', 'ZlMl6LDdlDHC+2BebYGKTE6JdCDMdWT76JXM0RJoPUH/U7BWeqosg/nJSPzEQbNIZuXCH7AXILoJwAx4lzRXBQ');
INSERT INTO public.event_signatures (event_id, server_name, key_id, signature) VALUES ('$Ic8TlLD2IJRkiuVOQLk3Sa2aMgGqQqAh0lCVfPvuopM', 'example.org', 'ed25519:ac2d510c', 'iXknGojDDhQmDR/qzjWgfQihdaKYkELfIdrtkvtBWsdqLK6rWYvnmRRKC3q4VK6G5deUOTvutidOJO/wJ6OUBQ');
INSERT INTO public.event_signatures (event_id, server_name, key_id, signature) VALUES ('$5nOxHSGI8IqOf2a_lwP8yqaSIwQs-oZK-GIB9aR1-CE', 'example.org', 'ed25519:ac2d510c', 'rH7AB0zIbC9dydOstVbtsuejiGpgNTubntQSy3Jp4/y2xrgg69dQgb9XQcgSpZzqN+aq18fu+KqFq8PMLf5jCA');
INSERT INTO public.event_signatures (event_id, server_name, key_id, signature) VALUES ('$KcUeD1n_N2qMfVYYymDEtk-bUIagq8T0fDs-Z1C22F8', 'example.org', 'ed25519:ac2d510c', '2BFeZN53Fl+69teqQJNMNikxNRy9vasFhWz3iyGPwaU4qCw5aUnnZaEm7tHKoZmf0RHp47DF73WlpIxHVTV4Cg');
INSERT INTO public.event_signatures (event_id, server_name, key_id, signature) VALUES ('$emYLQiGP0XWcov5YjluNNYaKcS9ypfHkwDHsGkJxc-4', 'example.org', 'ed25519:ac2d510c', 'LXgimFfBxT5TIRczebbRe25WPaRWoCiTcJaGRITEWFnpYPCWTnJ3NJ2NRa1BTCg+r0H1MNhjGWkJbxcD9oJWAA');
INSERT INTO public.event_signatures (event_id, server_name, key_id, signature) VALUES ('$Tj9XNWsarQZusIJAuUcmQ_XIX-4_sAzVP5VUj6g2vMk', 'example.org', 'ed25519:ac2d510c', 'lOBufilV9EGPZ1FiezmQdDFXkO6oDtHvrcEJSEKNA8kUqR3+4e8XJ+0LefQw2C/NqXEgXUwBQMNvFgiRwyq2Dg');
INSERT INTO public.event_signatures (event_id, server_name, key_id, signature) VALUES ('$8AwgfgEPhgBOqsFJDIeMUZuYVxSBggibmsxwjU9MkZY', 'example.org', 'ed25519:ac2d510c', 'XG2aPjgMAsbo7QGl5yuHHOU09xwagsoEf+iKyMegyUhNlKGD0zHdpH/KwTYvAzIRFM1h4AOr6+H4sa2t7fJ/Cg');
INSERT INTO public.event_signatures (event_id, server_name, key_id, signature) VALUES ('$5KAhYnMasuZPEbMdElqpPcg5xbY4tuAn4esKeyAwc4Y', 'example.org', 'ed25519:ac2d510c', 'aI67KNCBNNUD6u3MPbknhA1PyY6+goSK0Ce5wZ6y3GBWMI81cnAGNAaAFZ0xnOYmDG25XjxDreAQvi/kNGmsCw');
INSERT INTO public.event_signatures (event_id, server_name, key_id, signature) VALUES ('$Ddc9U0VrcERho-K0z__0oMsXraYcoMGzessOX97rP44', 'example.org', 'ed25519:ac2d510c', '1ZEz6eDflBHVfH3Dq7X9S0wUQbJJknRqdrQlw2KusBf1cbs4rkjdkl6s3wkdZY9girScojTREoQViRfcnP1TAg');


--
-- Data for Name: event_stream_watermark; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.event_stream_watermark (singleton, watermark) VALUES (1, '24');


--
-- Data for Name: events; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.events (event_id, room_id, sender_user_id, json, depth, stream_ordering) VALUES ('$PW80ohbgl9Y-TuRoQMsk1IQrNVbWabrWmKGlGXaEuas', '!PW80ohbgl9Y-TuRoQMsk1IQrNVbWabrWmKGlGXaEuas', '@alice:example.org', '{"auth_events":[],"content":{"creator":"@alice:example.org","room_version":"12"},"depth":1,"hashes":{"sha256":"LI76iBouRFTdrwfqCDA/doY5DvzDfz9cqfkXJ3i82uk"},"origin_server_ts":1792750262036,"prev_events":[],"sender":"@alice:example.org","signatures":{"example.org":{"ed25519:ac2d510c":"igzjVerUpdWcamc7r+4VudAUWaoLhFjNgb0HL8zIhBQUbWlrjpQyqgKUOXee2hMkIPN+v950MCAX9zhYiCfVAg"}},"state_key":"","type":"m.room.create"}', '1', '1');
INSERT INTO public.events (event_id, room_id, sender_user_id, json, depth, stream_ordering) VALUES ('$F9JMTVXgFDNGp7iFGtx2TywcZGxTOnPJ9BsAxWeCEdw', '!PW80ohbgl9Y-TuRoQMsk1IQrNVbWabrWmKGlGXaEuas', '@alice:example.org', '{"auth_events":[],"content":{"membership":"join"},"depth":2,"hashes":{"sha256":"V2M6rkHt+KsgM2TwED33L17J6qjUOmb1FWnDsaPniQk"},"origin_server_ts":1792750262043,"prev_events":["$PW80ohbgl9Y-TuRoQMsk1IQrNVbWabrWmKGlGXaEuas"],"room_id":"!PW80ohbgl9Y-TuRoQMsk1IQrNVbWabrWmKGlGXaEuas","sender":"@alice:example.org","signatures":{"example.org":{"ed25519:ac2d510c":"CLkFccgtq7xL1IKZege9W49ye9KmedQJTCl34MNyLiEy0n8iIK9/8NxRNFdZj0hTBeogwyDAsNBK9HYa3IiWCw"}},"state_key":"@alice:example.org","type":"m.room.member"}', '2', '2');
INSERT INTO public.events (event_id, room_id, sender_user_id, json, depth, stream_ordering) VALUES ('$DHSsoabsUGpSCkU6E49p2ebYC871D2cTjt4jK9F_dPU', '!PW80ohbgl9Y-TuRoQMsk1IQrNVbWabrWmKGlGXaEuas', '@alice:example.org', '{"auth_events":["$F9JMTVXgFDNGp7iFGtx2TywcZGxTOnPJ9BsAxWeCEdw"],"content":{"ban":50,"events":{},"events_default":0,"invite":50,"kick":50,"redact":50,"state_default":50,"users":{},"users_default":0},"depth":3,"hashes":{"sha256":"0hEYZ40X5IWOpXKjFhIcSsLGkLANa4JxkMh0hELdT/U"},"origin_server_ts":1792750262047,"prev_events":["$F9JMTVXgFDNGp7iFGtx2TywcZGxTOnPJ9BsAxWeCEdw"],"room_id":"!PW80ohbgl9Y-TuRoQMsk1IQrNVbWabrWmKGlGXaEuas","sender":"@alice:example.org","signatures":{"example.org":{"ed25519:ac2d510c":"DTeaYmKFUUzufqqFBkex9V5cEJArGOHhD4EENQ3SV8pT30J9SVGE+FohKRzLoqv9ZP638iuXj0yCZs0O8vIsDg"}},"state_key":"","type":"m.room.power_levels"}', '3', '3');
INSERT INTO public.events (event_id, room_id, sender_user_id, json, depth, stream_ordering) VALUES ('$0tndBnog_7KI3K9-4Hyq8LxDck8wQESjEpNyVIYYDQs', '!PW80ohbgl9Y-TuRoQMsk1IQrNVbWabrWmKGlGXaEuas', '@alice:example.org', '{"auth_events":["$F9JMTVXgFDNGp7iFGtx2TywcZGxTOnPJ9BsAxWeCEdw","$DHSsoabsUGpSCkU6E49p2ebYC871D2cTjt4jK9F_dPU"],"content":{"join_rule":"invite"},"depth":4,"hashes":{"sha256":"yqYzZLdlYXQGKCkIjEFckLm+Gw+WkhiaLGvoTJk/dDQ"},"origin_server_ts":1792750262052,"prev_events":["$DHSsoabsUGpSCkU6E49p2ebYC871D2cTjt4jK9F_dPU"],"room_id":"!PW80ohbgl9Y-TuRoQMsk1IQrNVbWabrWmKGlGXaEuas","sender":"@alice:example.org","signatures":{"example.org":{"ed25519:ac2d510c":"5BUe7nv42I6NFF60nqXrT6tz8RUjfZ2OPUvbqvX39TXQMxrsYCIOD3Zc+FAH6KkqPW4830rdIswupU8gPiCBAw"}},"state_key":"","type":"m.room.join_rules"}', '4', '4');
INSERT INTO public.events (event_id, room_id, sender_user_id, json, depth, stream_ordering) VALUES ('$kU8vhg7WTtC-0NYMd38tEQ3g8OcQfIoa-WmSrtr7lI4', '!PW80ohbgl9Y-TuRoQMsk1IQrNVbWabrWmKGlGXaEuas', '@alice:example.org', '{"auth_events":["$F9JMTVXgFDNGp7iFGtx2TywcZGxTOnPJ9BsAxWeCEdw","$DHSsoabsUGpSCkU6E49p2ebYC871D2cTjt4jK9F_dPU"],"content":{"history_visibility":"shared"},"depth":5,"hashes":{"sha256":"p5CAexrAe81jLYO7Vy8wIVeje7XHqMlzuunmvfbjq+Y"},"origin_server_ts":1792750262057,"prev_events":["$0tndBnog_7KI3K9-4Hyq8LxDck8wQESjEpNyVIYYDQs"],"room_id":"!PW80ohbgl9Y-TuRoQMsk1IQrNVbWabrWmKGlGXaEuas","sender":"@alice:example.org","signatures":{"example.org":{"ed25519:ac2d510c":"fVtzbeVR14q7SJBPsPPfjEz8pBcOn+HhgHNgAb2EyoAI037hTL6X3mjhMQtO0/cf+8IniAAY4H5ZDKQsdxphAA"}},"state_key":"","type":"m.room.history_visibility"}', '5', '5');
INSERT INTO public.events (event_id, room_id, sender_user_id, json, depth, stream_ordering) VALUES ('$4-VN3QWZ4vK176ipjhrwIH_XuwoN1o_qkOyzM4tBdbk', '!PW80ohbgl9Y-TuRoQMsk1IQrNVbWabrWmKGlGXaEuas', '@alice:example.org', '{"auth_events":["$F9JMTVXgFDNGp7iFGtx2TywcZGxTOnPJ9BsAxWeCEdw","$DHSsoabsUGpSCkU6E49p2ebYC871D2cTjt4jK9F_dPU"],"content":{"guest_access":"can_join"},"depth":6,"hashes":{"sha256":"pz5PFinz3Kf1MAivwCDbBs8jZT1LPVLZh7VgsEqfc0U"},"origin_server_ts":1792750262061,"prev_events":["$kU8vhg7WTtC-0NYMd38tEQ3g8OcQfIoa-WmSrtr7lI4"],"room_id":"!PW80ohbgl9Y-TuRoQMsk1IQrNVbWabrWmKGlGXaEuas","sender":"@alice:example.org","signatures":{"example.org":{"ed25519:ac2d510c":"RnQu8cmDoPEScW8LEz9mX3t93jCLf/90Avn+twm/DY3Ya1FHfFtyIuz7dgf7M+tpj9i/AL0ZGyK2DzIu/BT0BQ"}},"state_key":"","type":"m.room.guest_access"}', '6', '6');
INSERT INTO public.events (event_id, room_id, sender_user_id, json, depth, stream_ordering) VALUES ('$UDClrVbxTCAqUy48bsypr8_K628lTtk2_7Zct0xnOI0', '!PW80ohbgl9Y-TuRoQMsk1IQrNVbWabrWmKGlGXaEuas', '@alice:example.org', '{"auth_events":["$F9JMTVXgFDNGp7iFGtx2TywcZGxTOnPJ9BsAxWeCEdw","$DHSsoabsUGpSCkU6E49p2ebYC871D2cTjt4jK9F_dPU"],"content":{"algorithm":"m.megolm.v1.aes-sha2"},"depth":7,"hashes":{"sha256":"1ct+/o8iMebnTfTi2JUZrtvHeZfS5EX/JmNsyUA0inA"},"origin_server_ts":1792750262066,"prev_events":["$4-VN3QWZ4vK176ipjhrwIH_XuwoN1o_qkOyzM4tBdbk"],"room_id":"!PW80ohbgl9Y-TuRoQMsk1IQrNVbWabrWmKGlGXaEuas","sender":"@alice:example.org","signatures":{"example.org":{"ed25519:ac2d510c":"uGTcu/1y5CdaFyE0C9X/H47uU25Y0lQCpItTVGeXGJu3Pi0Usc0GJkLyjkj0WPyoB0ByGE046TTqN82VbgF0CA"}},"state_key":"","type":"m.room.encryption"}', '7', '7');
INSERT INTO public.events (event_id, room_id, sender_user_id, json, depth, stream_ordering) VALUES ('$VFlheYPtLdtWHAta0334y93R9EiAhDyMDRzz8jVgr-8', '!PW80ohbgl9Y-TuRoQMsk1IQrNVbWabrWmKGlGXaEuas', '@alice:example.org', '{"auth_events":["$F9JMTVXgFDNGp7iFGtx2TywcZGxTOnPJ9BsAxWeCEdw","$DHSsoabsUGpSCkU6E49p2ebYC871D2cTjt4jK9F_dPU"],"content":{"name":"Upgrade Room"},"depth":8,"hashes":{"sha256":"B29ECidCVCCVaJELlijcO13pSJfIlZFhF7rQeD+96EM"},"origin_server_ts":1792750262070,"prev_events":["$UDClrVbxTCAqUy48bsypr8_K628lTtk2_7Zct0xnOI0"],"room_id":"!PW80ohbgl9Y-TuRoQMsk1IQrNVbWabrWmKGlGXaEuas","sender":"@alice:example.org","signatures":{"example.org":{"ed25519:ac2d510c":"LgfAOHBw225GdRSEChNTON81K0+So10p4I4R0VuzPTbjX4XqmfdOjQvqS6OI6LuvNGMM/L5idC8WES7NbuxuAA"}},"state_key":"","type":"m.room.name"}', '8', '8');
INSERT INTO public.events (event_id, room_id, sender_user_id, json, depth, stream_ordering) VALUES ('$fnF-lqLGhlyzYg4ueoTe9549wDEXJKRpI-1oN4ZFtoA', '!PW80ohbgl9Y-TuRoQMsk1IQrNVbWabrWmKGlGXaEuas', '@alice:example.org', '{"auth_events":["$F9JMTVXgFDNGp7iFGtx2TywcZGxTOnPJ9BsAxWeCEdw","$DHSsoabsUGpSCkU6E49p2ebYC871D2cTjt4jK9F_dPU","$0tndBnog_7KI3K9-4Hyq8LxDck8wQESjEpNyVIYYDQs"],"content":{"membership":"invite"},"depth":9,"hashes":{"sha256":"MKK6m5eF9+g1gXtbe+6OAuVE5KGZbPwMPRaiUDnalKE"},"origin_server_ts":1792750262079,"prev_events":["$VFlheYPtLdtWHAta0334y93R9EiAhDyMDRzz8jVgr-8"],"room_id":"!PW80ohbgl9Y-TuRoQMsk1IQrNVbWabrWmKGlGXaEuas","sender":"@alice:example.org","signatures":{"example.org":{"ed25519:ac2d510c":"i2U8+CIMpY1UyqWwz73UpIi15Arfi4x+ZIRF+jt4lhnur8e6LyhhovGJgnRf/c8QQA/xoXJddgKcoCMnxyqxDA"}},"state_key":"@bob:example.org","type":"m.room.member"}', '9', '9');
INSERT INTO public.events (event_id, room_id, sender_user_id, json, depth, stream_ordering) VALUES ('$UsILJ1Vb4ImkDlZVQzARExBIFeI-W5EKvdfPdd_HWRk', '!PW80ohbgl9Y-TuRoQMsk1IQrNVbWabrWmKGlGXaEuas', '@bob:example.org', '{"auth_events":["$DHSsoabsUGpSCkU6E49p2ebYC871D2cTjt4jK9F_dPU","$0tndBnog_7KI3K9-4Hyq8LxDck8wQESjEpNyVIYYDQs","$fnF-lqLGhlyzYg4ueoTe9549wDEXJKRpI-1oN4ZFtoA"],"content":{"membership":"join"},"depth":10,"hashes":{"sha256":"HwPFLNZmHn25Nz+3dxpjmqQej6Vd5rb/V9FRPdFTLpY"},"origin_server_ts":1792750262094,"prev_events":["$fnF-lqLGhlyzYg4ueoTe9549wDEXJKRpI-1oN4ZFtoA"],"room_id":"!PW80ohbgl9Y-TuRoQMsk1IQrNVbWabrWmKGlGXaEuas","sender":"@bob:example.org","signatures":{"example.org":{"ed25519:ac2d510c":"5EOMMMOybDGpkWuRmSLFvwDiUeS0v4ALMyEu7ZH/TfQUMhSmTGHQFplbOxgkfT+hHffyjLitJa/WUrIxCxMtBQ"}},"state_key":"@bob:example.org","type":"m.room.member"}', '10', '11');
INSERT INTO public.events (event_id, room_id, sender_user_id, json, depth, stream_ordering) VALUES ('$LV4ggre4BtqcB7IaQzzNVhNlikCp0kBd7moi5iROKfo', '!PW80ohbgl9Y-TuRoQMsk1IQrNVbWabrWmKGlGXaEuas', '@alice:example.org', '{"auth_events":["$F9JMTVXgFDNGp7iFGtx2TywcZGxTOnPJ9BsAxWeCEdw","$DHSsoabsUGpSCkU6E49p2ebYC871D2cTjt4jK9F_dPU"],"content":{"body":"upgrade message 1","msgtype":"m.text"},"depth":11,"hashes":{"sha256":"FPYV+a95pVT0Q4WjjUSMfzu9Is+A+mrNqczvdh7ZW4Q"},"origin_server_ts":1792750262117,"prev_events":["$UsILJ1Vb4ImkDlZVQzARExBIFeI-W5EKvdfPdd_HWRk"],"room_id":"!PW80ohbgl9Y-TuRoQMsk1IQrNVbWabrWmKGlGXaEuas","sender":"@alice:example.org","signatures":{"example.org":{"ed25519:ac2d510c":"/cA5ILkQxp/S0q5xU8vCmjfjPxgLSeVfj11QDIagyBn52OVMlkxki6PGSCFu73AQRcBYPBBak45+Xn5XS6MLAA"}},"type":"m.room.message"}', '11', '13');
INSERT INTO public.events (event_id, room_id, sender_user_id, json, depth, stream_ordering) VALUES ('$Z0ytL9BlIFISIxrt2eTCRTJ7R7f42onZZRbe_2ImK5M', '!PW80ohbgl9Y-TuRoQMsk1IQrNVbWabrWmKGlGXaEuas', '@alice:example.org', '{"auth_events":["$F9JMTVXgFDNGp7iFGtx2TywcZGxTOnPJ9BsAxWeCEdw","$DHSsoabsUGpSCkU6E49p2ebYC871D2cTjt4jK9F_dPU"],"content":{"body":"upgrade message 2","msgtype":"m.text"},"depth":12,"hashes":{"sha256":"pXC1ry6V/v+akdwfmbDZJwT0zluFPtRGH2KDxzlGNUU"},"origin_server_ts":1792750262127,"prev_events":["$LV4ggre4BtqcB7IaQzzNVhNlikCp0kBd7moi5iROKfo"],"room_id":"!PW80ohbgl9Y-TuRoQMsk1IQrNVbWabrWmKGlGXaEuas","sender":"@alice:example.org","signatures":{"example.org":{"ed25519:ac2d510c":"Jlj/LSx7/9mB+8xphfSSKQqsQ4onfWsplUJQ8uKuWKkB3K2XBVk02blqM3D1ddk7pG/aP2Bg5hMoylrueRoOCA"}},"type":"m.room.message"}', '12', '14');
INSERT INTO public.events (event_id, room_id, sender_user_id, json, depth, stream_ordering) VALUES ('$fLDkIkIn-ph02yfxRRffhu_AX3_wwIgZDH_Vr-YrKns', '!PW80ohbgl9Y-TuRoQMsk1IQrNVbWabrWmKGlGXaEuas', '@alice:example.org', '{"auth_events":["$F9JMTVXgFDNGp7iFGtx2TywcZGxTOnPJ9BsAxWeCEdw","$DHSsoabsUGpSCkU6E49p2ebYC871D2cTjt4jK9F_dPU"],"content":{"body":"upgrade message 3","msgtype":"m.text"},"depth":13,"hashes":{"sha256":"NLITsOn36hSXIw5J+vG1tXHApFM9nQ9fu9uEPf/V26M"},"origin_server_ts":1792750262139,"prev_events":["$Z0ytL9BlIFISIxrt2eTCRTJ7R7f42onZZRbe_2ImK5M"],"room_id":"!PW80ohbgl9Y-TuRoQMsk1IQrNVbWabrWmKGlGXaEuas","sender":"@alice:example.org","signatures":{"example.org":{"ed25519:ac2d510c":"3MAsxQdqO1JFP14ouJ5ptxKp/9ZyX2ReJw9un0tL7Hl69548gDfF5cKgSamYzDS/2hnC77MMAD9kQATmYyoJAg"}},"type":"m.room.message"}', '13', '15');
INSERT INTO public.events (event_id, room_id, sender_user_id, json, depth, stream_ordering) VALUES ('$f2hX4Ca1BCVBlAJnBXCuINGRj3sqDsb-RWYp61-O3zY', '!PW80ohbgl9Y-TuRoQMsk1IQrNVbWabrWmKGlGXaEuas', '@bob:example.org', '{"auth_events":["$DHSsoabsUGpSCkU6E49p2ebYC871D2cTjt4jK9F_dPU","$UsILJ1Vb4ImkDlZVQzARExBIFeI-W5EKvdfPdd_HWRk"],"content":{"body":"reply from bob","msgtype":"m.text"},"depth":14,"hashes":{"sha256":"fGc3Xa8+zqhgNNGa8gEj7915xna1OJDLNcKLSvRL8hE"},"origin_server_ts":1792750262150,"prev_events":["$fLDkIkIn-ph02yfxRRffhu_AX3_wwIgZDH_Vr-YrKns"],"room_id":"!PW80ohbgl9Y-TuRoQMsk1IQrNVbWabrWmKGlGXaEuas","sender":"@bob:example.org","signatures":{"example.org":{"ed25519:ac2d510c":"ZlMl6LDdlDHC+2BebYGKTE6JdCDMdWT76JXM0RJoPUH/U7BWeqosg/nJSPzEQbNIZuXCH7AXILoJwAx4lzRXBQ"}},"type":"m.room.message"}', '14', '16');
INSERT INTO public.events (event_id, room_id, sender_user_id, json, depth, stream_ordering) VALUES ('$Ic8TlLD2IJRkiuVOQLk3Sa2aMgGqQqAh0lCVfPvuopM', '!Ic8TlLD2IJRkiuVOQLk3Sa2aMgGqQqAh0lCVfPvuopM', '@alice:example.org', '{"auth_events":[],"content":{"creator":"@alice:example.org","room_version":"12"},"depth":1,"hashes":{"sha256":"4JdAE5OxQT2Z7X6cMLntYyCeVLHLbCnq9rgtxeBJg9A"},"origin_server_ts":1792750262161,"prev_events":[],"sender":"@alice:example.org","signatures":{"example.org":{"ed25519:ac2d510c":"iXknGojDDhQmDR/qzjWgfQihdaKYkELfIdrtkvtBWsdqLK6rWYvnmRRKC3q4VK6G5deUOTvutidOJO/wJ6OUBQ"}},"state_key":"","type":"m.room.create"}', '1', '17');
INSERT INTO public.events (event_id, room_id, sender_user_id, json, depth, stream_ordering) VALUES ('$5nOxHSGI8IqOf2a_lwP8yqaSIwQs-oZK-GIB9aR1-CE', '!Ic8TlLD2IJRkiuVOQLk3Sa2aMgGqQqAh0lCVfPvuopM', '@alice:example.org', '{"auth_events":[],"content":{"membership":"join"},"depth":2,"hashes":{"sha256":"eaiOZe7UwCTAM71Y19qVun2PFHAt2VXRQk1YlcA0/TE"},"origin_server_ts":1792750262167,"prev_events":["$Ic8TlLD2IJRkiuVOQLk3Sa2aMgGqQqAh0lCVfPvuopM"],"room_id":"!Ic8TlLD2IJRkiuVOQLk3Sa2aMgGqQqAh0lCVfPvuopM","sender":"@alice:example.org","signatures":{"example.org":{"ed25519:ac2d510c":"rH7AB0zIbC9dydOstVbtsuejiGpgNTubntQSy3Jp4/y2xrgg69dQgb9XQcgSpZzqN+aq18fu+KqFq8PMLf5jCA"}},"state_key":"@alice:example.org","type":"m.room.member"}', '2', '18');
INSERT INTO public.events (event_id, room_id, sender_user_id, json, depth, stream_ordering) VALUES ('$KcUeD1n_N2qMfVYYymDEtk-bUIagq8T0fDs-Z1C22F8', '!Ic8TlLD2IJRkiuVOQLk3Sa2aMgGqQqAh0lCVfPvuopM', '@alice:example.org', '{"auth_events":["$5nOxHSGI8IqOf2a_lwP8yqaSIwQs-oZK-GIB9aR1-CE"],"content":{"ban":50,"events":{},"events_default":0,"invite":50,"kick":50,"redact":50,"state_default":50,"users":{},"users_default":0},"depth":3,"hashes":{"sha256":"PGeOq4iOQ7YVaOsYA3MCM+qWg47coRhaWhSfcLNtdro"},"origin_server_ts":1792750262172,"prev_events":["$5nOxHSGI8IqOf2a_lwP8yqaSIwQs-oZK-GIB9aR1-CE"],"room_id":"!Ic8TlLD2IJRkiuVOQLk3Sa2aMgGqQqAh0lCVfPvuopM","sender":"@alice:example.org","signatures":{"example.org":{"ed25519:ac2d510c":"2BFeZN53Fl+69teqQJNMNikxNRy9vasFhWz3iyGPwaU4qCw5aUnnZaEm7tHKoZmf0RHp47DF73WlpIxHVTV4Cg"}},"state_key":"","type":"m.room.power_levels"}', '3', '19');
INSERT INTO public.events (event_id, room_id, sender_user_id, json, depth, stream_ordering) VALUES ('$emYLQiGP0XWcov5YjluNNYaKcS9ypfHkwDHsGkJxc-4', '!Ic8TlLD2IJRkiuVOQLk3Sa2aMgGqQqAh0lCVfPvuopM', '@alice:example.org', '{"auth_events":["$5nOxHSGI8IqOf2a_lwP8yqaSIwQs-oZK-GIB9aR1-CE","$KcUeD1n_N2qMfVYYymDEtk-bUIagq8T0fDs-Z1C22F8"],"content":{"alias":"#upgrade-public:example.org"},"depth":4,"hashes":{"sha256":"SM9VGKZEMF5gA+qcr8tI23hZHCIP+PxkJXCOucBKD4k"},"origin_server_ts":1792750262177,"prev_events":["$KcUeD1n_N2qMfVYYymDEtk-bUIagq8T0fDs-Z1C22F8"],"room_id":"!Ic8TlLD2IJRkiuVOQLk3Sa2aMgGqQqAh0lCVfPvuopM","sender":"@alice:example.org","signatures":{"example.org":{"ed25519:ac2d510c":"LXgimFfBxT5TIRczebbRe25WPaRWoCiTcJaGRITEWFnpYPCWTnJ3NJ2NRa1BTCg+r0H1MNhjGWkJbxcD9oJWAA"}},"state_key":"","type":"m.room.canonical_alias"}', '4', '20');
INSERT INTO public.events (event_id, room_id, sender_user_id, json, depth, stream_ordering) VALUES ('$Tj9XNWsarQZusIJAuUcmQ_XIX-4_sAzVP5VUj6g2vMk', '!Ic8TlLD2IJRkiuVOQLk3Sa2aMgGqQqAh0lCVfPvuopM', '@alice:example.org', '{"auth_events":["$5nOxHSGI8IqOf2a_lwP8yqaSIwQs-oZK-GIB9aR1-CE","$KcUeD1n_N2qMfVYYymDEtk-bUIagq8T0fDs-Z1C22F8"],"content":{"join_rule":"public"},"depth":5,"hashes":{"sha256":"lQHmYSaXd5UOLoZqdSKqg0MCeTNFMst6Cdl5eLjL+VE"},"origin_server_ts":1792750262184,"prev_events":["$emYLQiGP0XWcov5YjluNNYaKcS9ypfHkwDHsGkJxc-4"],"room_id":"!Ic8TlLD2IJRkiuVOQLk3Sa2aMgGqQqAh0lCVfPvuopM","sender":"@alice:example.org","signatures":{"example.org":{"ed25519:ac2d510c":"lOBufilV9EGPZ1FiezmQdDFXkO6oDtHvrcEJSEKNA8kUqR3+4e8XJ+0LefQw2C/NqXEgXUwBQMNvFgiRwyq2Dg"}},"state_key":"","type":"m.room.join_rules"}', '5', '21');
INSERT INTO public.events (event_id, room_id, sender_user_id, json, depth, stream_ordering) VALUES ('$8AwgfgEPhgBOqsFJDIeMUZuYVxSBggibmsxwjU9MkZY', '!Ic8TlLD2IJRkiuVOQLk3Sa2aMgGqQqAh0lCVfPvuopM', '@alice:example.org', '{"auth_events":["$5nOxHSGI8IqOf2a_lwP8yqaSIwQs-oZK-GIB9aR1-CE","$KcUeD1n_N2qMfVYYymDEtk-bUIagq8T0fDs-Z1C22F8"],"content":{"history_visibility":"shared"},"depth":6,"hashes":{"sha256":"9+ClxkeOg4q0tLWApF8t7v5NI/LSGZPIpKg+XAxQH/E"},"origin_server_ts":1792750262189,"prev_events":["$Tj9XNWsarQZusIJAuUcmQ_XIX-4_sAzVP5VUj6g2vMk"],"room_id":"!Ic8TlLD2IJRkiuVOQLk3Sa2aMgGqQqAh0lCVfPvuopM","sender":"@alice:example.org","signatures":{"example.org":{"ed25519:ac2d510c":"XG2aPjgMAsbo7QGl5yuHHOU09xwagsoEf+iKyMegyUhNlKGD0zHdpH/KwTYvAzIRFM1h4AOr6+H4sa2t7fJ/Cg"}},"state_key":"","type":"m.room.history_visibility"}', '6', '22');
INSERT INTO public.events (event_id, room_id, sender_user_id, json, depth, stream_ordering) VALUES ('$5KAhYnMasuZPEbMdElqpPcg5xbY4tuAn4esKeyAwc4Y', '!Ic8TlLD2IJRkiuVOQLk3Sa2aMgGqQqAh0lCVfPvuopM', '@alice:example.org', '{"auth_events":["$5nOxHSGI8IqOf2a_lwP8yqaSIwQs-oZK-GIB9aR1-CE","$KcUeD1n_N2qMfVYYymDEtk-bUIagq8T0fDs-Z1C22F8"],"content":{"guest_access":"forbidden"},"depth":7,"hashes":{"sha256":"rKJ9qLJPAcgSYKum5vm7XuMi7SSXS8wSSd/0ThmTpX4"},"origin_server_ts":1792750262194,"prev_events":["$8AwgfgEPhgBOqsFJDIeMUZuYVxSBggibmsxwjU9MkZY"],"room_id":"!Ic8TlLD2IJRkiuVOQLk3Sa2aMgGqQqAh0lCVfPvuopM","sender":"@alice:example.org","signatures":{"example.org":{"ed25519:ac2d510c":"aI67KNCBNNUD6u3MPbknhA1PyY6+goSK0Ce5wZ6y3GBWMI81cnAGNAaAFZ0xnOYmDG25XjxDreAQvi/kNGmsCw"}},"state_key":"","type":"m.room.guest_access"}', '7', '23');
INSERT INTO public.events (event_id, room_id, sender_user_id, json, depth, stream_ordering) VALUES ('$Ddc9U0VrcERho-K0z__0oMsXraYcoMGzessOX97rP44', '!Ic8TlLD2IJRkiuVOQLk3Sa2aMgGqQqAh0lCVfPvuopM', '@alice:example.org', '{"auth_events":["$5nOxHSGI8IqOf2a_lwP8yqaSIwQs-oZK-GIB9aR1-CE","$KcUeD1n_N2qMfVYYymDEtk-bUIagq8T0fDs-Z1C22F8"],"content":{"name":"Upgrade Public"},"depth":8,"hashes":{"sha256":"F8pk1nhqFTHY9n2oh+iaUlSi885o+qLuJN2Yl7YlhfE"},"origin_server_ts":1792750262199,"prev_events":["$5KAhYnMasuZPEbMdElqpPcg5xbY4tuAn4esKeyAwc4Y"],"room_id":"!Ic8TlLD2IJRkiuVOQLk3Sa2aMgGqQqAh0lCVfPvuopM","sender":"@alice:example.org","signatures":{"example.org":{"ed25519:ac2d510c":"1ZEz6eDflBHVfH3Dq7X9S0wUQbJJknRqdrQlw2KusBf1cbs4rkjdkl6s3wkdZY9girScojTREoQViRfcnP1TAg"}},"state_key":"","type":"m.room.name"}', '8', '24');


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
-- Data for Name: invites; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: key_backup_sessions; Type: TABLE DATA; Schema: public; Owner: -
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
-- Data for Name: media; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.media (media_id, owner_user_id, content_type, size_bytes, hash_algorithm, digest, quarantined, removed) VALUES ('m1_9070012d53f9', '@alice:example.org', 'text/plain', '340', 'blake2b', '9070012d53f92cf3bbfd1c8987cb29cf9ba6d7b9804e90883c9912e0e6c83288', 'false', 'false');


--
-- Data for Name: media_blobs; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.media_blobs (storage_id, hash_algorithm, digest, size_bytes, bytes, ref_count) VALUES ('blob_9070012d53f92cf3bbfd1c8987cb29cf9ba6d7b9804e90883c9912e0e6c83288_340', 'blake2b', '9070012d53f92cf3bbfd1c8987cb29cf9ba6d7b9804e90883c9912e0e6c83288', '340', '\x6d65726f76696e6769616e20757067726164652066697874757265206d656469610a6d65726f76696e6769616e20757067726164652066697874757265206d656469610a6d65726f76696e6769616e20757067726164652066697874757265206d656469610a6d65726f76696e6769616e20757067726164652066697874757265206d656469610a6d65726f76696e6769616e20757067726164652066697874757265206d656469610a6d65726f76696e6769616e20757067726164652066697874757265206d656469610a6d65726f76696e6769616e20757067726164652066697874757265206d656469610a6d65726f76696e6769616e20757067726164652066697874757265206d656469610a6d65726f76696e6769616e20757067726164652066697874757265206d656469610a6d65726f76696e6769616e20757067726164652066697874757265206d656469610a', '1');


--
-- Data for Name: membership; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.membership (room_id, user_id, membership, stream_ordering) VALUES ('!PW80ohbgl9Y-TuRoQMsk1IQrNVbWabrWmKGlGXaEuas', '@alice:example.org', 'join', '0');
INSERT INTO public.membership (room_id, user_id, membership, stream_ordering) VALUES ('!PW80ohbgl9Y-TuRoQMsk1IQrNVbWabrWmKGlGXaEuas', '@bob:example.org', 'join', '12');
INSERT INTO public.membership (room_id, user_id, membership, stream_ordering) VALUES ('!Ic8TlLD2IJRkiuVOQLk3Sa2aMgGqQqAh0lCVfPvuopM', '@alice:example.org', 'join', '0');


--
-- Data for Name: notifications; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.notifications (user_id, room_id, event_id, stream_ordering, ts, actions, profile_tag, highlight) VALUES ('@bob:example.org', '!PW80ohbgl9Y-TuRoQMsk1IQrNVbWabrWmKGlGXaEuas', '$fnF-lqLGhlyzYg4ueoTe9549wDEXJKRpI-1oN4ZFtoA', '9', '1792750262079', '["notify",{"set_tweak":"sound","value":"default"}]', '', 'false');
INSERT INTO public.notifications (user_id, room_id, event_id, stream_ordering, ts, actions, profile_tag, highlight) VALUES ('@bob:example.org', '!PW80ohbgl9Y-TuRoQMsk1IQrNVbWabrWmKGlGXaEuas', '$LV4ggre4BtqcB7IaQzzNVhNlikCp0kBd7moi5iROKfo', '13', '1792750262117', '["notify",{"set_tweak":"sound","value":"default"}]', '', 'false');
INSERT INTO public.notifications (user_id, room_id, event_id, stream_ordering, ts, actions, profile_tag, highlight) VALUES ('@bob:example.org', '!PW80ohbgl9Y-TuRoQMsk1IQrNVbWabrWmKGlGXaEuas', '$Z0ytL9BlIFISIxrt2eTCRTJ7R7f42onZZRbe_2ImK5M', '14', '1792750262127', '["notify",{"set_tweak":"sound","value":"default"}]', '', 'false');
INSERT INTO public.notifications (user_id, room_id, event_id, stream_ordering, ts, actions, profile_tag, highlight) VALUES ('@bob:example.org', '!PW80ohbgl9Y-TuRoQMsk1IQrNVbWabrWmKGlGXaEuas', '$fLDkIkIn-ph02yfxRRffhu_AX3_wwIgZDH_Vr-YrKns', '15', '1792750262139', '["notify",{"set_tweak":"sound","value":"default"}]', '', 'false');
INSERT INTO public.notifications (user_id, room_id, event_id, stream_ordering, ts, actions, profile_tag, highlight) VALUES ('@alice:example.org', '!PW80ohbgl9Y-TuRoQMsk1IQrNVbWabrWmKGlGXaEuas', '$f2hX4Ca1BCVBlAJnBXCuINGRj3sqDsb-RWYp61-O3zY', '16', '1792750262150', '["notify",{"set_tweak":"sound","value":"default"}]', '', 'false');


--
-- Data for Name: one_time_keys; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.one_time_keys (user_id, device_id, key_id, json) VALUES ('@alice:example.org', 'UPGRADE1', 'signed_curve25519:AAAAAQ', '{"key":"9Z7XgBxsaacYytJUW/Rp5UlwDvYukAD+XUHRm2bNPjQ","signatures":{"@alice:example.org":{"ed25519:UPGRADE1":"H29aMpSHPHpsiaygOHGm6vewZCag4er3nlvI9CQBJvjLaSg8ZnKskrAg61DAtud2fpxjJDi8F6kSSp4vmKsJDQ"}}}');


--
-- Data for Name: openid_tokens; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: policy_rules; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: presence_state; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: profiles; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.profiles (user_id, displayname, avatar_url) VALUES ('@bob:example.org', '', '');
INSERT INTO public.profiles (user_id, displayname, avatar_url) VALUES ('@alice:example.org', 'Alice Upgrade', '');


--
-- Data for Name: push_rules; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: pushers; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.pushers (user_id, app_id, pushkey, kind, app_display_name, device_display_name, profile_tag, lang, data_url, data_format, data_extra_json) VALUES ('@alice:example.org', 'org.merovingian.upgrade', 'upgrade-pushkey', 'http', 'Upgrade Fixture App', 'Upgrade Fixture Device', '', 'en', 'https://push.example.org/_matrix/push/v1/notify', '', '');


--
-- Data for Name: rate_limits; Type: TABLE DATA; Schema: public; Owner: -
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

INSERT INTO public.room_aliases (room_alias, room_id) VALUES ('#upgrade-public:example.org', '!Ic8TlLD2IJRkiuVOQLk3Sa2aMgGqQqAh0lCVfPvuopM');


--
-- Data for Name: room_versions; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: rooms; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.rooms (room_id, creator_user_id) VALUES ('!PW80ohbgl9Y-TuRoQMsk1IQrNVbWabrWmKGlGXaEuas', '@alice:example.org');
INSERT INTO public.rooms (room_id, creator_user_id) VALUES ('!Ic8TlLD2IJRkiuVOQLk3Sa2aMgGqQqAh0lCVfPvuopM', '@alice:example.org');


--
-- Data for Name: schema_migrations; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.schema_migrations (version, name, direction) VALUES ('1', 'initial_schema', 'upgrade');
INSERT INTO public.schema_migrations (version, name, direction) VALUES ('2', 'sync_stream_watermark', 'upgrade');
INSERT INTO public.schema_migrations (version, name, direction) VALUES ('3', 'event_stream_watermark', 'upgrade');
INSERT INTO public.schema_migrations (version, name, direction) VALUES ('4', 'state_transitions', 'upgrade');
INSERT INTO public.schema_migrations (version, name, direction) VALUES ('5', 'backfill_state_transitions', 'upgrade');
INSERT INTO public.schema_migrations (version, name, direction) VALUES ('6', 'account_threepids', 'upgrade');
INSERT INTO public.schema_migrations (version, name, direction) VALUES ('7', 'account_threepids_columns', 'upgrade');
INSERT INTO public.schema_migrations (version, name, direction) VALUES ('8', 'pushers', 'upgrade');
INSERT INTO public.schema_migrations (version, name, direction) VALUES ('9', 'notifications', 'upgrade');
INSERT INTO public.schema_migrations (version, name, direction) VALUES ('10', 'openid_tokens', 'upgrade');
INSERT INTO public.schema_migrations (version, name, direction) VALUES ('11', 'pushers_data_extra', 'upgrade');


--
-- Data for Name: server_signing_keys; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.server_signing_keys (server_name, key_id, public_key, valid_until_ts, secret_key) VALUES ('example.org', 'ed25519:ac2d510c', 'rC1RDJm5tXMbkXdi7yy6N2Rk3wa5XXx3MkIQf5T+KWU', '1793355061536', '\x736563726574626f783a76313a77444b70756861574c592b782b57357a4a5359324c70642b784153336a426943457538704e63385331524d68746378496f794f4e4c4c6d536431646c68414e5779484757325754667746344b6e4f2b694b4572475a775670454e50746376476b513273595648345176567a526c6d645966313733312b515a317074454167354c654f624c76446975653863');


--
-- Data for Name: state_group_edges; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: state_groups; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: state_transitions; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.state_transitions (room_id, event_type, state_key, event_id, previous_event_id) VALUES ('!PW80ohbgl9Y-TuRoQMsk1IQrNVbWabrWmKGlGXaEuas', 'm.room.create', '', '$PW80ohbgl9Y-TuRoQMsk1IQrNVbWabrWmKGlGXaEuas', '');
INSERT INTO public.state_transitions (room_id, event_type, state_key, event_id, previous_event_id) VALUES ('!PW80ohbgl9Y-TuRoQMsk1IQrNVbWabrWmKGlGXaEuas', 'm.room.member', '@alice:example.org', '$F9JMTVXgFDNGp7iFGtx2TywcZGxTOnPJ9BsAxWeCEdw', '');
INSERT INTO public.state_transitions (room_id, event_type, state_key, event_id, previous_event_id) VALUES ('!PW80ohbgl9Y-TuRoQMsk1IQrNVbWabrWmKGlGXaEuas', 'm.room.power_levels', '', '$DHSsoabsUGpSCkU6E49p2ebYC871D2cTjt4jK9F_dPU', '');
INSERT INTO public.state_transitions (room_id, event_type, state_key, event_id, previous_event_id) VALUES ('!PW80ohbgl9Y-TuRoQMsk1IQrNVbWabrWmKGlGXaEuas', 'm.room.join_rules', '', '$0tndBnog_7KI3K9-4Hyq8LxDck8wQESjEpNyVIYYDQs', '');
INSERT INTO public.state_transitions (room_id, event_type, state_key, event_id, previous_event_id) VALUES ('!PW80ohbgl9Y-TuRoQMsk1IQrNVbWabrWmKGlGXaEuas', 'm.room.history_visibility', '', '$kU8vhg7WTtC-0NYMd38tEQ3g8OcQfIoa-WmSrtr7lI4', '');
INSERT INTO public.state_transitions (room_id, event_type, state_key, event_id, previous_event_id) VALUES ('!PW80ohbgl9Y-TuRoQMsk1IQrNVbWabrWmKGlGXaEuas', 'm.room.guest_access', '', '$4-VN3QWZ4vK176ipjhrwIH_XuwoN1o_qkOyzM4tBdbk', '');
INSERT INTO public.state_transitions (room_id, event_type, state_key, event_id, previous_event_id) VALUES ('!PW80ohbgl9Y-TuRoQMsk1IQrNVbWabrWmKGlGXaEuas', 'm.room.encryption', '', '$UDClrVbxTCAqUy48bsypr8_K628lTtk2_7Zct0xnOI0', '');
INSERT INTO public.state_transitions (room_id, event_type, state_key, event_id, previous_event_id) VALUES ('!PW80ohbgl9Y-TuRoQMsk1IQrNVbWabrWmKGlGXaEuas', 'm.room.name', '', '$VFlheYPtLdtWHAta0334y93R9EiAhDyMDRzz8jVgr-8', '');
INSERT INTO public.state_transitions (room_id, event_type, state_key, event_id, previous_event_id) VALUES ('!PW80ohbgl9Y-TuRoQMsk1IQrNVbWabrWmKGlGXaEuas', 'm.room.member', '@bob:example.org', '$fnF-lqLGhlyzYg4ueoTe9549wDEXJKRpI-1oN4ZFtoA', '');
INSERT INTO public.state_transitions (room_id, event_type, state_key, event_id, previous_event_id) VALUES ('!PW80ohbgl9Y-TuRoQMsk1IQrNVbWabrWmKGlGXaEuas', 'm.room.member', '@bob:example.org', '$UsILJ1Vb4ImkDlZVQzARExBIFeI-W5EKvdfPdd_HWRk', '$fnF-lqLGhlyzYg4ueoTe9549wDEXJKRpI-1oN4ZFtoA');
INSERT INTO public.state_transitions (room_id, event_type, state_key, event_id, previous_event_id) VALUES ('!Ic8TlLD2IJRkiuVOQLk3Sa2aMgGqQqAh0lCVfPvuopM', 'm.room.create', '', '$Ic8TlLD2IJRkiuVOQLk3Sa2aMgGqQqAh0lCVfPvuopM', '');
INSERT INTO public.state_transitions (room_id, event_type, state_key, event_id, previous_event_id) VALUES ('!Ic8TlLD2IJRkiuVOQLk3Sa2aMgGqQqAh0lCVfPvuopM', 'm.room.member', '@alice:example.org', '$5nOxHSGI8IqOf2a_lwP8yqaSIwQs-oZK-GIB9aR1-CE', '');
INSERT INTO public.state_transitions (room_id, event_type, state_key, event_id, previous_event_id) VALUES ('!Ic8TlLD2IJRkiuVOQLk3Sa2aMgGqQqAh0lCVfPvuopM', 'm.room.power_levels', '', '$KcUeD1n_N2qMfVYYymDEtk-bUIagq8T0fDs-Z1C22F8', '');
INSERT INTO public.state_transitions (room_id, event_type, state_key, event_id, previous_event_id) VALUES ('!Ic8TlLD2IJRkiuVOQLk3Sa2aMgGqQqAh0lCVfPvuopM', 'm.room.canonical_alias', '', '$emYLQiGP0XWcov5YjluNNYaKcS9ypfHkwDHsGkJxc-4', '');
INSERT INTO public.state_transitions (room_id, event_type, state_key, event_id, previous_event_id) VALUES ('!Ic8TlLD2IJRkiuVOQLk3Sa2aMgGqQqAh0lCVfPvuopM', 'm.room.join_rules', '', '$Tj9XNWsarQZusIJAuUcmQ_XIX-4_sAzVP5VUj6g2vMk', '');
INSERT INTO public.state_transitions (room_id, event_type, state_key, event_id, previous_event_id) VALUES ('!Ic8TlLD2IJRkiuVOQLk3Sa2aMgGqQqAh0lCVfPvuopM', 'm.room.history_visibility', '', '$8AwgfgEPhgBOqsFJDIeMUZuYVxSBggibmsxwjU9MkZY', '');
INSERT INTO public.state_transitions (room_id, event_type, state_key, event_id, previous_event_id) VALUES ('!Ic8TlLD2IJRkiuVOQLk3Sa2aMgGqQqAh0lCVfPvuopM', 'm.room.guest_access', '', '$5KAhYnMasuZPEbMdElqpPcg5xbY4tuAn4esKeyAwc4Y', '');
INSERT INTO public.state_transitions (room_id, event_type, state_key, event_id, previous_event_id) VALUES ('!Ic8TlLD2IJRkiuVOQLk3Sa2aMgGqQqAh0lCVfPvuopM', 'm.room.name', '', '$Ddc9U0VrcERho-K0z__0oMsXraYcoMGzessOX97rP44', '');


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

INSERT INTO public.users (user_id, password_hash, locked, suspended, admin) VALUES ('@alice:example.org', 'password-hash:v2:$argon2id$v=19$m=65536,t=2,p=1$38X5LIZI9pU6l5+SMbB0Wg$EFp6LYzUYqr/3woVpDOyT2FpUEyBECnmaZ1m2nWvzeI', 'false', 'false', 'false');
INSERT INTO public.users (user_id, password_hash, locked, suspended, admin) VALUES ('@bob:example.org', 'password-hash:v2:$argon2id$v=19$m=65536,t=2,p=1$SMHZpp9EEJQtSCCAbf08zQ$MK92wg4QIpa+d7quz5zxM3KDRBv9g7l3pqBdFiKJm6A', 'false', 'false', 'false');


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
-- Name: client_txn_ids client_txn_ids_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.client_txn_ids
    ADD CONSTRAINT client_txn_ids_pkey PRIMARY KEY (user_id, room_id, event_type, txn_id);


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
-- Name: media_blobs media_blobs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.media_blobs
    ADD CONSTRAINT media_blobs_pkey PRIMARY KEY (storage_id);


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
-- PostgreSQL database dump complete
--


