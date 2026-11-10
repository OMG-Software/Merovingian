// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/core/CopyableConditionVariable.hpp"
#include "merovingian/core/CopyableMutex.hpp"
#include "merovingian/federation/BadSignatureBucket.hpp"
#include "merovingian/federation/FederationAcceptedTransaction.hpp"
#include "merovingian/federation/FederationKeyRecord.hpp"
#include "merovingian/federation/FederationRateLimitBucket.hpp"
#include "merovingian/federation/FederationRemoteRuntime.hpp"
#include "merovingian/federation/KeyResolutionBucket.hpp"
#include "merovingian/federation/KeyResolutionFailure.hpp"
#include "merovingian/federation/RuntimeFederationConfig.hpp"
#include "merovingian/federation/InboundIngestion.hpp"
#include "merovingian/federation/InboundRequestProviders.hpp"
#include "merovingian/federation/MembershipEndpoints.hpp"
#include "merovingian/federation/ThirdPartyInvite.hpp"
#include "merovingian/observability/AuditLogEvent.hpp"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <list>
#include <optional>
#include <string_view>
#include <type_traits>
#include <vector>

namespace merovingian::federation
{

struct FederationRuntimeState final
{
    RuntimeFederationConfig config{};
    // Protects federation-local mutable bookkeeping while homeserver-level
    // federation dispatch runs without HomeserverRuntime::mutex.
    core::CopyableMutex mutex{};
    std::vector<FederationRemoteRuntime> remotes{};
    // Replay-dedup ring (see #416): capped at kMaxAcceptedTransactions
    // (InboundRequest.cpp) so a sustained stream of distinct transaction ids
    // cannot grow the main process's memory without bound. Entries are always
    // appended in acceptance order under federation_guard(), so the oldest
    // entry is always at the front — a plain FIFO pop_front() eviction (O(1)
    // on a list) is enough to keep this bounded.
    std::list<FederationAcceptedTransaction> accepted_transactions{};
    // Total bytes of the response_body values kept in accepted_transactions,
    // bounded by config.accepted_transaction_cache_bytes (ADR-0283).
    std::size_t accepted_transaction_bytes{0U};
    std::vector<FederationRateLimitBucket> rate_limit_buckets{};
    // Bounded audit ring (#423): capped at kMaxAuditEvents
    // (InboundRequest.cpp) with FIFO eviction, mirroring
    // accepted_transactions above. unsafe_audit_events counts retained
    // entries whose reason_code carries signature/token material so
    // federation_audit_is_safe stays O(1).
    std::list<observability::AuditLogEvent> audit_events{};
    std::size_t unsafe_audit_events{0U};
    RemoteKeyResolver remote_key_resolver{};
    // Optional, strictly network-free lookup of a PDU verification key. Remote
    // keys must satisfy the cache freshness policy; local retained keys stay local.
    // A hit is still verified against the event timestamp by PDU authorization.
    std::function<std::optional<FederationKeyRecord>(std::string_view, std::string_view)> cached_pdu_key_lookup{};
    RemoteKeyCacheProbe remote_key_cache_probe{};
    // Pre-authentication key-resolution budget state. Unlike rate_limit_buckets
    // above -- which is keyed on an already-verified origin and so bounded by
    // the number of real federating peers -- these are reachable before any
    // identity is established, so both containers are explicitly capped with
    // FIFO eviction (kMaxKeyResolutionBuckets / kMaxKeyResolutionFailures in
    // InboundRequest.cpp). An unbounded pre-auth map is the very DoS this
    // budget exists to prevent.
    std::list<KeyResolutionBucket> key_resolution_buckets{};
    std::list<KeyResolutionFailure> key_resolution_failures{};
    // Failed-signature budget per source address. Pre-authentication like the
    // containers above, so capped with FIFO eviction (kMaxBadSignatureBuckets
    // in InboundRequest.cpp).
    std::list<BadSignatureBucket> bad_signature_buckets{};
    // Resolutions currently in flight process-wide. Guarded by `mutex`; the
    // resolver call itself runs unlocked, so this is incremented before the
    // call and decremented after by a scope guard.
    std::uint32_t key_resolutions_in_flight{0U};
    // Notified after key_resolutions_in_flight is decremented, for the one
    // admission path that waits for a slot (resolve_join_state_key).
    core::CopyableConditionVariable key_resolution_slot_released{};
    // Optional ingestion hooks. When set, accepted PDUs are appended to the
    // event graph via pdu_sink and accepted EDUs are routed to runtime
    // surfaces (typing tracker, receipt store, etc.) via edu_sink. Both
    // hooks are invoked from handle_inbound_federation_request.
    PduSink pdu_sink{};
    EduSink edu_sink{};
    // Federation membership and history endpoints. Optional: when unset
    // the handler returns 501 Not Implemented for the corresponding route
    // so callers know to fall back to the legacy "log and accept" stub
    // behaviour rather than appearing to succeed.
    MembershipTemplateProvider membership_template_provider{};
    MembershipAcceptor membership_acceptor{};
    InviteHandler invite_handler{};
    // Issues the invite for an `exchange_third_party_invite` (ADR-0484). Unset (a worker): the endpoint answers 501.
    ThirdPartyInviteExchanger third_party_invite_exchanger{};
    BackfillProvider backfill_provider{};
    // Optional resolver for inbound `query/directory`. When unset the handler
    // responds 501 Not Implemented.
    DirectoryQueryProvider directory_query_provider{};
    // Optional provider for the inbound published room directory. When unset the handler responds 501
    // Not Implemented.
    PublicRoomsProvider public_rooms_provider{};
    // Optional resolver for inbound `query/profile`. When unset the handler
    // responds 501 Not Implemented.
    ProfileQueryProvider profile_query_provider{};
    // Optional resolvers for inbound E2EE key federation routes. Each unset
    // hook makes its route respond 501 Not Implemented.
    DeviceKeysQueryProvider device_keys_query_provider{};
    OneTimeKeysClaimProvider one_time_keys_claim_provider{};
    UserDevicesProvider user_devices_provider{};
    // Optional resolvers for inbound event-graph queries. Each unset hook
    // makes its route respond 501 Not Implemented.
    EventQueryProvider event_query_provider{};
    StateQueryProvider state_query_provider{};
    StateIdsQueryProvider state_ids_query_provider{};
    EventAuthQueryProvider event_auth_query_provider{};
    MissingEventsQueryProvider missing_events_query_provider{};
    TimestampToEventQueryProvider timestamp_to_event_query_provider{};
    // Optional resolver for inbound space hierarchy. When unset the handler
    // responds 501 Not Implemented.
    SpaceHierarchyProvider space_hierarchy_provider{};
    // Optional provider for inbound federation media downloads. When unset the
    // handler responds 501 Not Implemented.
    MediaDownloadProvider media_download_provider{};
    // Optional provider for inbound federation thumbnails; as above, 501 when unset.
    MediaThumbnailProvider media_thumbnail_provider{};
    // Optional resolver for room version. When set, parse_federation_pdu
    // calls it with the room_id from the PDU JSON and uses the returned
    // version string for event-ID computation and signature verification.
    // When unset, both operations fall back to room version "12".
    RoomVersionResolver room_version_resolver{};
    // Optional provider for per-room server ACL enforcement (MSC4436).
    // When unset, ACL checks are skipped (e.g. in low-level unit tests).
    RoomServerAclProvider room_server_acl_provider{};
    // Optional admin rules for operator_policy_refusal. A worker has no authority over them: its answer is empty
    // and main judges what it relays (ADR-0358, ADR-0390).
    ServerPolicyRefusalProvider server_policy_refusal_provider{};
    PduStoredProbe pdu_already_stored{};
};

static_assert(std::is_nothrow_move_constructible_v<FederationRuntimeState> &&
              std::is_nothrow_move_assignable_v<FederationRuntimeState>);

} // namespace merovingian::federation
