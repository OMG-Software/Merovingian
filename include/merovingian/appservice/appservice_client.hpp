// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/appservice/registration.hpp"
#include "merovingian/federation/cached_server_discovery.hpp"
#include "merovingian/http/outbound_client.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace merovingian::appservice
{

// One event in a `PUT /_matrix/app/v1/transactions/{txnId}` request body
// (Matrix v1.19 Application Service API §"Pushing events"). Mirrors the
// spec's `ClientEvent` shape. `content_json` is the pre-serialized `content`
// object (never re-parsed by the builder — the caller already has it from
// the persisted event).
struct AppserviceTransactionEvent final
{
    std::string content_json{}; // pre-serialized JSON object; empty means "{}"
    std::string event_id{};
    std::uint64_t origin_server_ts{0U};
    std::string room_id{};
    std::string sender{};
    std::optional<std::string> state_key{}; // present only for state events
    std::string type{};
};

// One `PUT /_matrix/app/v1/transactions/{txnId}` call's worth of events.
// `ephemeral` data (m.presence/m.typing/m.receipt, spec v1.13) is not yet
// implemented — see docs/todos/capability-gaps.md.
struct AppserviceTransaction final
{
    std::string txn_id{};
    std::vector<AppserviceTransactionEvent> events{};
};

// Pure builder: no network, no I/O. Unit-testable in isolation.
[[nodiscard]] auto build_transaction_request_body(AppserviceTransaction const& transaction) -> std::string;

// Outcome of one outbound call. `disabled` is set when the appservice's
// registration has `url: null` ("no traffic is required" per spec) — the
// caller made no network attempt at all.
struct AppserviceCallResult final
{
    bool ok{false};
    bool disabled{false};
    std::uint16_t status{0U};
    http::OutboundError error{http::OutboundError::none};
    std::string error_detail{};
};

// Outcome of a `GET /_matrix/app/v1/users/{userId}` or
// `GET /_matrix/app/v1/rooms/{roomAlias}` query. `exists` reflects the
// spec's contract exactly: true only on HTTP 200 ("this user/alias exists");
// false on 404 ("does not exist"); `ok` is false only for a transport
// failure or an unexpected status (401/403/5xx), which the caller must NOT
// treat as a negative existence answer.
struct AppserviceQueryResult final
{
    bool ok{false};
    bool disabled{false};
    std::uint16_t status{0U};
    bool exists{false};
    http::OutboundError error{http::OutboundError::none};
    std::string error_detail{};
};

// Outbound Application Service API client (Matrix v1.19). Mirrors
// push::PushGatewayClient's shape, with one deliberate difference: an
// appservice's registration `url` is OPERATOR-configured (a local
// filesystem artifact, not something a network peer can point at) — the
// spec's own canonical registration example gives a plain
// `http://127.0.0.1:1234` URL, which is also how most real-world bridges
// run. Host resolution therefore goes through the SAME
// `CachedServerDiscovery`/`ServerDiscoveryNetwork` abstraction the
// federation and push-gateway clients use (never a raw socket, never ad-hoc
// DNS), but via `.upstream().lookup_addresses()` directly rather than the
// higher-level `discover_server()` — the private/loopback-address rejection
// that layer applies is specifically for attacker/client-influenced
// destinations, which an operator-configured appservice URL is not. Outbound
// requests set `OutboundRequest::allow_cleartext_http = true` for the same
// reason; see that field's doc comment.
class AppserviceClient final
{
public:
    AppserviceClient(http::OutboundClient& outbound, federation::CachedServerDiscovery& discovery) noexcept;

    // PUT /_matrix/app/v1/transactions/{txnId}. `disabled` is returned
    // immediately (no network I/O) when `registration.url` is nullopt.
    [[nodiscard]] auto send_transaction(AppserviceRegistration const& registration,
                                        AppserviceTransaction const& transaction) -> AppserviceCallResult;

    // GET /_matrix/app/v1/users/{userId} — spec: "The homeserver will only
    // query user IDs inside the application service's users namespace." The
    // caller is responsible for that namespace check before calling this.
    [[nodiscard]] auto query_user(AppserviceRegistration const& registration, std::string_view user_id)
        -> AppserviceQueryResult;

    // GET /_matrix/app/v1/rooms/{roomAlias}.
    [[nodiscard]] auto query_room_alias(AppserviceRegistration const& registration, std::string_view room_alias)
        -> AppserviceQueryResult;

private:
    http::OutboundClient& outbound_;
    federation::CachedServerDiscovery& discovery_;

    [[nodiscard]] auto perform_query(AppserviceRegistration const& registration, std::string_view path)
        -> AppserviceQueryResult;
};

} // namespace merovingian::appservice
