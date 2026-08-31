// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/appservice/registration.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/federation/cached_server_discovery.hpp"
#include "merovingian/http/outbound_client.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
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

// A `field_types` entry of a `GET /_matrix/app/v1/thirdparty/protocol/{protocol}`
// response (Matrix v1.19 Application/Client-Server API "Third-party
// networks"/"Third-party Lookups"). Both members are opaque, untrusted
// strings supplied by the appservice — never interpreted, only bounded and
// echoed back to the client.
struct ThirdPartyFieldType final
{
    std::string placeholder{};
    std::string regexp{};
};

// One entry of a Protocol response's `instances` array. `icon` and
// `network_id` are the spec's optional/required fields respectively;
// `instance_id` is NOT stored here — the spec requires the HOMESERVER to
// mint it ("This field is added to the response ... by the homeserver"), so
// it is assigned when the client-server response is built, not when this
// type is parsed from the appservice's reply.
struct ThirdPartyProtocolInstance final
{
    std::string desc{};
    canonicaljson::Object fields{}; // preset search-field values; string members only (see .cpp)
    std::string icon{};             // empty means absent
    std::string network_id{};
};

// A `GET /_matrix/app/v1/thirdparty/protocol/{protocol}` response, bounded
// and type-checked field-by-field before being trusted. See appservice_
// client.cpp's parse_protocol_object for the exact bounds applied — an
// appservice/bridge is not a trusted peer (src/appservice/AGENTS.md).
struct ThirdPartyProtocol final
{
    std::vector<std::pair<std::string, ThirdPartyFieldType>> field_types{};
    std::string icon{};
    std::vector<ThirdPartyProtocolInstance> instances{};
    std::vector<std::string> location_fields{};
    std::vector<std::string> user_fields{};
};

// One entry of a `GET /_matrix/app/v1/thirdparty/location[/{protocol}]`
// response array (spec `Location` object).
struct ThirdPartyLocation final
{
    std::string alias{};
    canonicaljson::Object fields{};
    std::string protocol{};
};

// One entry of a `GET /_matrix/app/v1/thirdparty/user[/{protocol}]`
// response array (spec `User` object).
struct ThirdPartyUser final
{
    std::string userid{};
    canonicaljson::Object fields{};
    std::string protocol{};
};

// Outcome of `GET /_matrix/app/v1/thirdparty/protocol/{protocol}`. `found`
// mirrors the query-result convention above: true only on a 200 whose body
// parsed into a well-formed Protocol object; false on 404 ("no protocol was
// found") — `ok` is false only for a transport failure, an unexpected
// status, or a 200 whose body could not be parsed as a Protocol object
// (a malformed/hostile appservice reply), none of which the caller may
// treat as "not found".
struct AppserviceThirdPartyProtocolResult final
{
    bool ok{false};
    bool disabled{false};
    std::uint16_t status{0U};
    bool found{false};
    ThirdPartyProtocol protocol{};
    http::OutboundError error{http::OutboundError::none};
    std::string error_detail{};
};

// Outcome of a `GET /_matrix/app/v1/thirdparty/location[/{protocol}]` call.
struct AppserviceThirdPartyLocationsResult final
{
    bool ok{false};
    bool disabled{false};
    std::uint16_t status{0U};
    bool found{false};
    std::vector<ThirdPartyLocation> locations{};
    http::OutboundError error{http::OutboundError::none};
    std::string error_detail{};
};

// Outcome of a `GET /_matrix/app/v1/thirdparty/user[/{protocol}]` call.
struct AppserviceThirdPartyUsersResult final
{
    bool ok{false};
    bool disabled{false};
    std::uint16_t status{0U};
    bool found{false};
    std::vector<ThirdPartyUser> users{};
    http::OutboundError error{http::OutboundError::none};
    std::string error_detail{};
};

// Pure, network-free parsers for the untrusted `GET /_matrix/app/v1/
// thirdparty/*` JSON body the query_thirdparty_* methods below receive over
// the wire. Each takes an already-parsed `canonicaljson::Value` (e.g. from
// `canonicaljson::parse_json`) and applies the same bounded, type-checked
// extraction the live query path uses — dropping malformed entries rather
// than propagating them, and truncating/capping per the bounds documented
// on ThirdPartyProtocol/ThirdPartyLocation/ThirdPartyUser above. Exposed for
// the same reason build_transaction_request_body is: fully unit-testable
// without a mock network peer (src/appservice/AGENTS.md: "a bridge is not a
// trusted peer").
[[nodiscard]] auto parse_thirdparty_protocol_response(canonicaljson::Value const& parsed_body)
    -> std::optional<ThirdPartyProtocol>;
[[nodiscard]] auto parse_thirdparty_location_response(canonicaljson::Value const& parsed_body)
    -> std::vector<ThirdPartyLocation>;
[[nodiscard]] auto parse_thirdparty_user_response(canonicaljson::Value const& parsed_body)
    -> std::vector<ThirdPartyUser>;

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

    // GET /_matrix/app/v1/thirdparty/protocol/{protocol} — spec: "called by
    // the homeserver when it wants to present clients with specific
    // information about the various third-party networks that an
    // application service supports."
    [[nodiscard]] auto query_thirdparty_protocol(AppserviceRegistration const& registration, std::string_view protocol)
        -> AppserviceThirdPartyProtocolResult;

    // GET /_matrix/app/v1/thirdparty/location?alias={alias}.
    [[nodiscard]] auto query_thirdparty_location_by_alias(AppserviceRegistration const& registration,
                                                          std::string_view alias)
        -> AppserviceThirdPartyLocationsResult;

    // GET /_matrix/app/v1/thirdparty/location/{protocol}?<fields>, where
    // `fields` is forwarded verbatim as the outbound query string — the
    // protocol-defined search fields the client supplied are opaque to the
    // homeserver and passed straight through, per spec: "the search fields
    // will be passed along to the application service for filtering."
    [[nodiscard]] auto query_thirdparty_location_by_protocol(
        AppserviceRegistration const& registration, std::string_view protocol,
        std::vector<std::pair<std::string, std::string>> const& fields) -> AppserviceThirdPartyLocationsResult;

    // GET /_matrix/app/v1/thirdparty/user?userid={userid}.
    [[nodiscard]] auto query_thirdparty_user_by_userid(AppserviceRegistration const& registration,
                                                       std::string_view user_id) -> AppserviceThirdPartyUsersResult;

    // GET /_matrix/app/v1/thirdparty/user/{protocol}?<fields>.
    [[nodiscard]] auto query_thirdparty_user_by_protocol(AppserviceRegistration const& registration,
                                                         std::string_view protocol,
                                                         std::vector<std::pair<std::string, std::string>> const& fields)
        -> AppserviceThirdPartyUsersResult;

private:
    http::OutboundClient& outbound_;
    federation::CachedServerDiscovery& discovery_;

    [[nodiscard]] auto perform_query(AppserviceRegistration const& registration, std::string_view path)
        -> AppserviceQueryResult;
};

} // namespace merovingian::appservice
