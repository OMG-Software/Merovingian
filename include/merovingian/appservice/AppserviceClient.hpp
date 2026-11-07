// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/appservice/AppserviceCallResult.hpp"
#include "merovingian/appservice/AppservicePingResult.hpp"
#include "merovingian/appservice/AppserviceQueryResult.hpp"
#include "merovingian/appservice/AppserviceRegistration.hpp"
#include "merovingian/appservice/AppserviceThirdPartyLocationsResult.hpp"
#include "merovingian/appservice/AppserviceThirdPartyProtocolResult.hpp"
#include "merovingian/appservice/AppserviceThirdPartyUsersResult.hpp"
#include "merovingian/appservice/AppserviceTransaction.hpp"
#include "merovingian/appservice/ThirdPartyLocation.hpp"
#include "merovingian/appservice/ThirdPartyProtocol.hpp"
#include "merovingian/appservice/ThirdPartyUser.hpp"
#include "merovingian/canonicaljson/Value.hpp"
#include "merovingian/config/AppserviceConfig.hpp"
#include "merovingian/config/Config.hpp"
#include "merovingian/federation/CachedServerDiscovery.hpp"
#include "merovingian/http/OutboundClient.hpp"
#include "merovingian/http/OutboundRequest.hpp"
#include "merovingian/http/OutboundResult.hpp"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace merovingian::appservice
{

// Pure builder: no network, no I/O. Unit-testable in isolation.
[[nodiscard]] auto build_transaction_request_body(AppserviceTransaction const& transaction) -> std::string;

// The most bytes of an appservice's ping response body kept for the `body` of an M_BAD_STATUS error.
inline constexpr auto max_ping_body_bytes = std::size_t{1024U};

// Pure: the request body of `POST /_matrix/app/v1/ping`: `{"transaction_id":"..."}`, the ID "copied
// directly" from the client call (an empty string included), or `{}` when the appservice sent none.
[[nodiscard]] auto build_ping_request_body(std::optional<std::string_view> transaction_id) -> std::string;

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
// push::PushGatewayClient's shape, with deliberate differences: an
// appservice's registration `url` is OPERATOR-configured (a local
// filesystem artifact, not something a network peer can point at).
// Host resolution therefore goes through the SAME
// `CachedServerDiscovery`/`ServerDiscoveryNetwork` abstraction the
// federation and push-gateway clients use (never a raw socket, never ad-hoc
// DNS), but via `.upstream().lookup_addresses()` directly rather than the
// higher-level `discover_server()` - the private/loopback-address rejection
// that layer applies is specifically for attacker/client-influenced
// destinations, which an operator-configured appservice URL is not.
//
// Cleartext is restricted (ADR-0515), because every request carries the
// hs_token: an `https` url is used as given, and an `http` url is used only
// when its host is a loopback IP literal (127.0.0.0/8 or ::1; the name
// `localhost` is not one) or an exact, ASCII-case-insensitive entry of
// `AppserviceConfig::allow_cleartext_hosts`. A url with userinfo or a query
// string is refused too. `load_registrations` applies the same rule at start-up;
// this client applies it again before every call, and a refused call makes no
// lookup and no connection (it fails as `OutboundError::invalid_url`).
// `OutboundRequest::allow_cleartext_http` is set only after that check.
class AppserviceClient final
{
public:
    using Perform = std::function<http::OutboundResult(http::OutboundRequest const&)>;

    AppserviceClient(http::OutboundClient& outbound, federation::CachedServerDiscovery& discovery,
                     config::AppserviceConfig const& config = {}, Perform perform = {});

    // PUT /_matrix/app/v1/transactions/{txnId}. `disabled` is returned
    // immediately (no network I/O) when `registration.url` is nullopt.
    [[nodiscard]] auto send_transaction(AppserviceRegistration const& registration,
                                        AppserviceTransaction const& transaction) -> AppserviceCallResult;

    // POST /_matrix/app/v1/ping — "called by the homeserver to ensure that the connection works
    // and the hs_token the homeserver has is correct", as the direct result of the appservice
    // calling POST /_matrix/client/v1/appservice/{appserviceId}/ping. Sends the registration's
    // hs_token like every other call. Blocks for up to the configured total timeout, so a caller
    // must not hold runtime.mutex (RuntimeLockRelease) while it runs.
    [[nodiscard]] auto ping(AppserviceRegistration const& registration, std::optional<std::string_view> transaction_id)
        -> AppservicePingResult;

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
    std::uint32_t connect_timeout_seconds_{10U};
    std::uint32_t total_timeout_seconds_{30U};
    std::size_t response_max_size_bytes_{16U * 1024U * 1024U};
    std::vector<std::string> allow_cleartext_hosts_{};
    Perform perform_{};

    [[nodiscard]] auto perform_query(AppserviceRegistration const& registration, std::string_view path)
        -> AppserviceQueryResult;
};

} // namespace merovingian::appservice
