// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/url_preview_service.hpp"

#include "merovingian/canonicaljson/serializer.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/federation/server_discovery.hpp"
#include "merovingian/homeserver/client_outbound_proxy.hpp"
#include "merovingian/homeserver/local_services.hpp"
#include "merovingian/homeserver/remote_media_fetch_coalescer.hpp"
#include "merovingian/homeserver/remote_media_fetch_scope.hpp"
#include "merovingian/homeserver/request_lock.hpp"
#include "merovingian/http/outbound_client.hpp"
#include "merovingian/media/repository.hpp"
#include "merovingian/media/url_preview.hpp"
#include "merovingian/observability/logger.hpp"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace merovingian::homeserver
{
namespace
{

    auto log_diagnostic(std::string_view event, std::vector<observability::StructuredLogField> fields,
                        observability::LogEventSeverity severity = observability::LogEventSeverity::debug) -> void
    {
        observability::log_diagnostic("media_service", "url_preview." + std::string{event}, fields, severity);
    }

    // A URL that cannot be previewed: refused by the SSRF gate, unreachable,
    // too slow, too large, too many redirects or an HTTP error. All of them
    // look the same to the client, so the endpoint cannot be used to learn
    // which internal names resolve or which addresses answer (ADR-0213).
    constexpr auto preview_unavailable = std::string_view{"URL preview unavailable"};
    // Failures are cached for at most this long, successes for the configured TTL.
    constexpr auto max_failure_cache_seconds = std::uint32_t{300U};

    [[nodiscard]] auto refused(std::uint16_t status, std::string_view errcode, std::string_view reason)
        -> OperationResult
    {
        auto result = make_operation_result(false, {}, std::string{reason}, status);
        result.errcode = std::string{errcode};
        return result;
    }

    [[nodiscard]] auto unavailable() -> OperationResult
    {
        return refused(502U, "M_UNKNOWN", preview_unavailable);
    }

    [[nodiscard]] auto wall_clock_ms() -> std::uint64_t
    {
        return static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
                .count());
    }

    [[nodiscard]] auto find_header(std::vector<http::OutboundHeader> const& headers, std::string_view name)
        -> std::string
    {
        for (auto const& header : headers)
        {
            if (header.name.size() == name.size() && std::ranges::equal(header.name, name, [](char a, char b) {
                    auto const lower = [](char c) {
                        return c >= 'A' && c <= 'Z' ? static_cast<char>(c - 'A' + 'a') : c;
                    };
                    return lower(a) == lower(b);
                }))
            {
                return header.value;
            }
        }
        return {};
    }

    [[nodiscard]] auto is_redirect(std::uint16_t status) noexcept -> bool
    {
        return status == 301U || status == 302U || status == 303U || status == 307U || status == 308U;
    }

    struct GatedFetch final
    {
        bool ok{false};
        std::string reason{};
        std::string content_type{};
        std::string body{};
        // The URL the content finally came from, after redirects.
        std::string final_url{};
    };

    // Everything the gate needs from the runtime, copied while runtime.mutex
    // is held, so the released regions touch no runtime state.
    struct FetchContext final
    {
        http::OutboundClient* outbound_client{nullptr};
        federation::ServerDiscoveryNetwork* discovery_network{nullptr};
        std::vector<std::string> denied_ranges{};
        std::uint32_t max_redirects{0U};
    };

    // ADR-0213: the one way a preview reaches the network. Each hop is parsed
    // strictly (http or https; no userinfo, fragment or encoded authority),
    // resolved, and refused unless every address is public and outside
    // `denied_ranges`; the connection is then pinned to those addresses, so a
    // second DNS answer cannot redirect it. Redirects are followed here, never
    // by the HTTP client, and every hop goes through the same check. Runs with
    // runtime.mutex held; releases it for DNS and for each request.
    [[nodiscard]] auto gated_fetch(HomeserverRuntime& runtime, FetchContext const& context, std::string const& url,
                                   std::size_t max_bytes, OutboundDeadline const& deadline) -> GatedFetch
    {
        auto current = url;
        for (auto hop = std::uint32_t{0U}; hop <= context.max_redirects; ++hop)
        {
            auto const parsed = http::parse_outbound_url(current, true);
            if (!parsed.has_value() || (parsed->scheme != "https" && parsed->scheme != "http"))
            {
                return {false, "URL is not an absolute http or https URL"};
            }
            auto const budget = deadline.remaining_seconds();
            if (budget == 0U)
            {
                return {false, "deadline exceeded"};
            }
            auto pinned = std::vector<std::string>{};
            auto trusted_ca_pem = std::string{};
            // Test-only seam (TestOnlyForcedOutboundResolution): empty in
            // production, so every production hop resolves below.
            if (auto const forced = runtime.test_forced_outbound_resolution.find(parsed->host);
                forced != runtime.test_forced_outbound_resolution.end())
            {
                pinned = forced->second.pinned_addresses;
                trusted_ca_pem = forced->second.trusted_ca_pem;
            }
            else
            {
                auto const resolution = [&context, &parsed] {
                    auto const unlocked = RuntimeLockRelease{};
                    return federation::resolve_federation_destination(
                        parsed->host, parsed->port, *context.discovery_network, context.denied_ranges);
                }();
                if (!resolution.discovery_allowed)
                {
                    log_diagnostic("fetch.refused_address",
                                   {
                                       {"host",   parsed->host,      false},
                                       {"reason", resolution.reason, false}
                    });
                    return {false, "destination refused: " + resolution.reason};
                }
                pinned = resolution.pinned_addresses;
            }

            auto request = http::OutboundRequest{};
            request.method = "GET";
            request.url = parsed->url;
            request.pinned_addresses = std::move(pinned);
            request.trusted_ca_pem = std::move(trusted_ca_pem);
            // ADR-0213: a preview is the one client-named destination allowed
            // over cleartext. The request carries no credential, the response
            // is treated as hostile either way, and the address pin and peer
            // check apply to http exactly as to https.
            request.allow_cleartext_http = parsed->scheme == "http";
            request.connect_timeout_seconds = std::min(budget, 5U);
            request.total_timeout_seconds = budget;
            request.max_response_body_bytes = max_bytes;
            request.headers = {
                {"Accept",     "text/html, application/xhtml+xml, image/*;q=0.8"},
                {"User-Agent", "Merovingian URL preview"                        },
            };
            auto const result = [&context, &request] {
                auto const unlocked = RuntimeLockRelease{};
                return context.outbound_client->perform(request);
            }();
            if (is_redirect(result.response.status))
            {
                auto next =
                    media::resolve_preview_reference(parsed->url, find_header(result.response.headers, "location"));
                if (next.empty())
                {
                    return {false, "redirect without a usable Location"};
                }
                current = std::move(next);
                continue;
            }
            if (!result.ok)
            {
                return {false, std::string{http::outbound_error_name(result.error)}};
            }
            if (result.response.status < 200U || result.response.status >= 300U)
            {
                return {false, "remote returned " + std::to_string(result.response.status)};
            }
            return {true, {}, find_header(result.response.headers, "content-type"), result.response.body, parsed->url};
        }
        return {false, "too many redirects"};
    }

    [[nodiscard]] auto digits_only(std::string_view value) noexcept -> bool
    {
        return !value.empty() && value.size() <= 9U && std::ranges::all_of(value, [](char c) {
            return c >= '0' && c <= '9';
        });
    }

    // The spec's 200 body: the OpenGraph properties, og:image replaced by the
    // mxc:// URI of the stored image (with matrix:image:size), and
    // og:image:width/height as integers. og:title falls back to <title>.
    [[nodiscard]] auto preview_body(media::OpenGraphData const& data, std::optional<std::string> const& image_uri,
                                    std::uint64_t image_size, std::string_view image_type) -> std::string
    {
        auto members = canonicaljson::Object{};
        auto has_title = false;
        auto has_image_type = false;
        for (auto const& [key, value] : data.properties)
        {
            if (key == "og:image" || key == "og:image:url" || key == "og:image:secure_url")
            {
                continue;
            }
            if (!image_uri.has_value() && key.starts_with("og:image:"))
            {
                continue;
            }
            has_title = has_title || key == "og:title";
            has_image_type = has_image_type || key == "og:image:type";
            if ((key == "og:image:width" || key == "og:image:height") && digits_only(value))
            {
                members.push_back(canonicaljson::make_member(
                    key, canonicaljson::Value{static_cast<std::int64_t>(std::stoll(value))}));
                continue;
            }
            members.push_back(canonicaljson::make_member(key, canonicaljson::Value{value}));
        }
        if (!has_title && !data.title.empty())
        {
            members.push_back(canonicaljson::make_member("og:title", canonicaljson::Value{data.title}));
        }
        if (image_uri.has_value())
        {
            members.push_back(canonicaljson::make_member("og:image", canonicaljson::Value{*image_uri}));
            members.push_back(canonicaljson::make_member("matrix:image:size",
                                                         canonicaljson::Value{static_cast<std::int64_t>(image_size)}));
            if (!has_image_type && !image_type.empty())
            {
                members.push_back(
                    canonicaljson::make_member("og:image:type", canonicaljson::Value{std::string{image_type}}));
            }
        }
        auto const serialized = canonicaljson::serialize_canonical(canonicaljson::Value{std::move(members)});
        return serialized.error == canonicaljson::CanonicalJsonError::none ? serialized.output : std::string{"{}"};
    }

    // Fetches, parses and stores; the caller holds the coalescing lead and
    // caches the outcome.
    [[nodiscard]] auto build_preview(HomeserverRuntime& runtime, std::string_view user_id, std::string const& url,
                                     FetchContext const& context, OutboundDeadline const& deadline)
        -> std::optional<std::string>
    {
        auto const& config = runtime.media_repository.config;
        auto const page = gated_fetch(runtime, context, url, config.url_preview_max_page_bytes, deadline);
        if (!page.ok)
        {
            log_diagnostic("fetch.failed", {
                                               {"reason", page.reason, false}
            });
            return std::nullopt;
        }
        if (!media::content_type_is_html(page.content_type))
        {
            // Spec: "The OpenGraph data for the URL, which may be empty."
            return std::string{"{}"};
        }
        // The page is up to url_preview_max_page_size of hostile HTML: parse it
        // without runtime.mutex. extract_open_graph is pure and linear.
        auto const data = [&page] {
            auto const unlocked = RuntimeLockRelease{};
            return media::extract_open_graph(page.body);
        }();

        auto image_uri = std::optional<std::string>{};
        auto image_size = std::uint64_t{0U};
        auto image_type = std::string{};
        auto const image = std::ranges::find_if(data.properties, [](auto const& property) {
            return property.first == "og:image" || property.first == "og:image:secure_url" ||
                   property.first == "og:image:url";
        });
        if (image != data.properties.end())
        {
            auto const image_url = media::resolve_preview_reference(page.final_url, image->second);
            auto const max_image =
                std::min(config.url_preview_max_image_bytes,
                         config.max_upload_bytes == 0U ? config.url_preview_max_image_bytes : config.max_upload_bytes);
            auto const fetched = image_url.empty() ? GatedFetch{false, "og:image is not a usable URL"}
                                                   : gated_fetch(runtime, context, image_url,
                                                                 static_cast<std::size_t>(max_image), deadline);
            if (fetched.ok && !fetched.body.empty())
            {
                // Stored like an upload by this user: MIME policy, scanner,
                // quarantine, size limit and the user's quotas all apply.
                auto const stored = store_fetched_media_for_user(runtime, user_id, fetched.content_type, fetched.body);
                if (stored.ok)
                {
                    auto const first = stored.value.find('|');
                    auto const second = stored.value.find('|', first + 1U);
                    image_uri = stored.value.substr(0U, first);
                    image_size = static_cast<std::uint64_t>(fetched.body.size());
                    image_type = stored.value.substr(second + 1U);
                }
                else
                {
                    log_diagnostic("image.not_stored", {
                                                           {"reason", stored.reason, false}
                    });
                }
            }
            else
            {
                log_diagnostic("image.fetch_failed", {
                                                         {"reason", fetched.reason, false}
                });
            }
        }
        return preview_body(data, image_uri, image_size, image_type);
    }

} // namespace

auto preview_url(HomeserverRuntime& runtime, std::string_view user_id, std::string_view url,
                 RemoteMediaRequestContext const& remote) -> OperationResult
{
    auto const& config = runtime.media_repository.config;
    if (!config.url_preview_enabled)
    {
        // Off by default (ADR-0213): to a client the endpoint does not exist.
        return refused(404U, "M_UNRECOGNIZED", "URL previews are disabled on this server");
    }
    if (url.empty())
    {
        return refused(400U, "M_MISSING_PARAM", "url is required");
    }
    auto const parsed = url.size() > media::max_preview_url_bytes ? std::nullopt : http::parse_outbound_url(url, true);
    if (!parsed.has_value() || (parsed->scheme != "https" && parsed->scheme != "http"))
    {
        return refused(400U, "M_INVALID_PARAM", "url must be an absolute http or https URL");
    }
    auto const key = parsed->url;

    auto const answer_from_cache = [&runtime, &key]() -> std::optional<OperationResult> {
        auto const cached = runtime.url_preview_cache.find(key, wall_clock_ms());
        if (!cached.has_value())
        {
            return std::nullopt;
        }
        return cached->ok ? make_operation_result(true, cached->body, {}, 200U) : unavailable();
    };
    if (auto cached = answer_from_cache(); cached.has_value())
    {
        return std::move(*cached);
    }
    if (runtime.outbound_client == nullptr || runtime.discovery_network == nullptr)
    {
        return unavailable();
    }

    // ADR-0121: never on a main-pool thread. The transport hands the request
    // to the media fetch pool, whose admission bounds concurrent previews.
    auto const mode = RemoteMediaFetchScope::current_mode();
    if (mode == RemoteMediaFetchMode::defer && RemoteMediaFetchScope::record_deferral())
    {
        return make_operation_result(false, {}, "URL preview deferred to the media fetch pool", 503U);
    }
    // ADR-0079: run inline (no media pool), the fetch holds a request thread,
    // so it takes a client-outbound slot first, as a remote media fetch does.
    auto const slot = mode == RemoteMediaFetchMode::inline_fetch
                          ? admit_client_outbound_proxy(runtime, remote.client_key)
                          : std::optional<http::InFlightBudget::Slot>{};
    if (mode == RemoteMediaFetchMode::inline_fetch && !slot.has_value())
    {
        auto throttled = refused(429U, "M_LIMIT_EXCEEDED", "too many concurrent URL previews");
        throttled.retry_after_ms = runtime.client_outbound_proxy_policy.retry_after_ms;
        return throttled;
    }
    auto const deadline = OutboundDeadline{config.url_preview_timeout_seconds};

    // One fetch per URL at a time; a second request for it waits for the
    // first (with runtime.mutex released) and then reads the cache.
    auto& coalescer = *runtime.remote_media_fetch_coalescer;
    auto const coalesce_key = "preview:" + key;
    auto const lead = [&]() -> std::variant<RemoteMediaFetchCoalescer::Lead, OperationResult> {
        while (true)
        {
            if (auto held = coalescer.try_lead(coalesce_key); held.has_value())
            {
                return std::move(*held);
            }
            auto const idle = [&coalescer, &coalesce_key, &deadline] {
                auto const unlocked = RuntimeLockRelease{};
                return coalescer.wait_until_idle(coalesce_key, deadline.end());
            }();
            if (auto cached = answer_from_cache(); cached.has_value())
            {
                return std::move(*cached);
            }
            if (!idle || deadline.expired())
            {
                return unavailable();
            }
        }
    }();
    if (std::holds_alternative<OperationResult>(lead))
    {
        return std::get<OperationResult>(lead);
    }

    auto const context = FetchContext{runtime.outbound_client.get(), runtime.discovery_network.get(),
                                      runtime.federation.config.deny_ip_ranges, config.url_preview_max_redirects};
    auto const body = build_preview(runtime, user_id, key, context, deadline);
    auto const now = wall_clock_ms();
    auto const ttl_seconds = body.has_value()
                                 ? config.url_preview_cache_ttl_seconds
                                 : std::min(config.url_preview_cache_ttl_seconds, max_failure_cache_seconds);
    if (ttl_seconds > 0U)
    {
        runtime.url_preview_cache.store(
            key,
            {body.has_value(), body.value_or(std::string{}), now + static_cast<std::uint64_t>(ttl_seconds) * 1000U},
            config.url_preview_cache_max_entries);
    }
    log_diagnostic(body.has_value() ? "preview.built" : "preview.unavailable",
                   {
                       {"actor", std::string{user_id}, false}
    });
    return body.has_value() ? make_operation_result(true, *body, {}, 200U) : unavailable();
}

} // namespace merovingian::homeserver
