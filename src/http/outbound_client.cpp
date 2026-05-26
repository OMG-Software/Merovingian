// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/http/outbound_client.hpp"

#include "merovingian/observability/logger.hpp"
#include "merovingian/observability/observability.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <limits>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include <curl/curl.h>

namespace merovingian::http
{

namespace
{

    using namespace std::string_view_literals;

    auto log_diagnostic(std::string_view event, std::vector<observability::StructuredLogField> fields) -> void
    {
        LOG_DEBUG(observability::diagnostic_log_summary("outbound_client", event, std::move(fields)));
    }

    constexpr auto https_scheme = "https://"sv;
    constexpr auto default_https_port = std::uint16_t{443U};

    // libcurl global init/cleanup guard. Constructed once on first use via a
    // function-local static (thread-safe per C++11+ magic statics) and torn
    // down at program exit. curl_global_init is documented as not thread-safe
    // so this guard must complete before any concurrent curl_easy_init call.
    class CurlGlobalGuard final
    {
    public:
        CurlGlobalGuard() noexcept
        {
            auto const code = curl_global_init(CURL_GLOBAL_DEFAULT);
            initialized_ = (code == CURLE_OK);
        }
        ~CurlGlobalGuard()
        {
            if (initialized_)
            {
                curl_global_cleanup();
            }
        }
        CurlGlobalGuard(CurlGlobalGuard const&) = delete;
        auto operator=(CurlGlobalGuard const&) -> CurlGlobalGuard& = delete;
        CurlGlobalGuard(CurlGlobalGuard&&) noexcept = delete;
        auto operator=(CurlGlobalGuard&&) noexcept -> CurlGlobalGuard& = delete;

        [[nodiscard]] auto initialized() const noexcept -> bool
        {
            return initialized_;
        }

    private:
        bool initialized_{false};
    };

    [[nodiscard]] auto ensure_curl_initialized() noexcept -> bool
    {
        static auto const guard = CurlGlobalGuard{};
        return guard.initialized();
    }

    [[nodiscard]] auto is_known_method(std::string_view method) noexcept -> bool
    {
        constexpr auto known = std::array{"GET"sv, "POST"sv, "PUT"sv, "DELETE"sv};
        return std::any_of(known.begin(), known.end(), [method](auto candidate) noexcept {
            return candidate == method;
        });
    }

    [[nodiscard]] auto starts_with_https(std::string_view url) noexcept -> bool
    {
        return url.size() > https_scheme.size() && url.substr(0U, https_scheme.size()) == https_scheme;
    }

    [[nodiscard]] auto url_host_segment_present(std::string_view url) noexcept -> bool
    {
        if (!starts_with_https(url))
        {
            return false;
        }
        auto const after_scheme = url.substr(https_scheme.size());
        if (after_scheme.empty())
        {
            return false;
        }
        auto const first = after_scheme.front();
        // Reject leading '/', ':', or '@' — these would mean the URL is missing
        // a host or carries credentials in the authority segment.
        return first != '/' && first != ':' && first != '@';
    }

    struct HostPort final
    {
        std::string host{};
        std::uint16_t port{default_https_port};
    };

    [[nodiscard]] auto parse_https_host_port(std::string_view url) -> std::optional<HostPort>
    {
        if (!starts_with_https(url))
        {
            return std::nullopt;
        }
        auto const after_scheme = url.substr(https_scheme.size());
        auto const slash_pos = after_scheme.find('/');
        auto const authority = slash_pos == std::string_view::npos ? after_scheme : after_scheme.substr(0U, slash_pos);
        if (authority.empty())
        {
            return std::nullopt;
        }
        auto const colon_pos = authority.find(':');
        if (colon_pos == std::string_view::npos)
        {
            return HostPort{std::string{authority}, default_https_port};
        }
        auto const host = authority.substr(0U, colon_pos);
        auto const port_str = authority.substr(colon_pos + 1U);
        if (host.empty() || port_str.empty())
        {
            return std::nullopt;
        }
        auto port = std::uint16_t{0U};
        auto const* begin = port_str.data();
        auto const* end = port_str.data() + port_str.size();
        auto const conv = std::from_chars(begin, end, port);
        if (conv.ec != std::errc{} || conv.ptr != end || port == 0U)
        {
            return std::nullopt;
        }
        return HostPort{std::string{host}, port};
    }

    // RAII wrapper for a curl_slist*. The list is freed in the destructor so
    // every exit path from perform() releases the allocation.
    class CurlSlistGuard final
    {
    public:
        CurlSlistGuard() noexcept = default;
        ~CurlSlistGuard()
        {
            if (list_ != nullptr)
            {
                curl_slist_free_all(list_);
            }
        }
        CurlSlistGuard(CurlSlistGuard const&) = delete;
        auto operator=(CurlSlistGuard const&) -> CurlSlistGuard& = delete;
        CurlSlistGuard(CurlSlistGuard&&) noexcept = delete;
        auto operator=(CurlSlistGuard&&) noexcept -> CurlSlistGuard& = delete;

        [[nodiscard]] auto append(std::string const& entry) noexcept -> bool
        {
            auto* updated = curl_slist_append(list_, entry.c_str());
            if (updated == nullptr)
            {
                return false;
            }
            list_ = updated;
            return true;
        }

        [[nodiscard]] auto get() const noexcept -> curl_slist*
        {
            return list_;
        }

    private:
        curl_slist* list_{nullptr};
    };

    struct ResponseSink final
    {
        std::string body{};
        std::vector<OutboundHeader> headers{};
        std::size_t cap{0U};
        bool too_large{false};
    };

    extern "C" auto mero_curl_write_body(char* ptr, std::size_t size, std::size_t nmemb, void* userdata) noexcept
        -> std::size_t
    {
        auto* sink = static_cast<ResponseSink*>(userdata);
        if (sink == nullptr)
        {
            return 0U;
        }
        auto const bytes = size * nmemb;
        // Guard against accumulating past the cap. The subtraction form avoids
        // any overflow concern if bytes is enormous.
        if (bytes > sink->cap - sink->body.size())
        {
            sink->too_large = true;
            return 0U;
        }
        sink->body.append(ptr, bytes);
        return bytes;
    }

    extern "C" auto mero_curl_write_header(char* buffer, std::size_t size, std::size_t nitems, void* userdata) noexcept
        -> std::size_t
    {
        auto* sink = static_cast<ResponseSink*>(userdata);
        if (sink == nullptr)
        {
            return 0U;
        }
        auto const bytes = size * nitems;
        auto line = std::string_view{buffer, bytes};
        // Strip trailing CRLF so the stored header values are clean.
        while (!line.empty() && (line.back() == '\r' || line.back() == '\n'))
        {
            line.remove_suffix(1U);
        }
        // Skip the status line and the blank separator between headers and body.
        if (line.empty() || line.starts_with("HTTP/"))
        {
            return bytes;
        }
        auto const colon = line.find(':');
        if (colon == std::string_view::npos)
        {
            return bytes;
        }
        auto name = line.substr(0U, colon);
        auto value = line.substr(colon + 1U);
        while (!value.empty() && (value.front() == ' ' || value.front() == '\t'))
        {
            value.remove_prefix(1U);
        }
        sink->headers.push_back(OutboundHeader{std::string{name}, std::string{value}});
        return bytes;
    }

    [[nodiscard]] auto map_curl_code(CURLcode code, ResponseSink const& sink) noexcept -> OutboundError
    {
        switch (code)
        {
        case CURLE_OK:
            return OutboundError::none;
        case CURLE_PEER_FAILED_VERIFICATION:
        case CURLE_SSL_CACERT_BADFILE:
        case CURLE_SSL_CERTPROBLEM:
        case CURLE_SSL_CIPHER:
        case CURLE_SSL_CONNECT_ERROR:
        case CURLE_SSL_ENGINE_INITFAILED:
        case CURLE_SSL_ENGINE_NOTFOUND:
        case CURLE_SSL_ENGINE_SETFAILED:
        case CURLE_SSL_INVALIDCERTSTATUS:
        case CURLE_SSL_ISSUER_ERROR:
        case CURLE_SSL_PINNEDPUBKEYNOTMATCH:
        case CURLE_SSL_SHUTDOWN_FAILED:
        case CURLE_USE_SSL_FAILED:
            return OutboundError::tls_verification_failed;
        case CURLE_COULDNT_CONNECT:
        case CURLE_COULDNT_RESOLVE_HOST:
        case CURLE_COULDNT_RESOLVE_PROXY:
            return OutboundError::connection_failed;
        case CURLE_OPERATION_TIMEDOUT:
            return OutboundError::timeout;
        case CURLE_WRITE_ERROR:
            return sink.too_large ? OutboundError::response_too_large : OutboundError::network_error;
        default:
            return OutboundError::network_error;
        }
    }

    [[nodiscard]] auto fail(OutboundError error, std::string detail) -> OutboundResult
    {
        log_diagnostic("request.failed",
                       {
                           {"error",  std::string{outbound_error_name(error)}, false},
                           {"detail", detail,                                  false}
        });
        return OutboundResult{false, OutboundResponse{}, error, std::move(detail)};
    }

    [[nodiscard]] auto configure_security_options(CURL* handle) noexcept -> bool
    {
        // Treat any setopt failure on a security-critical option as fatal so
        // the request fails closed before a single byte hits the wire.
        if (curl_easy_setopt(handle, CURLOPT_SSL_VERIFYPEER, 1L) != CURLE_OK)
        {
            return false;
        }
        if (curl_easy_setopt(handle, CURLOPT_SSL_VERIFYHOST, 2L) != CURLE_OK)
        {
            return false;
        }
        if (curl_easy_setopt(handle, CURLOPT_FOLLOWLOCATION, 0L) != CURLE_OK)
        {
            return false;
        }
        if (curl_easy_setopt(handle, CURLOPT_PROTOCOLS_STR, "https") != CURLE_OK)
        {
            return false;
        }
        // Disable signal-driven DNS resolution so timeouts behave safely when
        // multiple OutboundClient instances run on different threads.
        if (curl_easy_setopt(handle, CURLOPT_NOSIGNAL, 1L) != CURLE_OK)
        {
            return false;
        }
        return true;
    }

} // namespace

struct OutboundClient::Impl final
{
    CURL* handle{nullptr};

    Impl() noexcept
    {
        if (!ensure_curl_initialized())
        {
            return;
        }
        handle = curl_easy_init();
    }
    ~Impl()
    {
        if (handle != nullptr)
        {
            curl_easy_cleanup(handle);
        }
    }
    Impl(Impl const&) = delete;
    auto operator=(Impl const&) -> Impl& = delete;
    Impl(Impl&&) noexcept = delete;
    auto operator=(Impl&&) noexcept -> Impl& = delete;
};

auto outbound_error_name(OutboundError error) noexcept -> std::string_view
{
    switch (error)
    {
    case OutboundError::none:
        return "none"sv;
    case OutboundError::invalid_url:
        return "invalid_url"sv;
    case OutboundError::invalid_method:
        return "invalid_method"sv;
    case OutboundError::https_required:
        return "https_required"sv;
    case OutboundError::unresolved_host:
        return "unresolved_host"sv;
    case OutboundError::tls_verification_failed:
        return "tls_verification_failed"sv;
    case OutboundError::connection_failed:
        return "connection_failed"sv;
    case OutboundError::redirect_rejected:
        return "redirect_rejected"sv;
    case OutboundError::response_too_large:
        return "response_too_large"sv;
    case OutboundError::timeout:
        return "timeout"sv;
    case OutboundError::network_error:
        return "network_error"sv;
    }
    return "unknown"sv;
}

auto detect_system_ca_trust() -> SystemCaTrust
{
    // Concatenated PEM bundles, in rough order of prevalence across the
    // platforms Merovingian ships on (Debian/Ubuntu/Alpine, Fedora/RHEL,
    // openSUSE, BSD/macOS, FreeBSD ports).
    constexpr std::array<std::string_view, 6U> bundle_files{
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/pki/tls/certs/ca-bundle.crt",
        "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
        "/etc/ssl/ca-bundle.pem",
        "/etc/ssl/cert.pem",
        "/usr/local/share/certs/ca-root-nss.crt",
    };
    // OpenSSL hashed certificate directories.
    constexpr std::array<std::string_view, 2U> bundle_dirs{
        "/etc/ssl/certs",
        "/etc/pki/tls/certs",
    };
    auto trust = SystemCaTrust{};
    for (auto const candidate : bundle_files)
    {
        auto error = std::error_code{};
        if (std::filesystem::is_regular_file(candidate, error))
        {
            trust.bundle_file = std::string{candidate};
            break;
        }
    }
    for (auto const candidate : bundle_dirs)
    {
        auto error = std::error_code{};
        if (std::filesystem::is_directory(candidate, error))
        {
            trust.bundle_dir = std::string{candidate};
            break;
        }
    }
    return trust;
}

auto validate_outbound_request(OutboundRequest const& request) noexcept -> OutboundError
{
    if (!is_known_method(request.method))
    {
        return OutboundError::invalid_method;
    }
    if (request.url.empty())
    {
        return OutboundError::invalid_url;
    }
    if (!starts_with_https(request.url))
    {
        return OutboundError::https_required;
    }
    if (!url_host_segment_present(request.url))
    {
        return OutboundError::invalid_url;
    }
    if (request.pinned_addresses.empty())
    {
        return OutboundError::unresolved_host;
    }
    return OutboundError::none;
}

OutboundClient::OutboundClient()
    : impl_(std::make_unique<Impl>())
{
}

OutboundClient::~OutboundClient() = default;

auto OutboundClient::perform(OutboundRequest const& request) -> OutboundResult
{
    auto const validation = validate_outbound_request(request);
    if (validation != OutboundError::none)
    {
        return fail(validation, std::string{outbound_error_name(validation)});
    }

    if (impl_->handle == nullptr)
    {
        return fail(OutboundError::network_error, "curl handle unavailable");
    }

    auto const host_port = parse_https_host_port(request.url);
    if (!host_port.has_value())
    {
        return fail(OutboundError::invalid_url, std::string{outbound_error_name(OutboundError::invalid_url)});
    }

    auto* handle = impl_->handle;
    curl_easy_reset(handle);

    if (!configure_security_options(handle))
    {
        return fail(OutboundError::network_error, "failed to configure curl security options");
    }

    if (curl_easy_setopt(handle, CURLOPT_CONNECTTIMEOUT, static_cast<long>(request.connect_timeout_seconds)) !=
            CURLE_OK ||
        curl_easy_setopt(handle, CURLOPT_TIMEOUT, static_cast<long>(request.total_timeout_seconds)) != CURLE_OK ||
        curl_easy_setopt(handle, CURLOPT_URL, request.url.c_str()) != CURLE_OK ||
        curl_easy_setopt(handle, CURLOPT_PATH_AS_IS, 1L) != CURLE_OK ||
        curl_easy_setopt(handle, CURLOPT_CUSTOMREQUEST, request.method.c_str()) != CURLE_OK)
    {
        return fail(OutboundError::network_error, "failed to configure curl request");
    }

    // Optional in-memory CA bundle. When populated (tests, pinned-CA
    // deployments) it replaces the system trust store. When empty, point
    // libcurl at the host trust store explicitly: the bundled libcurl is
    // built from source with no fixed --with-ca-bundle, so its compiled-in
    // default path may not exist on the deployment host, which surfaces as
    // tls_verification_failed on otherwise-valid public certificates.
    if (!request.trusted_ca_pem.empty())
    {
        auto ca_blob = curl_blob{};
        // curl owns the copy thanks to CURL_BLOB_COPY, so the caller's
        // buffer can go out of scope after curl_easy_setopt returns.
        ca_blob.data = const_cast<char*>(request.trusted_ca_pem.data());
        ca_blob.len = request.trusted_ca_pem.size();
        ca_blob.flags = CURL_BLOB_COPY;
        if (curl_easy_setopt(handle, CURLOPT_CAINFO_BLOB, &ca_blob) != CURLE_OK)
        {
            return fail(OutboundError::network_error, "failed to attach CA bundle");
        }
    }
    else
    {
        // Probed once per process. Certificate verification stays on; if no
        // trust store is found the request still fails closed rather than
        // skipping verification.
        static auto const ca_trust = detect_system_ca_trust();
        if (!ca_trust.bundle_file.empty() &&
            curl_easy_setopt(handle, CURLOPT_CAINFO, ca_trust.bundle_file.c_str()) != CURLE_OK)
        {
            return fail(OutboundError::network_error, "failed to set CA bundle file");
        }
        if (!ca_trust.bundle_dir.empty() &&
            curl_easy_setopt(handle, CURLOPT_CAPATH, ca_trust.bundle_dir.c_str()) != CURLE_OK)
        {
            return fail(OutboundError::network_error, "failed to set CA bundle directory");
        }
    }

    if (!request.body.empty())
    {
        if (curl_easy_setopt(handle, CURLOPT_POSTFIELDS, request.body.data()) != CURLE_OK ||
            curl_easy_setopt(handle, CURLOPT_POSTFIELDSIZE_LARGE, static_cast<curl_off_t>(request.body.size())) !=
                CURLE_OK)
        {
            return fail(OutboundError::network_error, "failed to configure curl body");
        }
    }

    auto headers = CurlSlistGuard{};
    // Suppress libcurl's automatic Expect: 100-continue so the round trip is
    // a single request/response exchange.
    if (!headers.append("Expect:"))
    {
        return fail(OutboundError::network_error, "header allocation failed");
    }
    for (auto const& header : request.headers)
    {
        auto entry = header.name;
        entry += ": ";
        entry += header.value;
        if (!headers.append(entry))
        {
            return fail(OutboundError::network_error, "header allocation failed");
        }
    }
    if (curl_easy_setopt(handle, CURLOPT_HTTPHEADER, headers.get()) != CURLE_OK)
    {
        return fail(OutboundError::network_error, "failed to attach headers");
    }

    // Pin DNS for the URL host:port to the caller-supplied addresses. libcurl
    // will use these entries instead of consulting the resolver, locking the
    // connection to the address set validated by the federation security
    // policy.
    auto resolve = CurlSlistGuard{};
    for (auto const& address : request.pinned_addresses)
    {
        auto entry = host_port->host;
        entry += ':';
        entry += std::to_string(host_port->port);
        entry += ':';
        entry += address;
        if (!resolve.append(entry))
        {
            return fail(OutboundError::network_error, "resolve allocation failed");
        }
    }
    if (curl_easy_setopt(handle, CURLOPT_RESOLVE, resolve.get()) != CURLE_OK)
    {
        return fail(OutboundError::network_error, "failed to attach resolve list");
    }

    auto sink = ResponseSink{};
    sink.cap = request.max_response_body_bytes;
    if (curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, &mero_curl_write_body) != CURLE_OK ||
        curl_easy_setopt(handle, CURLOPT_WRITEDATA, &sink) != CURLE_OK ||
        curl_easy_setopt(handle, CURLOPT_HEADERFUNCTION, &mero_curl_write_header) != CURLE_OK ||
        curl_easy_setopt(handle, CURLOPT_HEADERDATA, &sink) != CURLE_OK)
    {
        return fail(OutboundError::network_error, "failed to attach response sinks");
    }

    auto const code = curl_easy_perform(handle);
    auto const mapped = map_curl_code(code, sink);

    auto status_code = long{0};
    curl_easy_getinfo(handle, CURLINFO_RESPONSE_CODE, &status_code);

    auto response = OutboundResponse{};
    response.status = status_code >= 0L && status_code <= static_cast<long>(std::numeric_limits<std::uint16_t>::max())
                          ? static_cast<std::uint16_t>(status_code)
                          : std::uint16_t{0U};
    response.body = std::move(sink.body);
    response.headers = std::move(sink.headers);

    // FOLLOWLOCATION is disabled, so a 3xx surfaces as a successful curl call
    // with a redirect status. Federation must not chase redirects, so the
    // response is preserved for audit but the result is marked as a
    // redirect_rejected failure.
    if (mapped == OutboundError::none && response.status >= 300U && response.status < 400U)
    {
        log_diagnostic("request.redirect_rejected", {
                                                        {"url",         request.url,                     false},
                                                        {"method",      request.method,                  false},
                                                        {"http_status", std::to_string(response.status), false}
        });
        return OutboundResult{
            false,
            std::move(response),
            OutboundError::redirect_rejected,
            std::string{outbound_error_name(OutboundError::redirect_rejected)},
        };
    }

    if (mapped != OutboundError::none)
    {
        log_diagnostic("request.error", {
                                            {"url",    request.url,                              false},
                                            {"method", request.method,                           false},
                                            {"error",  std::string{outbound_error_name(mapped)}, false}
        });
        return OutboundResult{
            false,
            std::move(response),
            mapped,
            std::string{outbound_error_name(mapped)},
        };
    }

    log_diagnostic("request.success", {
                                          {"url",         request.url,                     false},
                                          {"method",      request.method,                  false},
                                          {"http_status", std::to_string(response.status), false}
    });
    return OutboundResult{true, std::move(response), OutboundError::none, std::string{}};
}

} // namespace merovingian::http
