// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#include "merovingian/email/smtp_client.hpp"

#include "merovingian/core/secret_buffer.hpp"
#include "merovingian/email/mailbox_address.hpp"
#include "merovingian/http/outbound_client.hpp"
#include "merovingian/platform/file_metadata.hpp"

#include <curl/curl.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace merovingian::email
{

namespace
{

    // A password file is a single line; anything longer than this is not one.
    constexpr auto max_password_file_bytes = std::size_t{4096U};

    // libcurl's global state, initialised once before the first handle. curl_global_init is
    // thread-safe in the libcurl this project pins and reference counted, so this guard and the
    // HTTP client's own guard may both exist.
    class CurlGlobal final
    {
    public:
        CurlGlobal() noexcept
            : ok_{curl_global_init(CURL_GLOBAL_DEFAULT) == CURLE_OK}
        {
        }

        ~CurlGlobal()
        {
            if (ok_)
            {
                curl_global_cleanup();
            }
        }

        CurlGlobal(CurlGlobal const&) = delete;
        CurlGlobal(CurlGlobal&&) = delete;
        auto operator=(CurlGlobal const&) -> CurlGlobal& = delete;
        auto operator=(CurlGlobal&&) -> CurlGlobal& = delete;

        [[nodiscard]] auto ok() const noexcept -> bool
        {
            return ok_;
        }

    private:
        bool ok_;
    };

    [[nodiscard]] auto curl_ready() noexcept -> bool
    {
        static auto const global = CurlGlobal{};
        return global.ok();
    }

    struct CurlEasyDeleter final
    {
        auto operator()(CURL* handle) const noexcept -> void
        {
            curl_easy_cleanup(handle);
        }
    };

    struct CurlSlistDeleter final
    {
        auto operator()(curl_slist* list) const noexcept -> void
        {
            curl_slist_free_all(list);
        }
    };

    using CurlEasy = std::unique_ptr<CURL, CurlEasyDeleter>;
    using CurlSlist = std::unique_ptr<curl_slist, CurlSlistDeleter>;

    // Appends `entry` to `list`. curl_slist_append copies the string and returns the list's head:
    // the existing head when the list is not empty, else the one node it allocated. On failure the
    // list is unchanged and still owned by `list`.
    [[nodiscard]] auto append(CurlSlist& list, std::string const& entry) -> bool
    {
        auto* const head = curl_slist_append(list.get(), entry.c_str());
        if (head == nullptr)
        {
            return false;
        }
        if (list == nullptr)
        {
            list.reset(head);
        }
        return true;
    }

    // The message libcurl uploads as the DATA section, consumed front to back.
    struct UploadSource final
    {
        std::string_view remaining{};
    };

    auto read_message(char* buffer, std::size_t size, std::size_t count, void* user) noexcept -> std::size_t
    {
        auto& source = *static_cast<UploadSource*>(user);
        auto const capacity = size * count;
        auto const length = std::min(capacity, source.remaining.size());
        std::memcpy(buffer, source.remaining.data(), length);
        source.remaining.remove_prefix(length);
        return length;
    }

    [[nodiscard]] auto protocol_listed(std::string_view protocol) noexcept -> bool
    {
        auto const* const info = curl_version_info(CURLVERSION_NOW);
        if (info == nullptr || info->protocols == nullptr)
        {
            return false;
        }
        for (auto const* const* entry = info->protocols; *entry != nullptr; ++entry)
        {
            if (std::string_view{*entry} == protocol)
            {
                return true;
            }
        }
        return false;
    }

    [[nodiscard]] auto is_helo_name(std::string_view name) noexcept -> bool
    {
        constexpr auto max_helo_bytes = std::size_t{253U};
        return !name.empty() && name.size() <= max_helo_bytes && name.front() != '.' && name.front() != '-' &&
               std::ranges::all_of(name, [](char byte) {
                   return (byte >= 'a' && byte <= 'z') || (byte >= 'A' && byte <= 'Z') ||
                          (byte >= '0' && byte <= '9') || byte == '-' || byte == '.';
               });
    }

    // The password from `path`, without a trailing line ending, NUL-terminated for libcurl, in
    // locked memory that is wiped when it goes out of scope. nullopt when the file is not a usable
    // secret file, is empty, or holds a line break or NUL inside the password. libcurl keeps its
    // own copy for the handle's lifetime; the handle is destroyed when the send ends.
    [[nodiscard]] auto read_password(std::string const& path) -> std::optional<core::SecretBuffer>
    {
        auto contents = platform::read_secure_secret_file(path, max_password_file_bytes);
        if (!contents.has_value())
        {
            return std::nullopt;
        }
        auto bytes = std::span<std::uint8_t const>{contents->bytes()};
        while (!bytes.empty() &&
               (bytes.back() == static_cast<std::uint8_t>('\n') || bytes.back() == static_cast<std::uint8_t>('\r')))
        {
            bytes = bytes.first(bytes.size() - 1U);
        }
        if (bytes.empty() || std::ranges::any_of(bytes, [](std::uint8_t byte) {
                return byte == 0U || byte == static_cast<std::uint8_t>('\n') || byte == static_cast<std::uint8_t>('\r');
            }))
        {
            return std::nullopt;
        }
        auto terminated = core::SecretBuffer{bytes.size() + 1U};
        std::ranges::copy(bytes, terminated.bytes().begin());
        terminated.bytes().back() = 0U;
        return terminated;
    }

    [[nodiscard]] auto refused(std::string detail) -> SmtpSendOutcome
    {
        return SmtpSendOutcome{SmtpSendResult::refused_locally, std::move(detail)};
    }

    [[nodiscard]] auto failed(std::string detail) -> SmtpSendOutcome
    {
        return SmtpSendOutcome{SmtpSendResult::failed, std::move(detail)};
    }

    // The relay URL: scheme, host and port from the parsed endpoint, and the EHLO name as the path
    // (libcurl sends an SMTP URL's path as its EHLO domain).
    [[nodiscard]] auto relay_url(SmtpSettings const& settings) -> std::string
    {
        auto url = std::string{settings.endpoint.implicit_tls ? "smtps://" : "smtp://"};
        url += settings.endpoint.host;
        url += ":" + std::to_string(settings.endpoint.port);
        if (is_helo_name(settings.helo_domain))
        {
            url += "/" + settings.helo_domain;
        }
        return url;
    }

    // `host:port:address[,address...]` for CURLOPT_RESOLVE, from the test pins. An IPv6 literal
    // host is written without its brackets.
    [[nodiscard]] auto resolve_entry(SmtpEndpoint const& endpoint, SmtpTestResolution const& resolution) -> std::string
    {
        auto host = endpoint.host;
        if (host.size() >= 2U && host.front() == '[' && host.back() == ']')
        {
            host = host.substr(1U, host.size() - 2U);
        }
        auto entry = host + ":" + std::to_string(endpoint.port) + ":";
        for (auto index = std::size_t{0U}; index < resolution.pinned_addresses.size(); ++index)
        {
            entry += (index == 0U ? "" : ",") + resolution.pinned_addresses[index];
        }
        return entry;
    }

    [[nodiscard]] auto set_trust(CURL* handle, SmtpSettings const& settings) -> bool
    {
        if (settings.test_resolution.has_value() && !settings.test_resolution->trusted_ca_pem.empty())
        {
            auto const& pem = settings.test_resolution->trusted_ca_pem;
            auto ca_blob = curl_blob{};
            // CURL_BLOB_COPY: libcurl copies the bytes, so the settings may go out of scope.
            ca_blob.data = const_cast<char*>(pem.data());
            ca_blob.len = pem.size();
            ca_blob.flags = CURL_BLOB_COPY;
            return curl_easy_setopt(handle, CURLOPT_CAINFO_BLOB, &ca_blob) == CURLE_OK;
        }
        // Probed once per process, as the HTTP client does. Verification stays on: with no trust
        // store found, the handshake fails rather than proceeding unverified.
        static auto const ca_trust = http::detect_system_ca_trust();
        if (!ca_trust.bundle_file.empty() &&
            curl_easy_setopt(handle, CURLOPT_CAINFO, ca_trust.bundle_file.c_str()) != CURLE_OK)
        {
            return false;
        }
        return ca_trust.bundle_dir.empty() ||
               curl_easy_setopt(handle, CURLOPT_CAPATH, ca_trust.bundle_dir.c_str()) == CURLE_OK;
    }

    // What one session sends, gathered so configure_session can apply it. libcurl copies string
    // options but keeps pointers to the two lists and to `source` until the transfer ends, so the
    // caller keeps every one of these alive until curl_easy_perform returns.
    struct SessionParts final
    {
        std::string const& url;
        std::string const& envelope_from;
        CurlSlist const& recipients;
        CurlSlist const& pins;
        UploadSource& source;
        std::optional<core::SecretBuffer> const& password;
        bool cleartext;
        std::size_t message_bytes;
    };

    // Applies every option of one SMTP session to `curl`. False if libcurl refused any of them; the
    // caller then sends nothing. Each group below is a rule from ADR-0220.
    [[nodiscard]] auto configure_session(CURL* curl, SmtpSettings const& settings, SessionParts const& parts) -> bool
    {
        // Only the configured scheme may be spoken: never a redirect to another protocol.
        auto const* const protocols = settings.endpoint.implicit_tls ? "smtps" : "smtp";
        // TLS before anything else is sent (STARTTLS for smtp://), unless the operator chose a
        // cleartext loopback relay; verified peer and host name; never older than TLS 1.2.
        auto const use_ssl = parts.cleartext ? static_cast<long>(CURLUSESSL_NONE) : static_cast<long>(CURLUSESSL_ALL);
        auto ok = curl_easy_setopt(curl, CURLOPT_URL, parts.url.c_str()) == CURLE_OK &&
                  curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR, protocols) == CURLE_OK &&
                  curl_easy_setopt(curl, CURLOPT_USE_SSL, use_ssl) == CURLE_OK &&
                  curl_easy_setopt(curl, CURLOPT_SSLVERSION, static_cast<long>(CURL_SSLVERSION_TLSv1_2)) == CURLE_OK &&
                  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L) == CURLE_OK &&
                  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L) == CURLE_OK && set_trust(curl, settings);

        // No signals (the server is multi-threaded), no proxy from the environment, a fresh
        // connection that is never reused, and both timeouts.
        ok = ok && curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L) == CURLE_OK &&
             curl_easy_setopt(curl, CURLOPT_PROXY, "") == CURLE_OK &&
             curl_easy_setopt(curl, CURLOPT_FRESH_CONNECT, 1L) == CURLE_OK &&
             curl_easy_setopt(curl, CURLOPT_FORBID_REUSE, 1L) == CURLE_OK &&
             curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, static_cast<long>(settings.connect_timeout_seconds)) ==
                 CURLE_OK &&
             curl_easy_setopt(curl, CURLOPT_TIMEOUT, static_cast<long>(settings.total_timeout_seconds)) == CURLE_OK;

        // The envelope (one sender, one recipient) and the message, uploaded as the DATA section.
        ok = ok && curl_easy_setopt(curl, CURLOPT_MAIL_FROM, parts.envelope_from.c_str()) == CURLE_OK &&
             curl_easy_setopt(curl, CURLOPT_MAIL_RCPT, parts.recipients.get()) == CURLE_OK &&
             curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L) == CURLE_OK &&
             curl_easy_setopt(curl, CURLOPT_READFUNCTION, &read_message) == CURLE_OK &&
             curl_easy_setopt(curl, CURLOPT_READDATA, &parts.source) == CURLE_OK &&
             curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE, static_cast<curl_off_t>(parts.message_bytes)) == CURLE_OK;

        // Test-only address pins (empty in production).
        if (ok && parts.pins != nullptr)
        {
            ok = curl_easy_setopt(curl, CURLOPT_RESOLVE, parts.pins.get()) == CURLE_OK;
        }

        // SMTP AUTH, only ever after TLS (send_smtp_message refuses credentials on cleartext).
        if (ok && parts.password.has_value())
        {
            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): libcurl takes a C string.
            auto const* const password_text = reinterpret_cast<char const*>(parts.password->bytes().data());
            ok = curl_easy_setopt(curl, CURLOPT_USERNAME, settings.username.c_str()) == CURLE_OK &&
                 curl_easy_setopt(curl, CURLOPT_PASSWORD, password_text) == CURLE_OK;
        }
        return ok;
    }

} // namespace

auto smtp_protocol_available(bool implicit_tls) noexcept -> bool
{
    return protocol_listed(implicit_tls ? "smtps" : "smtp");
}

auto send_smtp_message(SmtpSettings const& settings, std::string_view recipient, std::string_view message)
    -> SmtpSendOutcome
{
    if (!is_safe_mailbox_address(settings.from) || !is_safe_mailbox_address(recipient))
    {
        return refused("sender or recipient is not a plain address");
    }
    auto const cleartext = !settings.endpoint.implicit_tls && !settings.require_tls;
    auto const has_credentials = !settings.username.empty() || !settings.password_file.empty();
    // Config validation refuses both of these; refuse again here so no caller can reach them.
    if (cleartext && !settings.endpoint.loopback_literal)
    {
        return refused("cleartext SMTP is allowed only to a loopback IP literal");
    }
    if (cleartext && has_credentials)
    {
        return refused("credentials are never sent without TLS");
    }
    if (settings.username.empty() != settings.password_file.empty())
    {
        return refused("username and password_file must be set together");
    }
    if (!smtp_protocol_available(settings.endpoint.implicit_tls))
    {
        return SmtpSendOutcome{SmtpSendResult::protocol_unavailable,
                               settings.endpoint.implicit_tls ? "libcurl lacks smtps" : "libcurl lacks smtp"};
    }
    if (!curl_ready())
    {
        return failed("libcurl global initialisation failed");
    }

    auto password = std::optional<core::SecretBuffer>{};
    if (has_credentials)
    {
        password = read_password(settings.password_file);
        if (!password.has_value())
        {
            return SmtpSendOutcome{SmtpSendResult::credentials_unavailable,
                                   "password_file is not a usable secret file"};
        }
    }

    auto const handle = CurlEasy{curl_easy_init()};
    if (handle == nullptr)
    {
        return failed("curl_easy_init failed");
    }
    auto* const curl = handle.get();
    auto const url = relay_url(settings);
    auto const envelope_from = "<" + settings.from + ">";
    auto recipients = CurlSlist{};
    auto pins = CurlSlist{};
    if (!append(recipients, "<" + std::string{recipient} + ">"))
    {
        return failed("could not build the recipient list");
    }
    if (settings.test_resolution.has_value() && !settings.test_resolution->pinned_addresses.empty() &&
        !append(pins, resolve_entry(settings.endpoint, *settings.test_resolution)))
    {
        return failed("could not build the resolve list");
    }
    auto source = UploadSource{message};

    auto const parts = SessionParts{url, envelope_from, recipients, pins, source, password, cleartext, message.size()};
    if (!configure_session(curl, settings, parts))
    {
        return failed("could not configure the SMTP session");
    }

    // One SMTP session: connect, (START)TLS, EHLO, AUTH when configured, MAIL FROM, RCPT TO, DATA,
    // QUIT. Blocking, bounded by the connect and total timeouts set above.
    auto const code = curl_easy_perform(curl);
    if (code == CURLE_OK)
    {
        return SmtpSendOutcome{SmtpSendResult::sent, {}};
    }
    if (code == CURLE_UNSUPPORTED_PROTOCOL)
    {
        return SmtpSendOutcome{SmtpSendResult::protocol_unavailable, curl_easy_strerror(code)};
    }
    return failed(curl_easy_strerror(code));
}

} // namespace merovingian::email
