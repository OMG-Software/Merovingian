// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/config/config.hpp"
#include "merovingian/federation_worker/ipc_key_fd.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <utility>
#include <vector>

#include <fcntl.h>
#include <unistd.h>

namespace
{

using merovingian::core::FileDescriptor;
using merovingian::federation_worker::clear_master_key_file;
using merovingian::federation_worker::read_ipc_auth_key;

// A byte pattern distinct from all-zero, so a test can tell "the key came
// back with the bytes we sent" apart from "the key came back default/empty".
[[nodiscard]] auto sample_key_bytes(std::size_t count) -> std::vector<std::uint8_t>
{
    auto bytes = std::vector<std::uint8_t>(count);
    for (auto i = std::size_t{0U}; i < count; ++i)
    {
        bytes[i] = static_cast<std::uint8_t>((i * 7U + 3U) & 0xFFU);
    }
    return bytes;
}

// Writes `bytes` into a fresh pipe and returns {read_end, write_end}. The
// caller decides whether/when to close write_end to control short vs. exact
// vs. long reads on the far side.
[[nodiscard]] auto make_pipe() -> std::pair<FileDescriptor, FileDescriptor>
{
    auto fds = std::array<int, 2>{-1, -1};
    REQUIRE(::pipe(fds.data()) == 0);
    return {FileDescriptor{fds[0]}, FileDescriptor{fds[1]}};
}

auto write_all(int fd, std::vector<std::uint8_t> const& bytes) -> void
{
    auto written = std::size_t{0U};
    while (written < bytes.size())
    {
        auto const rc = ::write(fd, bytes.data() + written, bytes.size() - written);
        REQUIRE(rc > 0);
        written += static_cast<std::size_t>(rc);
    }
}

} // namespace

SCENARIO("read_ipc_auth_key accepts exactly the expected number of key bytes",
         "[federation-worker][ipc-key-fd][worker_key_fd]")
{
    GIVEN("a pipe carrying exactly kIpcAuthKeyBytes bytes, then closed")
    {
        auto [read_fd, write_fd] = make_pipe();
        auto const key_bytes = sample_key_bytes(merovingian::crypto::kIpcAuthKeyBytes);
        write_all(write_fd.get(), key_bytes);
        write_fd.reset();

        WHEN("read_ipc_auth_key reads it")
        {
            auto const key = read_ipc_auth_key(std::move(read_fd));

            THEN("a key is returned carrying exactly the bytes that were sent")
            {
                REQUIRE(key.has_value());
                REQUIRE(key->bytes.size() == key_bytes.size());
                for (auto i = std::size_t{0U}; i < key_bytes.size(); ++i)
                {
                    REQUIRE(static_cast<std::uint8_t>(key->bytes[i]) == key_bytes[i]);
                }
            }
        }
    }
}

SCENARIO("read_ipc_auth_key rejects a short read", "[federation-worker][ipc-key-fd][worker_key_fd]")
{
    GIVEN("a pipe closed after fewer than kIpcAuthKeyBytes bytes")
    {
        auto [read_fd, write_fd] = make_pipe();
        auto const short_bytes = sample_key_bytes(merovingian::crypto::kIpcAuthKeyBytes - 1U);
        write_all(write_fd.get(), short_bytes);
        write_fd.reset();

        WHEN("read_ipc_auth_key reads it")
        {
            auto const key = read_ipc_auth_key(std::move(read_fd));

            THEN("no key is returned")
            {
                REQUIRE_FALSE(key.has_value());
            }
        }
    }
}

SCENARIO("read_ipc_auth_key rejects an empty/closed fd", "[federation-worker][ipc-key-fd][worker_key_fd]")
{
    GIVEN("a pipe closed with nothing written at all")
    {
        auto [read_fd, write_fd] = make_pipe();
        write_fd.reset();

        WHEN("read_ipc_auth_key reads it")
        {
            auto const key = read_ipc_auth_key(std::move(read_fd));

            THEN("no key is returned")
            {
                REQUIRE_FALSE(key.has_value());
            }
        }
    }
}

SCENARIO("read_ipc_auth_key rejects a long read", "[federation-worker][ipc-key-fd][worker_key_fd]")
{
    GIVEN("a pipe carrying more than kIpcAuthKeyBytes bytes before it is closed")
    {
        auto [read_fd, write_fd] = make_pipe();
        auto const long_bytes = sample_key_bytes(merovingian::crypto::kIpcAuthKeyBytes + 1U);
        write_all(write_fd.get(), long_bytes);
        write_fd.reset();

        WHEN("read_ipc_auth_key reads it")
        {
            auto const key = read_ipc_auth_key(std::move(read_fd));

            THEN("no key is returned, because the pipe carried more than a single key")
            {
                REQUIRE_FALSE(key.has_value());
            }
        }
    }
}

SCENARIO("clear_master_key_file empties the config's master key file path",
         "[federation-worker][ipc-key-fd][worker_key_fd]")
{
    GIVEN("a config with a configured master key file")
    {
        auto config = merovingian::config::Config{};
        config.security().secrets.master_key_file = "/etc/merovingian/master.key";
        REQUIRE_FALSE(config.security().secrets.master_key_file.empty());

        WHEN("clear_master_key_file is applied")
        {
            clear_master_key_file(config);

            THEN("the master key file path is empty")
            {
                REQUIRE(config.security().secrets.master_key_file.empty());
            }
        }
    }
}

SCENARIO("read_ipc_auth_key closes the fd it consumes", "[federation-worker][ipc-key-fd][worker_key_fd]")
{
    GIVEN("a pipe carrying exactly one valid key")
    {
        auto [read_fd, write_fd] = make_pipe();
        auto const key_bytes = sample_key_bytes(merovingian::crypto::kIpcAuthKeyBytes);
        write_all(write_fd.get(), key_bytes);
        write_fd.reset();
        auto const raw_fd = read_fd.get();

        WHEN("read_ipc_auth_key consumes it")
        {
            auto const key = read_ipc_auth_key(std::move(read_fd));

            THEN("the key is accepted and the fd number is no longer open")
            {
                REQUIRE(key.has_value());
                REQUIRE(::fcntl(raw_fd, F_GETFD) < 0);
            }
        }
    }
}
