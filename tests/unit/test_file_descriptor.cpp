// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/core/file_descriptor.hpp"

#include <catch2/catch_test_macros.hpp>

#include <set>
#include <tuple>

#include <fcntl.h>
#include <unistd.h>

SCENARIO("FileDescriptor defaults to invalid", "[core][file_descriptor]")
{
    GIVEN("the invalid file descriptor sentinel")
    {
        auto constexpr invalid_fd = merovingian::core::FileDescriptor::invalid;

        WHEN("a default FileDescriptor is constructed")
        {
            auto fd = merovingian::core::FileDescriptor{};

            THEN("it is invalid and stores the sentinel")
            {
                REQUIRE_FALSE(fd.valid());
                REQUIRE(fd.get() == invalid_fd);
            }
        }
    }
}

SCENARIO("FileDescriptor can release ownership", "[core][file_descriptor]")
{
    GIVEN("a pipe wrapped by FileDescriptor objects")
    {
        int raw_fds[2]{};
        REQUIRE(::pipe(raw_fds) == 0);

        auto read_end = merovingian::core::FileDescriptor{raw_fds[0]};
        auto write_end = merovingian::core::FileDescriptor{raw_fds[1]};

        WHEN("the read end is released")
        {
            auto const released = read_end.release();

            THEN("the wrapper no longer owns it")
            {
                REQUIRE_FALSE(read_end.valid());
                REQUIRE(released == raw_fds[0]);
            }

            std::ignore = ::close(released);
        }
    }
}

SCENARIO("FileDescriptor can set FD_CLOEXEC", "[core][file_descriptor]")
{
    GIVEN("a plain pipe")
    {
        int raw_fds[2]{};
        REQUIRE(::pipe(raw_fds) == 0);
        auto write_end = merovingian::core::FileDescriptor{raw_fds[1]};

        WHEN("set_cloexec() is called")
        {
            auto const ok = write_end.set_cloexec();

            THEN("the call succeeds and the FD_CLOEXEC flag is present")
            {
                REQUIRE(ok);
                auto const flags = ::fcntl(raw_fds[1], F_GETFD, 0);
                REQUIRE(flags >= 0);
                REQUIRE((flags & FD_CLOEXEC) != 0);
            }
        }
    }

    GIVEN("an invalid FileDescriptor")
    {
        auto fd = merovingian::core::FileDescriptor{};

        WHEN("set_cloexec() is called")
        {
            auto const ok = fd.set_cloexec();

            THEN("it reports failure without touching state")
            {
                REQUIRE_FALSE(ok);
                REQUIRE_FALSE(fd.valid());
            }
        }
    }
}

SCENARIO("close_all_file_descriptors_except preserves stdio and selected descriptors", "[core][file_descriptor]")
{
    GIVEN("three extra file descriptors beyond stdio")
    {
        int raw_fds[2]{};
        REQUIRE(::pipe(raw_fds) == 0);
        auto keep_fd = raw_fds[0];
        auto close_fd = raw_fds[1];

        // Ensure the descriptors we intend to close and keep are actually open.
        REQUIRE(::fcntl(keep_fd, F_GETFD, 0) >= 0);
        REQUIRE(::fcntl(close_fd, F_GETFD, 0) >= 0);

        WHEN("the helper is asked to keep stdio and one of the extra descriptors")
        {
            merovingian::core::close_all_file_descriptors_except(std::set<int>{keep_fd});

            THEN("the preserved descriptor is still open, the other is closed, and stdio remains")
            {
                REQUIRE(::fcntl(keep_fd, F_GETFD, 0) >= 0);
                REQUIRE(::fcntl(close_fd, F_GETFD, 0) < 0);
                REQUIRE(::fcntl(STDIN_FILENO, F_GETFD, 0) >= 0);
                REQUIRE(::fcntl(STDOUT_FILENO, F_GETFD, 0) >= 0);
                REQUIRE(::fcntl(STDERR_FILENO, F_GETFD, 0) >= 0);
            }
        }

        std::ignore = ::close(keep_fd);
        std::ignore = ::close(close_fd);
    }
}
