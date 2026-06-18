// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/core/file_descriptor.hpp"

#include <catch2/catch_test_macros.hpp>

#include <set>
#include <tuple>

#include <fcntl.h>
#include <sys/wait.h>
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
    GIVEN("two extra file descriptors beyond stdio")
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
            // The sweep closes every descriptor in the table except stdio and
            // the kept fd. Running it in this process would also close fds owned
            // by libraries linked into the test binary — most damagingly,
            // libsodium's cached /dev/urandom descriptor, after which the next
            // keypair generation in any later scenario aborts via sodium_misuse.
            // So exercise the helper in a forked child and observe its verdict
            // through the exit code; the parent's fd table is left intact.
            auto const pid = ::fork();
            REQUIRE(pid >= 0);
            if (pid == 0)
            {
                merovingian::core::close_all_file_descriptors_except(std::set<int>{keep_fd});
                auto const ok = ::fcntl(keep_fd, F_GETFD, 0) >= 0 &&     // kept fd open
                                ::fcntl(close_fd, F_GETFD, 0) < 0 &&     // other fd closed
                                ::fcntl(STDIN_FILENO, F_GETFD, 0) >= 0 && // stdio preserved
                                ::fcntl(STDOUT_FILENO, F_GETFD, 0) >= 0 &&
                                ::fcntl(STDERR_FILENO, F_GETFD, 0) >= 0;
                ::_exit(ok ? 0 : 1);
            }

            THEN("the child reports the kept fd and stdio survived while the other was closed")
            {
                auto status = 0;
                REQUIRE(::waitpid(pid, &status, 0) == pid);
                REQUIRE(WIFEXITED(status));
                REQUIRE(WEXITSTATUS(status) == 0);
            }
        }

        std::ignore = ::close(keep_fd);
        std::ignore = ::close(close_fd);
    }
}
