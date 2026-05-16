// SPDX-License-Identifier: GPL-3.0-or-later

#include <catch2/catch_session.hpp>

#include <csignal>

auto main(int argc, char* argv[]) -> int
{
    // Network-facing integration tests open TLS sockets that the remote side
    // can close abruptly when, for example, the client rejects the server's
    // certificate. Default SIGPIPE handling would kill the test process when
    // the server thread later writes to the closed peer. Ignoring SIGPIPE
    // keeps the failures observable through return values without losing
    // any test fidelity.
    std::signal(SIGPIPE, SIG_IGN);
    return Catch::Session{}.run(argc, argv);
}
