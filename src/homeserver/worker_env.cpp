// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/worker_env.hpp"

#include <cstdlib>
#include <string>

#include <unistd.h>

namespace merovingian::homeserver
{

auto build_minimal_worker_env() -> MinimalWorkerEnv
{
    auto env = MinimalWorkerEnv{};
    if (auto const* path = ::getenv("PATH"); path != nullptr)
    {
        env.entries.emplace_back(std::string{"PATH="} + path);
    }
    else
    {
        // Fallback so the child can still resolve NSS/TLS helpers when the
        // parent has no PATH (unusual but possible under hardened systemd
        // units that clear the environment).
        env.entries.emplace_back("PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin");
    }
    env.argv.reserve(env.entries.size() + 1U);
    for (auto const& entry : env.entries)
    {
        env.argv.push_back(entry.c_str());
    }
    env.argv.push_back(nullptr); // null-terminated, as posix_spawn requires
    return env;
}

} // namespace merovingian::homeserver