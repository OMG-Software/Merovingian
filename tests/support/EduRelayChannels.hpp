// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/ipc/channel.hpp"

#include <memory>

namespace merovingian::tests
{

// Shared by the downstream integration and sync fixtures. Unlike a fabricated
// authorization callback, this fixture uses the real authenticated transport and
// main-owned pending metadata. Signature verification is covered independently
// by the FED-12 behavioral regression, not by this downstream setup helper.
struct EduRelayChannels final
{
    std::unique_ptr<ipc::IpcChannel> main{};
    std::unique_ptr<ipc::IpcChannel> worker{};
};

} // namespace merovingian::tests
