// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

namespace merovingian::sync
{

// A long-poll the registry holds (ADR-0569). The registry never looks inside it: the transport derives a type that
// owns the connection and everything needed to answer. Destroying it closes the connection and releases whatever
// admission slots it holds, so a poll the registry drops on shutdown cleans up after itself.
class ParkedPoll
{
public:
    ParkedPoll() = default;
    ParkedPoll(ParkedPoll const&) = delete;
    auto operator=(ParkedPoll const&) -> ParkedPoll& = delete;
    ParkedPoll(ParkedPoll&&) = delete;
    auto operator=(ParkedPoll&&) -> ParkedPoll& = delete;
    virtual ~ParkedPoll() = default;
};

} // namespace merovingian::sync
