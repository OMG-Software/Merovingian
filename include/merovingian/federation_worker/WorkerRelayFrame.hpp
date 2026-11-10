// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

// GHSA-3p5v-vrg8-f545 (ADR-0595): the worker's half of a bound relay. A worker serving a request main forwarded may ask
// main for a one-time-key claim, a device-keys query, a device list or a profile, and main admits the frame only
// against the permit it gave that request (federation/WorkerRelayBinding.hpp). These functions are the one place the
// worker builds and sends such a frame, so the frame main's tests admit is the one the worker sends.

#include "merovingian/federation/WorkerRelayKind.hpp"

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace merovingian::ipc
{
class IpcChannel;
} // namespace merovingian::ipc

namespace merovingian::federation_worker
{

// The frame asking main for a relay of `kind`: its type (`otk_claim_ingest`, `device_keys_query_ingest`,
// `user_devices_ingest`, `profile_query_ingest`), `parent_request_id`, and `argument` as `request_body` (claim and
// keys query) or `user_id` (device list and profile). nullopt when `parent_request_id` is 0: a worker serving no
// request main forwarded relays nothing, since main would refuse it.
[[nodiscard]] auto worker_relay_frame(federation::WorkerRelayKind kind, std::string_view argument,
                                      std::uint64_t parent_request_id) -> std::optional<std::string>;

// Sends worker_relay_frame(kind, argument, parent_request_id) to main over `channel` and returns main's reply frame.
// nullopt, with nothing sent, when there is no parent request; nullopt when main does not answer within `timeout`.
[[nodiscard]] auto relay_to_main(ipc::IpcChannel& channel, federation::WorkerRelayKind kind, std::string_view argument,
                                 std::uint64_t parent_request_id, std::chrono::seconds timeout)
    -> std::optional<std::string>;

} // namespace merovingian::federation_worker
