// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// Exercises the decoders for the JSON bodies carried by the federation worker IPC frames, and the
// two field extractors they are built on. The frame body is authenticated and encrypted on the
// wire, but a compromised worker still writes the body that main decodes, so every decoder must
// survive any bytes. The channel's own framing (IpcChannel::read_frame) needs a live socket and
// the key exchange and is not reached from here.

#include "fuzz_input.hpp"
#include "merovingian/ipc/federation_ipc_frames.hpp"

#include <cstddef>
#include <cstdint>
#include <tuple>

extern "C" auto LLVMFuzzerTestOneInput(std::uint8_t const* data, std::size_t size) -> int
{
    auto const json = merovingian::fuzz::to_string(data, size);
    auto const [key, body] = merovingian::fuzz::split_at_nul(json);

    std::ignore = merovingian::ipc::deserialize_fed_request(json);
    std::ignore = merovingian::ipc::deserialize_fed_response(json);
    std::ignore = merovingian::ipc::deserialize_outbound_http_request(json);
    std::ignore = merovingian::ipc::deserialize_outbound_http_response(json);
    std::ignore = merovingian::ipc::deserialize_membership_template_ingest(json);
    std::ignore = merovingian::ipc::deserialize_membership_template_ingest_result(json);
    std::ignore = merovingian::ipc::ipc_json_get_str(body, key);
    std::ignore = merovingian::ipc::ipc_json_get_u64(body, key);
    return 0;
}
