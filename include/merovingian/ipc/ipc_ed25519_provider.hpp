// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/crypto/ed25519.hpp"

#include <string_view>

namespace merovingian::ipc
{

class IpcChannel;

// Ed25519Provider implementation used by the out-of-process federation worker.
// Signing is delegated to the main process over the encrypted IPC channel so
// the Matrix signing secret never enters the worker address space. Verification
// is unsupported in the worker; the main process handles all Ed25519 verification.
class IpcEd25519Provider final : public crypto::Ed25519Provider
{
public:
    explicit IpcEd25519Provider(IpcChannel* channel);
    ~IpcEd25519Provider() override = default;

    IpcEd25519Provider(IpcEd25519Provider const&) = delete;
    auto operator=(IpcEd25519Provider const&) -> IpcEd25519Provider& = delete;
    IpcEd25519Provider(IpcEd25519Provider&&) = delete;
    auto operator=(IpcEd25519Provider&&) -> IpcEd25519Provider& = delete;

    // Sends a sign_request frame to main and returns the base64-unpadded signature.
    // Returns an error SignatureResult on IPC failure or if main reports an error.
    [[nodiscard]] auto sign(crypto::Ed25519SecretKeyHandle const& key,
                            std::string_view message) -> crypto::SignatureResult override;

    // Unsupported in the worker process; terminates the process if called.
    [[nodiscard]] auto verify(crypto::Ed25519PublicKey const& public_key, std::string_view message,
                              crypto::Ed25519Signature const& signature) -> crypto::VerificationResult override;

private:
    IpcChannel* channel_;
};

} // namespace merovingian::ipc
