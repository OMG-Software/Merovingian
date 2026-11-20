// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

namespace merovingian::sync
{

// Which of an extension's two request keys a request used: the bare key (`to_device`, `e2ee`, `account_data`,
// `receipts`, `typing`), kept on the unstable `org.matrix.simplified_msc3575` endpoint, and the MSC-prefixed key the
// extension MSCs require on `/_matrix/client/v4/sync` (`org.matrix.msc4538.to_device`, `org.matrix.msc4543.e2ee`,
// `org.matrix.msc4548.account_data`, `org.matrix.msc4551.receipts`, `org.matrix.msc4508.typing`). A request that
// sends both is one request, read from the prefixed key, and is answered under each key it used (ADR-0865).
struct ExtensionNames final
{
    bool bare{false};
    bool prefixed{false};
};

} // namespace merovingian::sync
