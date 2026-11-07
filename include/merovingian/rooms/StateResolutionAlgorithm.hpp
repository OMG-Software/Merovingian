// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

namespace merovingian::rooms
{

enum class StateResolutionAlgorithm : unsigned char
{
    v2,
    // Room v12 (MSC4289/MSC4291): state resolution v2.1 — the iterative auth
    // checks algorithm starts from an empty state map instead of the
    // unconflicted state map, and the full conflicted set additionally
    // includes the conflicted state subgraph.
    // Spec: ../../docs/matrix-v1.19-spec/rooms/v12.md — "State resolution"
    // ("This state resolution algorithm is largely the same as the algorithm
    // found in room version 2 with the following modifications").
    v2_1,
};

} // namespace merovingian::rooms
