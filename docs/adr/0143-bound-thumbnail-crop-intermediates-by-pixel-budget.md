# Bound thumbnail crop intermediates by the existing pixel budget

* Status: accepted
* Date: 2026-10-14

Technical Story: MED-8 in the 29 September 2026 security audit.

## Context and Problem Statement

Bounding decoded pixels and final thumbnail pixels does not bound a crop's
fill image. The worker first scales the whole source to cover the target,
then center-crops it. A valid 4096×1 PNG cropped to 1×2048 would request an
8,388,608×2048 RGBA intermediate: 64 GiB despite a tiny final thumbnail.
An uncaught allocation exception previously escaped the worker's `main`.

## Decision Drivers

* Reject excessive intermediate work before narrowing dimensions or allocating.
* Preserve the existing bilinear and center-crop geometry for admitted work.
* Reuse the established pixel policy and framed error protocol.
* Keep decoding, resampling, and exception containment inside the hardened child.

## Considered Options

* Apply the existing effective pixel budget to the actual crop fill.
* Rely only on decoded/final dimensions and process resource limits.
* Replace the crop algorithm with a direct source-window resampler.

## Decision Outcome

Choose the existing effective pixel budget for each crop fill. A zero request
still means the worker ceiling, not unlimited work; a positive request cannot
raise the 4,096,000-pixel ceiling. Keep the existing rounded fill geometry,
represent its axes in `uint64_t`, and reject when the width exceeds the budget
divided by the nonzero height. Only narrow to `uint32_t` and resample after
admission. The already-enforced 4096-axis source/target bounds keep the rounded
wide conversions representable; an admitted area also proves the narrowed
axes fit. The existing decoder axis ceiling is not a new intermediate-axis cap.

Return the existing `too_large` response with no output pixels. The parent
`generate_thumbnail` driver maps that frame to status 413 with empty media
bytes, content type, and dimensions; this is not a claim that every public
media route exposes the same status instead of its existing failure policy.

After successful hardening, prepare an empty `internal_error` frame before
reading input. Enclose parsing, decoding, resampling, encoding, and final
framing in the worker exception boundary. Unexpected C++ exceptions use that
prebuilt frame without another string allocation. Failure before the frame
exists exits nonzero without consuming untrusted input. This boundary does
not catch operating-system signals or guarantee delivery to a closed pipe.

Keep the module's existing status-enum plus owned-output-reference pattern
for the private fallible resampler. The configured worker toolchain rejected
`std::expected`; introducing a toolchain workaround is not part of this repair.
No wire, database, configuration, or stored-media migration is introduced.

### Positive Consequences

* An admitted crop fill cannot exceed the same pixel budget as a decoded frame.
* Expected budget refusal does not depend on an allocation failure or sandbox kill.
* Existing admitted interpolation and center-crop code remain unchanged.

### Negative Consequences

* Some high-aspect requests are refused even though a direct-window algorithm
  could produce their small final image cheaply.
* This is a per-buffer pixel bound, not a new aggregate-memory or concurrency budget.

## Pros and Cons of the Options

### Existing effective pixel budget

* Good: a small, inspectable admission check closes the aspect-ratio amplification.
* Good: request-specific limits and the existing hard ceiling remain meaningful.
* Bad: it deliberately refuses expensive whole-fill implementations.

### Resource limits alone

* Bad: an otherwise valid request can terminate the worker instead of producing
  the controlled size error, and sanitizer builds omit the address-space cap.

### Direct source-window resampling

* Good: avoids the large intermediate instead of refusing it.
* Bad: changes interpolation and edge geometry, requiring separate fidelity and
  specification work rather than a resource-admission repair.

## Verification and Scope

The safe initial real-worker regression completed a successful normal build and
163 assertions: 115 passed, and all 48 failures were the crop-result checks on
eight budget/orientation combinations. Healthy decoding, scale controls, and an
ordinary crop passed. The old intermediates in that RED were at most 16 MiB;
the original 64 GiB case was not executed before repair.

Normal GREEN passes 201 assertions in three MED-8 scenarios, including both
orientations of the original magnitude as first-GREEN coverage. Related thumbnail
integration passes 776/10; ISO-5 isolation 554/4; thumbnail units 35/8; hardening
units 21/10. Independent source review and fresh combined verification remain
pending. Exception-allocation fault injection, dedicated JPEG amplification
fixtures, other platform execution, and broader thumbnail fidelity/upscaling
conformance are not claimed by these PNG admission regressions.

## Links

* [Media repository](../media-repository.md)
* [Hardening](../hardening.md)
* [Matrix v1.19 thumbnail requirements](../matrix-v1.19-spec/client-server-api.md#thumbnails)
