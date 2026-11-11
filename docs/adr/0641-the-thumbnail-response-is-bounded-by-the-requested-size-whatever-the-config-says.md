# The thumbnail response is bounded by the requested size, whatever the config says

* Status: accepted
* Date: 2026-11-11

Technical Story: release-gate audit run 2, `F-resource-exhaustion.thumbnailer.worker-output-unbounded-by-default`.

## Context and Problem Statement

`generate_thumbnail` read the worker's stdout without a byte limit when `ThumbnailerConfig::max_output_bytes` was 0. The
runtime copies `max_decode_output_bytes` into it, and that default is 0 and nothing sets it, so the server buffered
whatever a compromised decoder wrote until the 10 second deadline.

## Decision Drivers

* The parent must never buffer more than a fixed multiple of the largest legal response, in the shipped configuration.
* `max_decode_output_bytes` already means something else to the decoder admission policy (decoded size), so its default
  must not change.

## Considered Options

* Treat 0 as "the ceiling for the requested size", and let a configured value only lower it
* Give `max_decode_output_bytes` a finite default
* Cap with a single compiled constant

## Decision Outcome

Chosen option: the first. A legal response is a PNG of at most width x height RGBA pixels of the thumbnail asked for, so
the ceiling is twice that raw size plus 64 KiB, with each side clamped to `max_thumbnail_dimension`. The read limit is the
ceiling (plus the frame header), and a configured `max_output_bytes` below it applies instead. A configured value above
the ceiling is lowered to it, since no legal response is larger.

### Negative Consequences

* A 4096 by 4096 request has a ceiling of about 134 MB; the media layer's own `max_target_dimension` keeps requests well
  below that.

## Pros and Cons of the Options

### Give `max_decode_output_bytes` a finite default

* Bad, because the same option is the decoder's decoded-size budget and the worker's memory limit; a value right for one
  is wrong for the other, and an operator who sets it would still lift the parent's cap.

### Cap with a single compiled constant

* Bad, because a constant large enough for the biggest request is a large buffer for a 4x4 thumbnail.
