# Architecture

## Design priorities

1. Security first.
2. Correctness before features.
3. Hardened defaults.
4. Bounded resource usage.
5. Auditability.
6. Scale without bypassing checks.

## Runtime model

```text
merovingian-server
  ├── client API workers
  ├── federation workers
  ├── sync workers
  ├── database workers
  ├── outbound federation queues
  └── observability pipeline

merovingian-media
  └── isolated media processing

merovingian-signer
  └── isolated signing service
```

## Security principles

- All external input is hostile.
- Every queue is bounded.
- Every parser is fuzzed.
- References preferred over pointers.
- RAII required.
- No custom crypto.
- Encryption enabled by default where Matrix semantics allow.
