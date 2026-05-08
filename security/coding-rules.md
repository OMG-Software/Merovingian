# Coding Rules

## Mandatory rules

- Security defects block release.
- RAII everywhere.
- References preferred over pointers.
- No raw owning pointers.
- No naked `new` or `delete`.
- No manual `malloc` or `free` outside reviewed low-level wrappers.
- No unchecked narrowing conversions.
- No logging secrets.
- No parser without fuzz coverage.
- No protocol feature without tests.
- No dependency without review.
- Warnings are errors.

## Ownership policy

- Prefer values.
- Prefer references for required access.
- Use `std::span` and `std::string_view` for bounded non-owning access.
- Use `not_null<T*>` only for unavoidable interop.
- `std::shared_ptr` requires justification.

## Security-over-performance rule

Performance work must not bypass:

- validation
- bounds checks
- authorization
- signature verification
- redaction
- logging controls
- policy enforcement
