# ckb-idl-cli

`ckb-idl-cli` provides the `ckb-idl` command-line tool for packaging an exact
IDL 0.1.0 artifact with a CKB executable. Its job is deliberately narrow:
validate a canonical IDL, bind that exact byte sequence to a clean executable,
and verify the resulting deployment bundle.

It does not generate IDLs, invoke Cargo, or infer witness types. Contract
Makefiles own building and `ckb-idl-export` owns authoritative IDL generation.

## Intended workflow

```text
Rust witness definitions
        │
        ▼
ckb-idl-derive + ckb-idl-export
        │
        ▼
canonical IDL artifact + clean executable
        │
        ▼
ckb-idl bind
        │
        ▼
bound executable + frozen IDL + binding manifest
        │
        ▼
deployer submits bound executable unchanged
```

The IDL is a commitment input, not merely metadata. `ckb-idl` will validate
RFC 8785 canonical bytes and hash those exact bytes; it must never prettify,
minify, normalize, or rewrite the IDL before hashing.

<!-- ## Status

The package scaffold and stable command/error contract are implemented. The
four commands parse their documented arguments, but their operational behavior
is intentionally not implemented yet. Calling one currently returns:

```text
category=not_implemented path= message=command `<name>` is not implemented yet
```

with exit code `7`.

Implementation progress is tracked in
[docs/idl-0.1.0-binding/tasks.md](docs/idl-0.1.0-binding/tasks.md). -->

## Command interface

```text
ckb-idl validate --idl <path>
ckb-idl bind --executable <clean> --idl <canonical-idl> --out-dir <dir>
ckb-idl verify --executable <bound> --idl <frozen-idl> [--manifest <path>]
ckb-idl inspect --executable <bound>
```

Use `ckb-idl --help` for the current argument-level help.

Planned stable non-parser error codes are:

| Exit code | Category |
|---:|---|
| 3 | `invalid_document` |
| 4 | `invalid_trailer` |
| 5 | `commitment_mismatch` |
| 6 | `manifest_mismatch` |
| 7 | `io_error`, `filesystem_safety`, or `not_implemented` |

## Binding Trailer 1

The future `bind` command appends exactly 46 bytes:

```text
payload = version_u8 || flags_u8 || sha256(canonical_idl_bytes)
bound_code_data = clean_executable || payload || payload_length_u32_le || magic_8
```

| Field | Value |
|---|---|
| Version | `1` |
| Flags | `0` |
| Payload length | `34` bytes |
| Magic | `434b4249444c0000` (`CKBIDL` followed by two zero bytes) |
| Total trailer length | `46` bytes |

The IDL digest is raw SHA-256 over exact canonical IDL bytes. Bundle manifests
will additionally record CKB-personalized data hashes for both the clean
executable and complete bound code data.

## Planned bundle

For example:

```text
ckb-idl bind \
  --executable build/release/authorization-choice-lock \
  --idl artifacts/authorization-choice-lock.idl.json \
  --out-dir dist/authorization-choice-lock
```

will create:

```text
dist/authorization-choice-lock/
├── authorization-choice-lock
├── authorization-choice-lock.idl.json
└── authorization-choice-lock.binding.json
```

The frozen IDL will be byte-for-byte identical to the supplied IDL. Binding
will refuse to overwrite destinations, rebind an already-bound executable, or
silently accept malformed trailer-like input.

## Development

The project currently uses a sibling-path `ckb-idl-client` dependency for local
development. Before isolated CI or release packaging, coordinated crates must
use published or commit-pinned Git dependencies instead.

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo run --bin ckb-idl -- --help
```

## Design documents

- [Requirements](docs/idl-0.1.0-binding/requirements.md)
- [Design](docs/idl-0.1.0-binding/design.md)
- [Implementation tasks](docs/idl-0.1.0-binding/tasks.md)
