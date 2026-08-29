# rizin-rs

A Rust interface for Rizin, providing safe and ergonomic bindings to the Rizin reverse engineering framework.

## Status

![Nix](https://github.com/b1llow/rizin-rs/actions/workflows/nix.yml/badge.svg)

## Description

rizin-rs is a Rust library that provides bindings to the [Rizin](https://github.com/rizinorg/rizin) reverse engineering framework. This project aims to make Rizin's powerful features accessible to Rust developers with a safe and idiomatic API.

## Features

- Safe Rust bindings for Rizin's core functionality
- Idiomatic Rust API design
- Comprehensive documentation
- Example programs

## Installation

This alpha targets the Rizin 0.10 development line and requires Rizin
`>=0.10.0, <0.11.0`.

```bash
cargo add rizin-rs@0.10.0-alpha.1
```

```nix
rustPlatform.buildRustPackage {
    ...
    LIBCLANG_PATH = "${llvmPackages_18.libclang.lib}/lib";
    nativeBuildInputs = [
      rustPlatform.bindgenHook
      pkg-config
    ];
    buildInputs = [
      rizin
      llvmPackages_18.libclang
    ];
}
```

## Nix packages

The flake provides both the Rust bindings and the pinned Rizin build:

```bash
nix build .#rizin-rs
nix build .#rizin
```

Rizin is pinned to a specific commit from its `dev` branch. Update it to the
latest `dev` revision, including the upstream version and source/Meson hashes,
with:

```bash
./nix/rizin/update.sh
```

Pass a full 40-character commit SHA to pin a specific revision instead:

```bash
./nix/rizin/update.sh <commit>
```

## Usage

```rust
use rizin_rs::RzCore;

fn main() {
    let core = RzCore::new();
    core.config_set("analysis.arch", "x86").unwrap();
    core.config_set("analysis.bits", "64").unwrap();
    let arch = core.config_get("analysis.arch").unwrap();
    let bits = core.config_get("analysis.bits").unwrap();
    println!("Rizin analysis target: {arch}-{bits}");
}
```

Run the checked-in copy from the Nix development environment:

```bash
nix develop . --command cargo run -p rizin-rs --example basic
```

## Versioning

The crate's major/minor version tracks the compatible Rizin line. Alpha
releases use `0.10.0-alpha.N`; once `0.10.0` is published, Rust-only fixes use
the crate patch version while the exact Rizin source remains recorded by the
Nix pin. See [RELEASING.md](RELEASING.md) for the release order.

## License

The safe `rizin-rs` wrapper is released under
[CC0-1.0](https://github.com/b1llow/rizin-rs/blob/main/LICENSE).
The raw `rizin-sys` bindings and upstream Rizin are LGPL-3.0-only.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
