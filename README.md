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

```bash
cargo add rizin-rs
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
latest `dev` revision, including the source and Meson dependency hashes, with:

```bash
./nix/rizin/update.sh
```

Pass a full 40-character commit SHA to pin a specific revision instead:

```bash
./nix/rizin/update.sh <commit>
```

## Usage

TODO

## License

[LICENSE]

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
