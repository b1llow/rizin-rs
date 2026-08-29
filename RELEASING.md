# Releasing

`rizin-rs` and `rizin-sys` release in lockstep. The `0.10` line targets Rizin
`>=0.10.0, <0.11.0`; prereleases increment `alpha.N`, and the final `0.10.0`
version is reserved until the bindings are ready to leave alpha.

For every release, update both the workspace package version and the exact
`rizin-sys` requirement in `rizin-rs/Cargo.toml`, then refresh `Cargo.lock`.

## Verify the packages

Run the repository checks, then verify the raw bindings package first:

```bash
nix develop . --command cargo publish --dry-run --locked -p rizin-sys
nix develop . --command cargo package --list -p rizin-rs
```

Cargo cannot fully package or dry-run `rizin-rs` until the exact `rizin-sys`
version is available from the registry. Before that point, inspect its package
list and rely on the workspace tests and Nix build to verify both crates
together.

## Publish

Authenticate Cargo using a scoped crates.io token outside the repository, then
publish in dependency order:

```bash
nix develop . --command cargo publish --locked -p rizin-sys
# Wait until 0.10.0-alpha.1 is visible in the crates.io index.
nix develop . --command cargo publish --dry-run --locked -p rizin-rs
nix develop . --command cargo publish --locked -p rizin-rs
```

Create the matching `v0.10.0-alpha.1` source tag only after both uploads
succeed. Published versions are immutable; yank a broken release and publish
the next `alpha.N` instead of attempting to reuse its version.
