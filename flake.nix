{
  description = "Rust rizin bindings";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
      ...
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs { inherit system; };
        inherit (pkgs)
          nixfmt-tree
          rustPlatform
          llvmPackages_18
          mkShell
          rust-analyzer
          rustfmt
          cargo-watch
          ;

        rizin = pkgs.callPackage ./nix/rizin { };
        rizin-rs = pkgs.callPackage ./nix/rizin-rs { inherit rizin; };

        env = {
          LIBCLANG_PATH = "${llvmPackages_18.libclang.lib}/lib";
        };
      in
      {
        formatter = nixfmt-tree;

        packages = {
          default = rizin-rs;
          inherit rizin rizin-rs;
        };

        devShells = {
          default = mkShell (
            env
            // {
              inputsFrom = [
                self.packages.${system}.default
              ];
              packages = [
                rust-analyzer
                cargo-watch
              ];
              shellHook = ''
                echo "🦀 Rust dev shell ready. Try: cargo run"
              '';
              RUST_SRC_PATH = "${rustPlatform.rustLibSrc}";
            }
          );
          fmt = mkShell {
            packages = [
              rustPlatform.rust.cargo
              rustfmt
            ];
          };
        };

      }
    );
}
