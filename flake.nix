{
  description = "Rust rizin bindings";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    b = {
      url = "github:b1llow/nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
      b,
      ...
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs { inherit system; };
        inherit (pkgs)
          lib
          nixfmt-tree
          rustPlatform
          pkg-config
          llvmPackages_18
          mkShell
          rust-analyzer
          cargo-watch
          ;
        bpkgs = b.packages.${system};
        inherit (bpkgs) rizin;

        env = {
          LIBCLANG_PATH = "${llvmPackages_18.libclang.lib}/lib";
        };

        rizin-rs = rustPlatform.buildRustPackage (
          env
          // rec {
            pname = "rizin-rs";
            version = "0.9.1";
            src = ./.;
            cargoLock.lockFile = ./Cargo.lock;

            nativeBuildInputs = [
              rustPlatform.bindgenHook
              pkg-config
            ];
            buildInputs = [
              rizin
              llvmPackages_18.libclang
            ];

            doCheck = false;

            preConfigure = ''

            '';
          }
        );
      in
      {
        formatter = nixfmt-tree;

        packages = {
          default = rizin-rs;
          inherit rizin-rs;
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
            ];
          };
        };

      }
    );
}
