{
  description = "Rust rizin bindings";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";
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
        inherit (pkgs) lib nixfmt-tree;
        bpkgs = b.packages.${system};
        inherit (bpkgs) rizin;

        env = {
          RIZIN_DIR = "${rizin}";
          LIBCLANG_PATH = "${pkgs.llvmPackages_18.libclang.lib}/lib";
        };

        rizin-rs = pkgs.rustPlatform.buildRustPackage (
          env
          // rec {
            pname = "rizin-rs";
            version = "0.9.0";
            src = ./.;

            cargoLock.lockFile = ./Cargo.lock;

            cargoHash = "";

            buildInputs = [
              rizin
              pkgs.llvmPackages_18.libclang
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
          default = pkgs.mkShell (
            env
            // {
              inputsFrom = [
                self.packages.${system}.default
              ];
              packages = [
                pkgs.rust-analyzer
                pkgs.cargo-watch
              ];
              shellHook = ''
                echo "🦀 Rust dev shell ready. Try: cargo run"
              '';
              RUST_SRC_PATH = "${pkgs.rust.packages.stable.rustPlatform.rustLibSrc}";
            }
          );
        };

      }
    );
}
