{
  lib,
  llvmPackages_18,
  pkg-config,
  rizin,
  rustPlatform,
}:

let
  workspaceManifest = lib.importTOML ../../Cargo.toml;
in
rustPlatform.buildRustPackage {
  pname = "rizin-rs";
  version = workspaceManifest.workspace.package.version;

  src = ../..;
  cargoLock.lockFile = ../../Cargo.lock;

  LIBCLANG_PATH = "${llvmPackages_18.libclang.lib}/lib";

  nativeBuildInputs = [
    rustPlatform.bindgenHook
    pkg-config
  ];
  buildInputs = [
    rizin
    llvmPackages_18.libclang
  ];

  doCheck = true;
}
