{
  llvmPackages_18,
  pkg-config,
  rizin,
  rustPlatform,
}:

rustPlatform.buildRustPackage {
  pname = "rizin-rs";
  inherit (rizin) version;

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
