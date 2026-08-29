{
  cacert,
  fetchFromGitHub,
  git,
  lib,
  makeSetupHook,
  meson,
  rizin,
  stdenvNoCC,
}:

let
  checksums = builtins.fromJSON (builtins.readFile ./checksum.json);

  src = fetchFromGitHub {
    owner = "rizinorg";
    repo = "rizin";
    rev = checksums.rev;
    hash = checksums.srcHash;
  };

  mesonDeps = stdenvNoCC.mkDerivation {
    pname = "rizin-meson-deps";
    version = builtins.substring 0 12 checksums.rev;
    inherit src;

    postUnpack = ''
      rm "$sourceRoot/subprojects/sigdb.wrap"
    '';

    nativeBuildInputs = [
      cacert
      git
      meson
    ];

    buildPhase = ''
      runHook preBuild

      meson subprojects download
      find subprojects -type d -name .git -prune -exec rm -rf {} +
      cp -r subprojects "$out"

      runHook postBuild
    '';

    phases = [
      "unpackPhase"
      "buildPhase"
    ];
    impureEnvVars = lib.fetchers.proxyImpureEnvVars;
    outputHashMode = "recursive";
    outputHashAlgo = "sha256";
    outputHash = checksums.mesonDepsHash;
  };

  mesonDepsConfigHook = makeSetupHook {
    name = "rizin-meson-deps-config-hook";
  } ./meson-deps-config-hook.sh;
in
rizin.overrideAttrs (prevAttrs: {
  version = "unstable-${builtins.substring 0 12 checksums.rev}";
  inherit src mesonDeps;
  patches = builtins.filter (
    patch: builtins.baseNameOf patch != "0001-fix-compilation-with-clang.patch"
  ) (prevAttrs.patches or [ ]);

  mesonFlags = [
    "-Dportable=true"
    "-Dinstall_sigdb=false"
  ];

  nativeBuildInputs = (prevAttrs.nativeBuildInputs or [ ]) ++ [ mesonDepsConfigHook ];
  buildInputs = [ ];

  # nixpkgs-update: no auto update
  passthru = {
    inherit mesonDeps;
    updateScript = ./update.sh;
    skipBulkUpdate = true;
  };
})
