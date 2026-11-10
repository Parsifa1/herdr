{
  lib,
  stdenv,
  rustPlatform,
  callPackage,
  runCommand,
  zig_0_16,
  zstd,
  pkg-config,
  git,
  coreutils,
  cctools ? null,
  xcbuild ? null,
  rcodesign ? null,
  commitHash ? null,
}:

let
  manifest = lib.importTOML ../Cargo.toml;
  zigDeps = callPackage ../vendor/libghostty-vt/build.zig.zon.nix {
    name = "herdr-libghostty-vt-zig-cache";
    inherit zstd;
    linkFarm =
      name: entries:
      runCommand name { } ''
        mkdir -p $out
        ${lib.concatMapStringsSep "\n" (entry: ''
          cp -rL ${entry.path} $out/${entry.name}
        '') entries}
      '';
  };
  darwinToolchain = lib.optionals stdenv.hostPlatform.isDarwin [
    cctools
    xcbuild
  ];
  # Codesigning identity is supplied out-of-band by CI so macOS TCC grants
  # survive rebuilds: a real certificate keeps the designated requirement
  # stable, while an ad-hoc signature pins it to the cdhash, which changes on
  # every build. These are plain filesystem paths, so no key material ever
  # enters the store. Absent for local builds, which stay ad-hoc signed.
  codesignP12 = builtins.getEnv "HERDR_CODESIGN_P12";
  codesignPasswordFile = builtins.getEnv "HERDR_CODESIGN_P12_PASSWORD_FILE";
  # Nix cannot see file contents behind those paths, so without this the
  # derivation would keep its hash when the certificate is rotated and a cache
  # hit would serve the previous signature.
  codesignKeyId = builtins.getEnv "HERDR_CODESIGN_KEY_ID";
  withSignature =
    stdenv.hostPlatform.isDarwin
    && codesignP12 != ""
    && codesignPasswordFile != ""
    && codesignKeyId != "";
in
rustPlatform.buildRustPackage {
  pname = "herdr";
  version = manifest.package.version;

  src = lib.fileset.toSource {
    root = ./..;
    fileset = lib.fileset.intersection (lib.fileset.fromSource (lib.sources.cleanSource ./..)) (
      lib.fileset.unions [
        ../assets
        ../crates
        ../distribution/install.ps1
        ../docs/next/api/herdr-api.schema.json
        ../src
        ../vendor/libghostty-vt
        ../vendor/libghostty-vt.vendor.json
        ../vendor/portable-pty
        ../build.rs
        ../Cargo.lock
        ../Cargo.toml
        ../skills/herdr/SKILL.md
      ]
    );
  };

  cargoLock = {
    lockFile = ../Cargo.lock;
  };

  nativeBuildInputs = [
    git
    pkg-config
  ] ++ darwinToolchain ++ lib.optionals withSignature [ rcodesign ];

  env = {
    LIBGHOSTTY_VT_OPTIMIZE = "ReleaseFast";
    LIBGHOSTTY_VT_SIMD = "true";
    LIBGHOSTTY_VT_ZIG_SYSTEM_DIR = zigDeps;
    ZIG = lib.getExe zig_0_16;
    HERDR_BUILD_COMMIT = lib.optionalString (commitHash != null) commitHash;
  } // lib.optionalAttrs withSignature {
    inherit codesignKeyId;
  };

  preBuild = ''
    export ZIG_GLOBAL_CACHE_DIR="$TMPDIR/zig-global-cache"
    export ZIG_LOCAL_CACHE_DIR="$TMPDIR/zig-local-cache"
  '';

  # Rust tests are covered by the normal CI workflow. The Nix check is
  # intentionally build-only so it validates packaging inputs without
  # duplicating the full Rust test suite.
  doCheck = false;

  # Must be postFixup, not postInstall: `strip` runs during fixupPhase and
  # would invalidate the signature. `--timestamp-url none` avoids Apple's TSA
  # (unreachable for a self-signed cert, and non-deterministic anyway).
  postFixup = lib.optionalString withSignature ''
    set -e
    raw=$(${lib.getExe' coreutils "sha256sum"} ${lib.escapeShellArg codesignP12})
    actual=''${raw%% *}
    if [ "$actual" != "$codesignKeyId" ]; then
      echo "codesigning identity is not the one this derivation was evaluated for" >&2
      echo "  expected: $codesignKeyId" >&2
      echo "  actual:   $actual" >&2
      exit 1
    fi
    rcodesign sign \
      --p12-file ${lib.escapeShellArg codesignP12} \
      --p12-password-file ${lib.escapeShellArg codesignPasswordFile} \
      --timestamp-url none \
      --binary-identifier herdr \
      "$out/bin/herdr" "$out/bin/herdr.signed"
    mv "$out/bin/herdr.signed" "$out/bin/herdr"
    chmod 555 "$out/bin/herdr"
  '';

  meta = {
    description = "Terminal workspace manager for AI coding agents";
    homepage = "https://herdr.dev";
    license = lib.licenses.asl20;
    mainProgram = "herdr";
    platforms = lib.platforms.linux ++ lib.platforms.darwin;
  };
}
