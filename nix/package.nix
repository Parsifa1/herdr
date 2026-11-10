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
  cctools ? null,
  xcbuild ? null,
  rcodesign ? null,
  enableCodesign ? true,
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
  # The signing identity is pinned here rather than read from the environment:
  # an environment read needs impure evaluation, which consumers cannot use.
  # Pinning also means a local pure evaluation derives the same output path as
  # CI, so the signed artifact is substituted instead of rebuilt. No key
  # material reaches the store; only this path string and the certificate hash.
  codesignP12 = "/tmp/herdr-codesign/identity.p12";
  codesignPasswordFile = "/tmp/herdr-codesign/password";
  # SHA-1 of the certificate, identical to the "certificate root = H"…"" value
  # macOS records in the designated requirement. Changing the certificate must
  # change this constant so the derivation cannot hit a stale signed output.
  codesignCertSha1 = "14d58e07e52f264376d7f38139ad59e9d2fe6ddf";
  withSignature = stdenv.hostPlatform.isDarwin && enableCodesign;
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
    inherit codesignCertSha1;
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
    if [ ! -r ${lib.escapeShellArg codesignP12} ]; then
      echo "codesigning identity missing: ${codesignP12}" >&2
      echo "this package is pinned to certificate ${codesignCertSha1};" >&2
      echo "provide that key or build with enableCodesign = false" >&2
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
    dr=$(/usr/bin/codesign -d -r- "$out/bin/herdr" 2>&1)
    case "$dr" in
      *"certificate root = H\"$codesignCertSha1\""*) ;;
      *)
        echo "signed with an unexpected certificate:" >&2
        echo "$dr" >&2
        exit 1
        ;;
    esac
  '';

  meta = {
    description = "Terminal workspace manager for AI coding agents";
    homepage = "https://herdr.dev";
    license = lib.licenses.asl20;
    mainProgram = "herdr";
    platforms = lib.platforms.linux ++ lib.platforms.darwin;
  };
}
