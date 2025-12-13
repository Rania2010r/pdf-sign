{
  description = "pdf-sign: lightweight PDF signing with OpenPGP via gpg-agent";

  nixConfig = {
    extra-substituters = [
      "https://pdf-sign.cachix.org"
    ];
    extra-trusted-public-keys = [
      "pdf-sign.cachix.org-1:RjOq/uF6ksxVZsLfI9+SW4Nkhcc63+klWAoAtkZRF2U="
    ];
  };

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    crane.url = "github:ipetkov/crane";
  };

  outputs = { self, nixpkgs, flake-utils, crane, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
        };

        craneLib = crane.mkLib pkgs;
        lib = pkgs.lib;

        commonArgs = {
          src = craneLib.cleanCargoSource ./.;
          strictDeps = true;

          nativeBuildInputs = with pkgs; [
            pkg-config
            capnproto
          ];
        };

        cargoArtifacts = craneLib.buildDepsOnly commonArgs;

        meta = with lib; {
          description = "Lightweight PDF signing tool that appends detached OpenPGP signatures (delegates signing to gpg-agent)";
          homepage = "https://github.com/0x77dev/pdf-sign";
          license = licenses.gpl3Only;
          mainProgram = "pdf-sign";
          platforms = platforms.unix;
        };

        pdfSign = craneLib.buildPackage (commonArgs // {
          inherit cargoArtifacts;
          meta = meta;
        });
      in
      {
        checks = {
          pdf-sign-e2e = pkgs.runCommand "pdf-sign-e2e" {
            nativeBuildInputs = with pkgs; [ gnupg ];
          } ''
            set -euo pipefail

            export GNUPGHOME="$(mktemp -d)"
            chmod 700 "$GNUPGHOME"

            # Non-interactive agent defaults: sequoia-gpg-agent sends OPTION values,
            # keep them non-empty even in CI.
            export GPG_TTY=/dev/null
            export LANG=C

            gpgconf --launch gpg-agent

            gpg --batch --pinentry-mode loopback --passphrase "" \
              --quick-generate-key "CI Test <ci@example.invalid>" default default never

            gpg --batch --armor --export "ci@example.invalid" > cert.asc

            cat > input.pdf <<'EOF'
%PDF-1.1
1 0 obj
<<>>
endobj
trailer
<<>>
%%EOF
EOF

            signed="$(${pdfSign}/bin/pdf-sign sign input.pdf --key cert.asc)"
            ${pdfSign}/bin/pdf-sign verify "$signed" --cert cert.asc | grep -x OK >/dev/null

            touch "$out"
          '';
        };

        packages =
          {
            default = pdfSign;
            pdf-sign = pdfSign;
          };

        devShells.default = pkgs.mkShell {
          inputsFrom = [ pdfSign ];
          packages = with pkgs; [
            rustc
            cargo
            rustfmt
            clippy
            pkg-config
            capnproto
          ];
        };
      }
    );
}


