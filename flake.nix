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


