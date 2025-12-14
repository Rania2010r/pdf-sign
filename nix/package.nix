{
  pkgs,
  craneLib,
  lib,
}:
rec {
  commonArgs = {
    src = craneLib.cleanCargoSource ../.;
    strictDeps = true;

    nativeBuildInputs = with pkgs; [
      pkg-config
      capnproto
    ];
  };

  cargoArtifacts = craneLib.buildDepsOnly commonArgs;

  pdfSign = craneLib.buildPackage (
    commonArgs
    // {
      inherit cargoArtifacts;
      meta = with lib; {
        description = "Lightweight PDF signing tool that appends detached OpenPGP signatures (delegates signing to gpg-agent)";
        homepage = "https://github.com/0x77dev/pdf-sign";
        license = licenses.gpl3Only;
        mainProgram = "pdf-sign";
        platforms = platforms.unix;
      };
    }
  );
}
