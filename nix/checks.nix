{
  pkgs,
  craneLib,
  package,
  git-hooks,
  system,
}:
{
  pre-commit-check = import ./git-hooks.nix {
    inherit git-hooks system pkgs;
    src = ../.;
  };

  cargo-test = craneLib.cargoTest (
    package.commonArgs
    // {
      cargoArtifacts = package.cargoArtifacts;
    }
  );

  pdf-sign-e2e =
    pkgs.runCommand "pdf-sign-e2e"
      {
        nativeBuildInputs = with pkgs; [ gnupg ];
      }
      ''
        export PDF_SIGN="${package.pdfSign}/bin/pdf-sign"
        ${builtins.readFile ../scripts/e2e.sh}
      '';
}
