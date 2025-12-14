{
  pkgs,
  pdfSign,
  pre-commit-check,
}:
pkgs.mkShell {
  inputsFrom = [ pdfSign ];

  shellHook = pre-commit-check.shellHook;

  packages =
    with pkgs;
    [
      rustc
      cargo
      rustfmt
      clippy
      pkg-config
      capnproto
    ]
    ++ pre-commit-check.enabledPackages;
}
