{ pkgs ? import <nixpkgs> { } }: pkgs.rustPlatform.buildRustPackage {
  src = pkgs.lib.cleanSource ./.;
  pname = "upload.files.noratrieb.dev";
  version = "0.1.0";
  cargoLock.lockFile = ./Cargo.lock;
  meta = {
    mainProgram = "upload-files-noratrieb-dev";
  };
}
