{ stdenv, lib, poetry2nix, python39, patchelf, coreutils, poetryOverrides
, writeScriptBin, makeWrapper }:
let
  app = poetry2nix.mkPoetryApplication {
    projectDir = ./.;
    python = python39;
    buildInputs = [ patchelf ];
    overrides = [ poetry2nix.defaultPoetryOverrides poetryOverrides ];
  };
in stdenv.mkDerivation {
    name = "shrinkwrap";
    buildInputs = [ makeWrapper ];
    phases = [ "installPhase" ];
    installPhase = ''
        mkdir $out
        makeWrapper ${app}/bin/shrinkwrap $out/bin/shrinkwrap --prefix PATH : ${lib.makeBinPath [coreutils patchelf]}
    '';
}
