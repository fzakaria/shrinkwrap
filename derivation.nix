{ stdenv, lib, poetry2nix, python39, poetryOverrides, writeScriptBin
, makeWrapper }:
poetry2nix.mkPoetryApplication {
  projectDir = ./.;
  python = python39;
  overrides = [ poetry2nix.defaultPoetryOverrides poetryOverrides ];
}
