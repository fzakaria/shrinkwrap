{ stdenv, lib, poetry2nix, python39, patchelf, coreutils, poetryOverrides
, writeScriptBin }:
let
  app = poetry2nix.mkPoetryApplication {
    projectDir = ./.;
    python = python39;
    buildInputs = [ patchelf ];
    overrides = [ poetry2nix.defaultPoetryOverrides poetryOverrides ];
  };
in writeScriptBin "shrinkwrap" ''
  #! ${stdenv.shell}
  export PATH="${lib.makeBinPath ([ coreutils patchelf ])}''${PATH:+:}$PATH"
  ${app}/bin/shrinkwrap "$@"
''
