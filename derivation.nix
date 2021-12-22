{ poetry2nix, python39, patchelf, poetryOverrides }:

poetry2nix.mkPoetryApplication {
  projectDir = ./.;
  python = python39;
  buildInputs = [ patchelf ];
  overrides = [ poetry2nix.defaultPoetryOverrides poetryOverrides ];
}
