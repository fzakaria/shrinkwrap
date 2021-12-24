self: super: {
  # https://github.com/nix-community/poetry2nix/issues/218
  poetryOverrides = self: super: {
    typing-extensions = super.typing-extensions.overridePythonAttrs
      (old: { buildInputs = (old.buildInputs or [ ]) ++ [ self.flit-core ]; });

    lief = super.lief.overridePythonAttrs (old: { dontUseCmakeConfigure = true; nativeBuildInputs = [ self.pkgs.cmake ]; });
  };

  shrinkwrap = self.callPackage ./derivation.nix { };

  shrinkwrap-env = self.poetry2nix.mkPoetryEnv {
    projectDir = ./.;
    overrides = [ self.poetry2nix.defaultPoetryOverrides self.poetryOverrides ];
    editablePackageSources = { shrinkwrap = ./shrinkwrap; };
  };

}
