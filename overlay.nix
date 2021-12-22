self: super: {
  # https://github.com/nix-community/poetry2nix/issues/218
  poetryOverrides = self: super: {
    typing-extensions = super.typing-extensions.overridePythonAttrs
      (old: { buildInputs = (old.buildInputs or [ ]) ++ [ self.flit-core ]; });
  };

  shrinkwrap = self.callPackage ./derivation.nix { };
}
