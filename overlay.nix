self: super: {

  # https://github.com/nix-community/poetry2nix/issues/218
  poetryOverrides = self: super: {
    typing-extensions = super.typing-extensions.overridePythonAttrs
      (old: { buildInputs = (old.buildInputs or [ ]) ++ [ self.flit-core ]; });

    # This is an unreleased version of Lief that fixes a bug when generates GNU notes
    # https://github.com/lief-project/LIEF/commit/72ebe0d89e94c18d2b64da2cbbc7a0a0d53a5693
    lief = super.lief.overridePythonAttrs (old: {
      version = "0.12.72ebe0d";
      src = super.pkgs.fetchFromGitHub {
        owner = "lief-project";
        repo = "LIEF";
        rev = "72ebe0d89e94c18d2b64da2cbbc7a0a0d53a5693";
        sha256 = "039fwn6b92aq2vb8s44ld5bclz4gz2f9ki2kj7gy31x9lzjldnwk";
      };
      enableParallelBuilding = true;
      dontUseCmakeConfigure = true;
      nativeBuildInputs = [ self.pkgs.cmake ];
    });
  };

  shrinkwrap = self.callPackage ./derivation.nix { };

  shrinkwrap-env = self.poetry2nix.mkPoetryEnv {
    projectDir = ./.;
    overrides = [ self.poetry2nix.defaultPoetryOverrides self.poetryOverrides ];
    editablePackageSources = { shrinkwrap = ./shrinkwrap; };
  };

}
