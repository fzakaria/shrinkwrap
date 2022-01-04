{
  description = "Shrinkwrap and freeze the dynamic dependencies of binaries.";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-21.11";
    flake-utils.url = "github:numtide/flake-utils";
    patchelf = {
      url = "github:NixOS/patchelf";
      inputs = {
        nixpkgs.follows = "nixpkgs";
      };
    };
    poetry2nix = {
      url = "github:nix-community/poetry2nix";
      inputs = {
        flake-utils.follows = "flake-utils";
        nixpkgs.follows = "nixpkgs";
      };
    };
    flake-compat = {
      url = "github:edolstra/flake-compat";
      flake = false;
    };
  };

  outputs = { self, nixpkgs, flake-utils, poetry2nix, patchelf, ... }@inputs:
    flake-utils.lib.eachDefaultSystem (system:
      let
        patchelf-overlay = prev: super: { patchelf = patchelf.packages.${system}.patchelf; };
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ patchelf-overlay poetry2nix.overlay (import ./overlay.nix) ];
        };
        runCodeAnalysis = name: command:
          pkgs.runCommand "shrinkwrap-${name}-check" { } ''
            cd ${self}    
            ${command}
            mkdir $out
          '';
      in
      {
        packages = { shrinkwrap = pkgs.shrinkwrap; };


        checks = {
          pytest-check = runCodeAnalysis "pytest" ''
            ${pkgs.shrinkwrap-env}/bin/pytest -p no:cacheprovider .
          '';
          black-check = runCodeAnalysis "black" ''
            ${pkgs.shrinkwrap-env}/bin/black --check .
          '';
          mypy-check = runCodeAnalysis "mypy" ''
            ${pkgs.shrinkwrap-env}/bin/mypy .
          '';
          isort-check = runCodeAnalysis "isort" ''
            ${pkgs.shrinkwrap-env}/bin/isort -c .
          '';
          flake8-check = runCodeAnalysis "flake8" ''
            ${pkgs.shrinkwrap-env}/bin/flake8 .
          '';
          nixpkgs-fmt-check = runCodeAnalysis "nixpkgs-fmt" ''
            ${pkgs.nixpkgs-fmt}/bin/nixpkgs-fmt --check .
          '';
        };

        defaultPackage = pkgs.shrinkwrap;

        devShell = pkgs.shrinkwrap-env.env.overrideAttrs (old: {
          nativeBuildInputs = with pkgs;
            old.nativeBuildInputs ++ [ poetry nixpkgs-fmt nix-linter ];
        });

      });
}
