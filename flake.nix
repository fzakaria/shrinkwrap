{
  description = "Shrinkwrap and freeze the dynamic dependencies of binaries.";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-21.11";
    flake-utils.url = "github:numtide/flake-utils";
    poetry2nix = {
      url = "github:nix-community/poetry2nix";
      inputs = {
        flake-utils.follows = "flake-utils";
        nixpkgs.follows = "nixpkgs";
      };
    };
  };

  outputs = { self, nixpkgs, flake-utils, poetry2nix }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ poetry2nix.overlay (import ./overlay.nix) ];
        };
      in {
        packages = { shrinkwrap = pkgs.shrinkwrap; };


        checks = {
            pytest-check = pkgs.runCommand "shrinkwrap-check" { } ''
              cd ${self}
              ${pkgs.shrinkwrap-env}/bin/pytest .
              mkdir $out
            ''; 
        };

        defaultPackage = pkgs.shrinkwrap;

        devShell = pkgs.shrinkwrap-env.env.overrideAttrs (old: {
          nativeBuildInputs = with pkgs;
            old.nativeBuildInputs ++ [ pkgs.poetry ];
        });

      });
}
