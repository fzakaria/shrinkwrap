{
  description = "Shrinkwrap and freeze the dynamic dependencies of binaries.";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-21.11";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ (import ./overlay.nix) ];
        };
      in {
        packages = { shrinkwrap = pkgs.shrinkwrap; };

        defaultPackage = pkgs.shrinkwrap;

        devShell = pkgs.mkShell {
          buildInputs = with pkgs; [ poetry ];
          inputsFrom = builtins.attrValues self.packages.${system};
        };
        
      });
}
