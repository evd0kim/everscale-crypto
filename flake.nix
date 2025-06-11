{
  description = "everscale-crypto";
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";
    flake-compat.url = "github:edolstra/flake-compat/v1.1.0";
    systems.url = "github:nix-systems/default";
    flake-utils = {
      url = "github:numtide/flake-utils";
      inputs.systems.follows = "systems";
    };
  };
  outputs = { self, nixpkgs, flake-utils, ... }:
  let
  in flake-utils.lib.eachDefaultSystem (system:
  let
    pkgs = import nixpkgs {
      inherit system;
    };
  in {
    devShells.default = pkgs.mkShell {
      packages = builtins.attrValues {
        inherit (pkgs)
          cargo
          rustfmt
          rustc
          clippy
          rust-analyzer
          cargo-outdated;
      };
    };
  });
}
