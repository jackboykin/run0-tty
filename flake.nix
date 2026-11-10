{
  description = "Quiet terminal polkit agent for run0 and other systemd tools";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = {
    self,
    nixpkgs,
  }: let
    inherit (nixpkgs) lib;
    forAllSystems = lib.genAttrs ["x86_64-linux" "aarch64-linux"];
  in {
    packages = forAllSystems (system: let
      pkgs = nixpkgs.legacyPackages.${system};
    in {
      default = pkgs.rustPlatform.buildRustPackage {
        pname = "run0-tty";
        version = self.shortRev or self.dirtyShortRev or "dev";
        src = lib.fileset.toSource {
          root = ./.;
          fileset = lib.fileset.unions [./Cargo.toml ./Cargo.lock ./src];
        };
        cargoLock.lockFile = ./Cargo.lock;
        postInstall = ''
          mv $out/bin/run0-tty $out/bin/pkttyagent
        '';
        meta = {
          description = "Quiet terminal polkit agent for run0 and other systemd tools";
          homepage = "https://github.com/jackboykin/run0-tty";
          license = lib.licenses.mit;
          mainProgram = "pkttyagent";
        };
      };
    });

    overlays.default = final: _: {run0-tty = self.packages.${final.stdenv.hostPlatform.system}.default;};

    formatter = forAllSystems (system: nixpkgs.legacyPackages.${system}.alejandra);
  };
}
