{
  description = "run0 that asks for the password on the terminal";

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
          ln -s run0-tty $out/bin/run0
          mkdir -p $out/libexec/run0-tty
          ln -s ../../bin/run0-tty $out/libexec/run0-tty/pkttyagent
        '';
        meta = {
          description = "run0 that asks for the password on the terminal";
          homepage = "https://github.com/jackboykin/run0-tty";
          license = lib.licenses.mit;
          mainProgram = "run0-tty";
        };
      };
    });

    overlays.default = final: _: {run0-tty = self.packages.${final.stdenv.hostPlatform.system}.default;};

    formatter = forAllSystems (system: nixpkgs.legacyPackages.${system}.alejandra);
  };
}
