{
  outputs = inputs@{
    self, nixpkgs, flake-parts,
  }: flake-parts.lib.mkFlake { inherit inputs; } {
    systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
    transposition.lib.adHoc = true;

    perSystem = { pkgs, lib, ... }: {
      packages.default = pkgs.rustPlatform.buildRustPackage {
        pname = "substituter-api";
        version = "0.1.0";
        src = lib.fileset.toSource {
          root = ./.;
          fileset = lib.fileset.unions [
            ./Cargo.toml
            ./Cargo.lock
            ./src
          ];
        };
        cargoLock.lockFile = ./Cargo.lock;
      };

      devShells.default = pkgs.mkShell {
        nativeBuildInputs = with pkgs; [ rustc cargo clippy rustfmt ];
      };

      lib.fetch = { server, url }: let
        # The server checks that the store-path name is sha256(url), so an
        # anonymous registration can never point another path at a different url.
        name = builtins.hashString "sha256" url;
        data = pkgs.runCommand name { inherit server; } ''
          echo "substituter-api: expected to be substituted" >&2
          exit 1
        '';
        path = builtins.unsafeDiscardStringContext data.outPath;
        poke = pkgs.runCommand "poke-${builtins.hashString "sha256" "${server}:${url}"}" {
          outputHashMode = "recursive";
          outputHash = "sha256-d6xi4mKdjkX2JFicDIv5niSzpyI0m/Hnm8GGAIU04kY=";
        } ''
          set -e
          ${pkgs.curl}/bin/curl -fsS ${server}/poke \
            --data-binary ${pkgs.lib.escapeShellArg (builtins.toJSON { inherit path url; })}
          touch $out
        '';
      in pkgs.runCommand "fetch-${name}" { poke = builtins.readFile poke; } ''
        cp ${data} $out
      '';
    };
  };
}
