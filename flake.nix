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

      lib.fetch = { server, url, name }: let
        tag = builtins.substring 0 16 (builtins.hashString "sha256" "${name}:${server}:${url}");
        data = pkgs.runCommand "${name}-${tag}" { } ''
          echo "substituter-api: expected to be substituted" >&2
          exit 1
        '';
        path = builtins.unsafeDiscardStringContext data.outPath;
        notify = pkgs.runCommand "substituter-api-notify-${tag}" {
          outputHashMode = "recursive";
          outputHash = "sha256-d6xi4mKdjkX2JFicDIv5niSzpyI0m/Hnm8GGAIU04kY=";
        } ''
          set -e
          ${pkgs.curl}/bin/curl -fsS ${server}/notify \
            --data-binary ${pkgs.lib.escapeShellArg (builtins.toJSON { inherit path url; })}
          touch $out
        '';
      in pkgs.runCommand "${name}-${tag}" { notify = builtins.readFile notify; } ''
        cp ${data} $out
      '';
    };
  };
}
