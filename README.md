# substituter-api

A binary cache that proxies external URLs, so pure Nix evaluation can fetch resources without knowing their content hash.

```nix
{
  inputs = {
    substituter-api.url = "github:Anillc/substituter-api";
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-parts.url = "github:hercules-ci/flake-parts";
  };

  outputs = inputs@{
    self, nixpkgs, flake-parts, substituter-api,
  }: flake-parts.lib.mkFlake { inherit inputs; } {
    systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];

    perSystem = { system, ... }: let
      server = "http://127.0.0.1:8080";
    in {
      packages.default = substituter-api.lib.${system}.fetch {
        inherit server;
        url = "https://www.google.com/robots.txt";
        name = "google-robots";
      };
    };
  };
}
```

```bash
$ nix run .
$ nix build --option substituters http://127.0.0.1:8080 --option trusted-public-keys "$(cat substituter-api.pub)"
```
