{
  description = "Stable Rust + RustRover";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
  };

  outputs = { self, nixpkgs, rust-overlay }:
    let
      supportedSystems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = nixpkgs.lib.genAttrs supportedSystems;

      nixpkgsFor = forAllSystems (system: import nixpkgs {
        inherit system;
        overlays = [ (import rust-overlay) ];
      });
    in
    {
      devShells = forAllSystems (system:
        let
          pkgs = nixpkgsFor.${system};
          rustToolchain = pkgs.rust-bin.stable.latest.default.override {
            extensions = [ "rust-src" ];
          };
        in
        {
          default = pkgs.mkShell rec {
            nativeBuildInputs = with pkgs; [
              pkg-config
              rustToolchain
              # For clang bindgen
              # rustPlatform.bindgenHook
            ];

            buildInputs = with pkgs; [

            ];

            RUST_SRC_PATH = "${rustToolchain}/lib/rustlib/src/rust/library";

            LD_LIBRARY_PATH = pkgs.lib.makeLibraryPath buildInputs;

            shellHook = ''
              ln -sfn ${rustToolchain}/bin .toolchain
            '';
          };
        });
    };
}