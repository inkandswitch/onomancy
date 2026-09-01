{
  description = "onomancer";

  inputs = {
    nixpkgs.url = "nixpkgs/nixos-26.05";
    nixos-unstable.url = "nixpkgs/nixos-unstable-small";

    command-utils.url = "git+https://tangled.sh/@expede.wtf/nix-command-utils";
    flake-utils.url = "github:numtide/flake-utils";

    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    wasm-bodge-src = {
      url = "github:alexjg/wasm-bodge";
      flake = false;
    };
  };

  outputs = {
    self,
    command-utils,
    flake-utils,
    nixos-unstable,
    nixpkgs,
    rust-overlay,
    wasm-bodge-src
  } @ inputs:
    flake-utils.lib.eachDefaultSystem (
      system: let
        overlays = [
          (import rust-overlay)
        ];

        pkgs = import nixpkgs {
          inherit system overlays;
          config.allowUnfree = true;
        };

        unstable = import nixos-unstable {
          inherit system overlays;
          config.allowUnfree = true;
        };

        rustVersion = "1.91.0";

        rust-toolchain = pkgs.rust-bin.stable.${rustVersion}.default.override {
          extensions = [
            "cargo"
            "clippy"
            "llvm-tools-preview"
            "rust-src"
            "rust-std"
          ];

          targets = [
            "aarch64-apple-darwin"
            "x86_64-apple-darwin"

            "x86_64-unknown-linux-musl"
            "aarch64-unknown-linux-musl"

            "wasm32-unknown-unknown"
          ];
        };

        # Nightly rustfmt for unstable formatting options (imports_granularity, etc.)
        # We need a combined nightly toolchain (rustc + rustfmt) because rustfmt
        # links against librustc_driver, which lives in the rustc component.
        # On macOS, symlinks break @rpath resolution, so we wrap the binary
        # with DYLD_LIBRARY_PATH pointing to the combined toolchain's lib/.
        nightly-rustfmt-unwrapped = pkgs.rust-bin.nightly.latest.minimal.override {
          extensions = [ "rustfmt" ];
        };

        nightly-rustfmt = pkgs.writeShellScriptBin "rustfmt" ''
          export DYLD_LIBRARY_PATH="${nightly-rustfmt-unwrapped}/lib''${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}"
          export LD_LIBRARY_PATH="${nightly-rustfmt-unwrapped}/lib''${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
          exec "${nightly-rustfmt-unwrapped}/bin/rustfmt" "$@"
        '';

        # wasm-bodge: universal npm package builder for wasm-bindgen crates
        # Not yet in nixpkgs; edition 2024 requires our rust-overlay toolchain
        wasm-bodge-rustPlatform = pkgs.makeRustPlatform {
          cargo = rust-toolchain;
          rustc = rust-toolchain;
        };

        wasm-bodge = wasm-bodge-rustPlatform.buildRustPackage {
          pname = "wasm-bodge";
          version = wasm-bodge-src.shortRev;
          src = wasm-bodge-src;
          cargoHash = "sha256-KE/AAkrdQ/tmr1X4Fya9CU/oH8e166qJax2kZ3R6jX0=";
          nativeBuildInputs = [ unstable.cargo-auditable ];
          doCheck = false; # tests require npm/puppeteer infrastructure
        };

        format-pkgs = with pkgs; [
          alejandra
          nixpkgs-fmt
          taplo
        ];

        cargo-installs = with pkgs; [
          cargo-audit
          cargo-criterion
          cargo-deny
          cargo-expand
          cargo-mutants
          cargo-nextest
          cargo-outdated
          cargo-release
          cargo-sort
          cargo-udeps
          cargo-watch
          twiggy
          unstable.wasm-bindgen-cli
          wasm-tools
        ];

        ci-env = [
          rust-toolchain
          nightly-rustfmt
          pkgs.cargo-deny
        ];

        mkCheck = name: text:
          pkgs.writeShellApplication {
            name = "onomancy-${name}";
            runtimeInputs = ci-env;
            text = ''
              export RUSTFMT="${nightly-rustfmt}/bin/rustfmt"
              set -x
              ${text}
            '';
          };

        ci-checks = {
          ci-fmt = mkCheck "ci-fmt" ''
            cargo fmt --check
          '';

          ci-clippy = mkCheck "ci-clippy" ''
            cargo clippy --workspace --all-features --all-targets
          '';

          ci-test = mkCheck "ci-test" ''
            cargo test --workspace --all-features
          '';

          ci-wasm = mkCheck "ci-wasm" ''
            # --tests so the wasm-only test targets are COMPILE-checked
            # here in seconds. ci-browser executes them; this catches a
            # broken test file without waiting for a browser to start.
            cargo check --target wasm32-unknown-unknown -p onomancy_wasm --tests
            cargo check --target wasm32-unknown-unknown --no-default-features \
              -p onomancy_core -p onomancy_protocol -p onomancy_dnssec
          '';

          ci-no-std = mkCheck "ci-no-std" ''
            cargo check --workspace --no-default-features
          '';

          ci-deny = mkCheck "ci-deny" ''
            cargo deny check
          '';
        };

        # Real-browser wasm tests (chromedriver + geckodriver). Not in
        # the `ci` aggregate: pulls whole browsers — run deliberately.
        browser-pkgs = pkgs.lib.optionals pkgs.stdenv.isLinux [
          pkgs.chromedriver
          pkgs.chromium
          pkgs.firefox
          pkgs.geckodriver
        ];

        ci-browser = pkgs.writeShellApplication {
          name = "onomancy-ci-browser";
          runtimeInputs = [ rust-toolchain unstable.wasm-bindgen-cli ] ++ browser-pkgs;
          text = ''
            set -x
            # One engine at a time: the runner picks whichever driver
            # variable is set.
            env -u GECKODRIVER CHROMEDRIVER="$(command -v chromedriver)" \
              cargo test -p onomancy_wasm --target wasm32-unknown-unknown
            env -u CHROMEDRIVER GECKODRIVER="$(command -v geckodriver)" \
              cargo test -p onomancy_wasm --target wasm32-unknown-unknown
          '';
        };

        # Playwright tests against the built npm package: real
        # Chromium + Firefox driving the wasm-bodge build.
        ci-e2e = pkgs.writeShellApplication {
          name = "onomancy-ci-e2e";
          runtimeInputs = [
            rust-toolchain
            pkgs.esbuild
            pkgs.nodejs
            # wasm-bodge shells out to `wasm-bindgen`; the CLI must match
            # the workspace's wasm-bindgen crate version (same pin as
            # ci-browser).
            unstable.wasm-bindgen-cli
            wasm-bodge
          ];
          text = ''
            export PLAYWRIGHT_BROWSERS_PATH="${pkgs.playwright-driver.browsers}"
            export PLAYWRIGHT_SKIP_VALIDATE_HOST_REQUIREMENTS=true

            # --no-wasm-opt: wasm-bodge optimizes BEFORE wasm-bindgen
            # runs, and -O4 mangles the closure-descriptor shims
            # wasm-bindgen still needs — async exports then hit
            # `unreachable` at runtime.
            wasm-bodge build \
              --crate-path onomancy_wasm \
              --package-json onomancy_wasm/package.json \
              --out-dir onomancy_wasm/dist \
              --no-wasm-opt

            cd onomancy_wasm/e2e
            npm ci --no-audit --no-fund

            # Start the static server here: Playwright's webServer
            # spawner hardcodes /bin/sh, which NixOS doesn't ship.
            node serve.mjs 8177 &
            server_pid=$!
            trap 'kill "$server_pid"' EXIT

            # grep -v: Playwright acknowledges the skip-validation
            # env var once per browser launch; drop the spam.
            node node_modules/@playwright/test/cli.js test "$@" 2>&1 \
              | { grep -v 'Skipping host requirements validation' || true; }
          '';
        };

        ci-all = pkgs.writeShellApplication {
          name = "onomancy-ci";
          runtimeInputs = pkgs.lib.attrValues ci-checks;
          text = pkgs.lib.concatMapStringsSep "\n"
            (check: "onomancy-${check}")
            (builtins.attrNames ci-checks);
        };

        # Build the Wasm module and serve the browser demos (the live
        # verifier at / and documents-naming-documents at /names.html).
        demo = pkgs.writeShellApplication {
          name = "onomancy-demo";
          runtimeInputs = [
            rust-toolchain
            unstable.wasm-bindgen-cli
            pkgs.binaryen
            pkgs.python3
          ];
          text = ''
            if [ ! -f Cargo.toml ]; then
              echo "run from the workspace root" >&2
              exit 1
            fi
            port="''${1:-8080}"

            cargo build -p onomancy_wasm --target wasm32-unknown-unknown --release
            wasm-bindgen --target web --out-dir onomancy_wasm/demo/pkg \
              target/wasm32-unknown-unknown/release/onomancy_wasm.wasm
            wasm-opt -Oz -o onomancy_wasm/demo/pkg/onomancy_wasm_bg.wasm \
              onomancy_wasm/demo/pkg/onomancy_wasm_bg.wasm

            echo
            echo "  verifier:  http://localhost:$port/"
            echo "  names:     http://localhost:$port/names.html"
            echo
            exec python3 -m http.server --directory onomancy_wasm/demo "$port"
          '';
        };

        # Built-in command modules from nix-command-utils
        rust = command-utils.rust.${system};
        wasm = command-utils.wasm.${system};

        command_menu = command-utils.commands.${system} [
          # Rust commands
          (rust.audit { cargo-audit = pkgs.cargo-audit; })
          (rust.build { cargo = pkgs.cargo; })
          (rust.test { cargo = pkgs.cargo; cargo-watch = pkgs.cargo-watch; })
          (rust.lint { cargo = pkgs.cargo; })
          (rust.fmt { cargo = pkgs.cargo; })
          (rust.doc { cargo = pkgs.cargo; })
          (rust.bench { cargo = pkgs.cargo; cargo-criterion = pkgs.cargo-criterion; xdg-open = pkgs.xdg-utils; })
          (rust.watch { cargo-watch = pkgs.cargo-watch; })

          # Wasm commands
          (wasm.build { wasm-pack = pkgs.wasm-pack; })
          (wasm.release { wasm-pack = pkgs.wasm-pack; gzip = pkgs.gzip; })
          (wasm.doc { cargo = pkgs.cargo; xdg-open = pkgs.xdg-utils; })

          # Onomancy-specific commands
          (command-utils.asModule.${system} {
            "wasm:bodge" = command-utils.cmd.${system}
              "Build the npm package from onomancy_wasm (extra args pass through)" ''
                export PATH="${pkgs.esbuild}/bin:$PATH"
                # --no-wasm-opt: wasm-bodge optimizes BEFORE wasm-bindgen
                # runs, and -O4 mangles the closure-descriptor shims
                # wasm-bindgen still needs — async exports then hit
                # `unreachable` at runtime.
                exec ${wasm-bodge}/bin/wasm-bodge build \
                  --crate-path onomancy_wasm \
                  --package-json onomancy_wasm/package.json \
                  --out-dir onomancy_wasm/dist \
                  --no-wasm-opt \
                  "$@"
              '';
            "wasm:demo" = command-utils.cmd.${system}
              "Build & serve the browser demos (port arg, default 8080)" ''
                exec ${demo}/bin/onomancy-demo "$@"
              '';
            "wasm:e2e" = command-utils.cmd.${system}
              "Playwright browser tests against the built npm package" ''
                exec ${ci-e2e}/bin/onomancy-ci-e2e "$@"
              '';
          })
        ];
      in {
        devShells.default = pkgs.mkShell {
          name = "onomancer_shell";

          nativeBuildInputs =
            command_menu
            ++ [
              rust-toolchain
              nightly-rustfmt

              pkgs.binaryen
              pkgs.esbuild
              pkgs.nodejs
              pkgs.rust-analyzer
              pkgs.wasm-pack
              wasm-bodge
            ]
            ++ browser-pkgs
            ++ [
            ]
            ++ format-pkgs
            ++ cargo-installs
            ++ pkgs.lib.optionals pkgs.stdenv.isLinux [
              pkgs.clang
              pkgs.llvmPackages.libclang
            ];

          shellHook = ''
            unset SOURCE_DATE_EPOCH
            export WORKSPACE_ROOT="$(pwd)"
            export RUSTFMT="${nightly-rustfmt}/bin/rustfmt"
            menu
          '';
        };

        apps =
          pkgs.lib.mapAttrs (name: check: {
            type = "app";
            program = "${check}/bin/onomancy-${name}";
          })
          (ci-checks // {
            ci = ci-all;
            ci-browser = ci-browser;
            ci-e2e = ci-e2e;
            inherit demo;
          });

        formatter = pkgs.alejandra;
      }
    );
}
