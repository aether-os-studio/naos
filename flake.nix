{
  description = "Development shell for naos";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs }:
    let
      lib = nixpkgs.lib;
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems = f: lib.genAttrs systems (system: f system);
    in
    {
      devShells = forAllSystems (system:
        let
          pkgs = import nixpkgs { inherit system; };

          toolchainWrappers = pkgs.runCommand "naos-toolchain-wrappers" { } ''
            mkdir -p "$out/bin"

            cat > "$out/bin/clang-target-wrapper" <<'EOF'
            #!${pkgs.runtimeShell}
            set -euo pipefail

            tool="$(basename "$0")"
            base=''${tool%-linux-gnu-*}
            kind=''${tool#*-linux-gnu-}

            case "$base" in
              x86_64) ld_emulation="elf_x86_64" ;;
              aarch64) ld_emulation="aarch64elf" ;;
              riscv64) ld_emulation="elf64lriscv" ;;
              loongarch64) ld_emulation="elf64loongarch" ;;
              *)
                echo "unsupported target prefix: $base" >&2
                exit 1
                ;;
            esac

            case "$kind" in
              gcc) exec ${pkgs.clang}/bin/clang "$@" ;;
              g++)
                exec ${pkgs.clang}/bin/clang++ "$@"
                ;;
              ld)
                rewritten=(-m "$ld_emulation")
                for arg in "$@"; do
                  case "$arg" in
                    -Wl,*)
                      old_ifs="$IFS"
                      IFS=','
                      read -r -a split <<< "''${arg#-Wl,}"
                      IFS="$old_ifs"
                      rewritten+=("''${split[@]}")
                      ;;
                    *)
                      rewritten+=("$arg")
                      ;;
                  esac
                done
                exec ${pkgs.lld}/bin/ld.lld "''${rewritten[@]}"
                ;;
              nm) exec ${pkgs.llvm}/bin/llvm-nm "$@" ;;
              objcopy) exec ${pkgs.llvm}/bin/llvm-objcopy "$@" ;;
              *)
                echo "unsupported tool kind: $kind" >&2
                exit 1
                ;;
            esac
            EOF

            chmod +x "$out/bin/clang-target-wrapper"

            for arch in x86_64 aarch64 riscv64 loongarch64; do
              for tool in gcc g++ ld nm objcopy; do
                ln -s clang-target-wrapper "$out/bin/$arch-linux-gnu-$tool"
              done
            done
          '';
        in
        {
          default = pkgs.mkShell {
            packages = with pkgs; [
              bash
              binutils
              clang
              cpio
              curl
              dosfstools
              e2fsprogs
              findutils
              git
              gnumake
              gnugrep
              gnutar
              gptfdisk
              gzip
              lld
              llvm
              meson
              mtools
              nasm
              ninja
              pkg-config
              perl
              qemu
              wget
              which
              xz
              toolchainWrappers
            ];

            shellHook = ''
              export ARCH="''${ARCH:-x86_64}"
              export BUILD_MODE="''${BUILD_MODE:-debug}"
              export BOOT_PROTOCOL="''${BOOT_PROTOCOL:-limine}"
              export SYSTEM_ABI="''${SYSTEM_ABI:-linux}"
              export KERNEL_MODEL="''${KERNEL_MODEL:-mixed}"

              echo "naos dev shell"
              echo "default ARCH=$ARCH"
              echo "host tools are available; project scripts still invoke sudo for image/rootfs steps"
            '';
          };
        });

      formatter = forAllSystems (system:
        let
          pkgs = import nixpkgs { inherit system; };
        in
        pkgs.nixfmt);
    };
}
