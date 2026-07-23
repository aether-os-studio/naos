{
  description = "NixOS userspace and initramfs for na-kernel";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { nixpkgs, ... }:
    let
      lib = nixpkgs.lib;
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "riscv64-linux"
        "loongarch64-linux"
      ];
      forAllSystems = f: lib.genAttrs systems (system: f system);
    in
    {
      packages = forAllSystems (
        system:
        let
          pkgs = import nixpkgs { inherit system; };
          nixos = lib.nixosSystem {
            inherit system;
            modules = [ ./configuration.nix ];
          };
          modulesPath = builtins.getEnv "NA_KERNEL_MODULES";
          kernelModules =
            if modulesPath == "" then
              null
            else
              builtins.path {
                name = "na-kernel-modules";
                path = modulesPath;
              };
          initramfs =
            pkgs.runCommand "na-kernel-initramfs-${system}"
              {
                nativeBuildInputs = [ pkgs.cpio ];
              }
              ''
                root="$TMPDIR/root"
                mkdir -p "$root/bin" "$root/dev" "$root/lib/modules" "$root/proc" \
                  "$root/sbin" "$root/sys" "$root/sysroot"
                cp ${pkgs.pkgsStatic.busybox}/bin/busybox "$root/bin/busybox"
                chmod 0755 "$root/bin/busybox"
                for applet in awk cat echo grep ln ls mkdir mount mv poweroff reboot \
                  rm sed sh sleep switch_root sync test umount; do
                  ln -s /bin/busybox "$root/bin/$applet"
                done
                ln -s /bin/busybox "$root/sbin/switch_root"
                install -m 0755 ${./initramfs-init.sh} "$root/init"
                ${lib.optionalString (kernelModules != null) ''
                  cp ${kernelModules}/*.ko "$root/lib/modules/"
                ''}
                mkdir -p "$out"
                (cd "$root" && find . -print0 | sort -z | cpio --null -o -H newc) \
                  > "$out/initramfs.img"
              '';
          rootfsBase = import "${nixpkgs}/nixos/lib/make-disk-image.nix" {
            inherit lib pkgs;
            config = nixos.config;
            name = "na-kernel-nixos-rootfs-${system}";
            baseName = "rootfs";
            format = "raw";
            partitionTableType = "legacy";
            installBootLoader = false;
            diskSize = "auto";
            additionalSpace = "1024M";
            configFile = ./configuration.nix;
          };
          rootfs = lib.overrideDerivation rootfsBase (old: {
            preVM =
              builtins.replaceStrings
                [ "mkfs.ext4 -b 4096 -F -L" ]
                [
                  "mkfs.ext4 -b 1024 -I 256 -O extent,64bit,flex_bg,huge_file,dir_nlink,extra_isize,dir_index,metadata_csum,^has_journal,^quota,^metadata_csum_seed,^orphan_file,^project,^encrypt,^verity,^casefold,^inline_data,^ea_inode,^bigalloc,^mmp,^fast_commit,^sparse_super2 -F -L"
                ]
                old.preVM;
          });
        in
        {
          inherit initramfs rootfs;
          default = rootfs;
        }
      );

      devShells = lib.genAttrs [ "x86_64-linux" "aarch64-linux" ] (
        system:
        let
          pkgs = import nixpkgs { inherit system; };
        in
        {
          default = pkgs.mkShell {
            packages = with pkgs; [
              OVMF.fd
              cpio
              curl
              dosfstools
              findutils
              git
              gnumake
              gptfdisk
              mtools
              nix
              qemu
            ];
            shellHook = ''
              export NA_OVMF_CODE="${pkgs.OVMF.fd}/FV/OVMF_CODE.fd"
              echo "naos userspace shell; local Nix store: $PWD/.nix-store"
            '';
          };
        }
      );

      formatter = lib.genAttrs [ "x86_64-linux" "aarch64-linux" ] (
        system: (import nixpkgs { inherit system; }).nixfmt
      );
    };
}
