{ lib, pkgs, ... }:
{
  boot.kernel.enable = false;
  boot.initrd.enable = false;
  boot.loader.grub.enable = false;
  boot.loader.systemd-boot.enable = false;

  fileSystems."/" = {
    device = "/dev/root";
    fsType = "ext4";
  };

  networking.hostName = "na-kernel";
  networking.useDHCP = true;
  services.getty.autologinUser = "root";
  users.users.root.initialPassword = "root";

  environment.systemPackages = with pkgs; [
    bashInteractive
    coreutils
    curl
    findutils
    git
    gnugrep
    iproute2
    pciutils
    procps
    util-linux
  ];

  # na-kernel owns the kernel.  This repository owns only stage-1 and the
  # stage-2 NixOS userspace closure placed on the root filesystem.
  system.build.installBootLoader = lib.mkForce (pkgs.writeShellScript "no-bootloader" "exit 0");
  system.stateVersion = "25.11";
}
