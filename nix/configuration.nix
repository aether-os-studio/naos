{
  lib,
  pkgs,
  ...
}:
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

  time.timeZone = "Asia/Shanghai";

  users.users.root.initialPassword = "root";
  users.users.aether = {
    isNormalUser = true;
    description = "Aether";
    initialPassword = "aether";
    extraGroups = [ "wheel" ];
    home = "/home/aether";
  };

  services.getty.autologinUser = "aether";

  environment.systemPackages = with pkgs; [
    bashInteractive
    coreutils
    findutils
    pciutils
    usbutils
    git
    curl
    gnugrep
    iproute2
    fastfetch
    procps
    util-linux
    dbus
  ];

  services.dbus.enable = true;

  services.xserver = {
    enable = true;
    desktopManager = {
      xterm.enable = false;
      xfce.enable = true;
    };
  };
  services.displayManager.defaultSession = "xfce";

  # na-kernel owns the kernel. This repository owns only stage-1 and the
  # stage-2 NixOS userspace closure placed on the root filesystem.
  system.build.installBootLoader = lib.mkForce (pkgs.writeShellScript "no-bootloader" "exit 0");
  system.stateVersion = "26.05";
}
