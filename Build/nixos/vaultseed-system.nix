# Instalação:
#   1. Copiar/enviar para /etc/nixos/vaultseed.nix no servidor NixOS
#   2. Adicionar `./vaultseed.nix` ao campo `imports` do configuration.nix:
#        imports = [ ./hardware-configuration.nix ./vaultseed.nix ];
#   3. sudo nixos-rebuild switch

{ config, pkgs, lib, ... }:

let
  # Cross-compilers para targets Linux 
  # Cada pkgsCross.* dá um GCC configurado para o target respectivo.
  # Os binários ficam disponíveis no PATH com prefixo <triple>-gcc/g++.
  gcc-aarch64 = pkgs.pkgsCross.aarch64-multiplatform.buildPackages.gcc;
  gcc-armv7   = pkgs.pkgsCross.armv7l-hf-multiplatform.buildPackages.gcc;
  gcc-i686    = pkgs.pkgsCross.gnu32.buildPackages.gcc;

  # pkg-config para cada target (necessário para features = "desktop" cross)
  pkgconf-aarch64 = pkgs.pkgsCross.aarch64-multiplatform.buildPackages.pkg-config;
  pkgconf-armv7   = pkgs.pkgsCross.armv7l-hf-multiplatform.buildPackages.pkg-config;
  pkgconf-i686    = pkgs.pkgsCross.gnu32.buildPackages.pkg-config;

in {
  # Permitir pacotes non-free (Android SDK requer aceitar licença)
  nixpkgs.config.allowUnfree = lib.mkDefault true;

  environment.systemPackages = with pkgs; [

    # Java 17 (Android SDK + Gradle) 
    jdk17

    # Rust (gerido via rustup - targets instalados pelo setup.py) 
    rustup

    # Compiladores nativos + linkers
    gcc
    clang
    lld              # necessário para cargo-xwin (Windows cross)
    llvm             # lld-link
    mold             # linker rápido para builds nativas x86_64-unknown-linux-gnu

    # Ferramentas de build 
    pkg-config
    cmake
    gnumake
    binutils
    ninja            # necessário para build completo do skia (skia-bindings)
    gn               # idem - gerador de build do skia

    # Cross-compilers Linux (aarch64 / armv7 / i686) 
    gcc-aarch64
    gcc-armv7
    gcc-i686

    # pkg-config cross (para resolver libs nas arquitecturas alvo)
    pkgconf-aarch64
    pkgconf-armv7
    pkgconf-i686

    # Bibliotecas nativas para target desktop (features = "desktop") 
    libxkbcommon
    wayland
    wayland-protocols
    libGL
    libx11
    libxcursor
    libxrandr
    libxi
    fontconfig
    freetype
    gtk3

    # Outputs .dev (ficheiros .pc para pkg-config) 
    # environment.systemPackages só inclui o output "out" por defeito;
    # os .pc ficam no output "dev" - sem isto, pkg-config não encontra
    # fontconfig/freetype/etc mesmo com PKG_CONFIG_PATH correcto.
    fontconfig.dev
    freetype.dev
    libxkbcommon.dev
    wayland.dev
    libGL.dev

    # Libs cross-compiladas para aarch64 (ligação na cross-build desktop)
    (pkgs.pkgsCross.aarch64-multiplatform.libxkbcommon.overrideAttrs (old: {
      outputs = lib.filter (o: o != "doc") old.outputs;
      mesonFlags = (old.mesonFlags or []) ++ [ "-Denable-docs=false" ];
    }))
    pkgs.pkgsCross.aarch64-multiplatform.wayland
    pkgs.pkgsCross.aarch64-multiplatform.libGL

    # Utilitários 
    unzip
    curl
    wget
    git
    python3
    direnv    # usado por scripts antigos - pode ser removido quando não necessário
  ];

  # Variáveis de ambiente do sistema 
  # Definidas para todos os utilizadores / sessões SSH.
  environment.variables = {
    # Java
    JAVA_HOME = "${pkgs.jdk17}";

    # Rust cross-compilers - apontam para os binários instalados acima
    # (os nomes dos binários seguem o padrão <triple>-gcc do pkgsCross)
    CC_aarch64_unknown_linux_gnu    = "${gcc-aarch64}/bin/aarch64-unknown-linux-gnu-gcc";
    CXX_aarch64_unknown_linux_gnu   = "${gcc-aarch64}/bin/aarch64-unknown-linux-gnu-g++";

    CC_armv7_unknown_linux_gnueabihf  = "${gcc-armv7}/bin/armv7l-unknown-linux-gnueabihf-gcc";
    CXX_armv7_unknown_linux_gnueabihf = "${gcc-armv7}/bin/armv7l-unknown-linux-gnueabihf-g++";

    CC_i686_unknown_linux_gnu    = "${gcc-i686}/bin/i686-unknown-linux-gnu-gcc";
    CXX_i686_unknown_linux_gnu   = "${gcc-i686}/bin/i686-unknown-linux-gnu-g++";

    # pkg-config paths cross
    PKG_CONFIG_PATH_aarch64_unknown_linux_gnu   = "${pkgconf-aarch64}/lib/pkgconfig";
    PKG_CONFIG_PATH_armv7_unknown_linux_gnueabihf = "${pkgconf-armv7}/lib/pkgconfig";
    PKG_CONFIG_PATH_i686_unknown_linux_gnu      = "${pkgconf-i686}/lib/pkgconfig";
    PKG_CONFIG_ALLOW_CROSS                      = "1";

    # Cargo
    CARGO_TERM_COLOR  = "never";
    CARGO_INCREMENTAL = "1";

    # cargo-xwin (Windows cross)
    XWIN_ACCEPT_LICENSE = "1";
    XWIN_ARCH           = "x86,x86_64,aarch64";

    # Android
    ANDROID_NDK_HOME        = "$HOME/android-sdk/ndk/r27c";
    ANDROID_NDK             = "$HOME/android-sdk/ndk/r27c";
    ANDROID_SDK_ROOT        = "$HOME/android-sdk";
    ANDROID_HOME            = "$HOME/android-sdk";
  };

  # nix-ld: compatibilidade para binários FHS (aapt2, Android SDK, etc.) 
  # Sem isto, binários pré-compilados genéricos Linux falham com
  # "NixOS cannot run dynamically linked executables intended for generic linux"
  programs.nix-ld.enable = true;

  # PATH extra: gradle (instalado por utilizador em $HOME/gradle-*/bin)
  # não pode ficar aqui porque depende do utilizador - o setup.py adiciona
  # ao ~/.bashrc ou ~/.profile do utilizador.
}
