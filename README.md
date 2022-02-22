# AOS Code Repository

Welcome to AOS. This is the code handout repository.

The code in this repository is a simplified version of the [Barrelfish OS](barrelfish.org).

## License

see the LICENSE file.

## Dependencies

Before you can start, make sure you have installed the following dependencies:

```
apt-get install build-essential bison flex ghc libghc-src-exts-dev \
                libghc-ghc-paths-dev libghc-parsec3-dev libghc-random-dev \
                libghc-ghc-mtl-dev libghc-async-dev picocom cabal-install freebsd-glue \
                libelf-freebsd-dev git gcc-aarch64-linux-gnu g++-aarch64-linux-gnu \
                qemu-efi-aarch64 qemu-system-arm qemu-utils python3 parted wget mtools

wget -P $HOME/bin https://github.com/NXPmicro/mfgtools/releases/download/uuu_1.4.165/uuu
chmod 755 $HOME/bin/uuu
```

## Docker

Use the following command to obtain and start a Docker container with all dependencies.

```
./tools/bfdocker.sh
```

## Building

To build Barrelfish, create a build directory, and execute Hake to generate the Makefile

```
mkdir build
cd build
../hake/hake.sh -s ../ -a armv8
```

Then you can use `make` to build Barrelfish. To obtain an overview of all targets execute
```
make help
```

Likewise, for all platforms that can be build

```
make help-platforms
```

and finally the boot targets with

```
make help-boot
```