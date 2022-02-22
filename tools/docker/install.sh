#!/bin/bash

# Copyright (c) 2021 The University of British Columbia.
# All rights reserved.
#
# This file is distributed under the terms in the attached LICENSE file.


# update the repositories
apt-get update && apt-get upgrade -y

# install some system dependencies
DEBIAN_FRONTEND=noninteractive apt-get install -y \
    python3 parted wget mtools

# install barrelfish dependencies
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y \
    build-essential bison flex ghc libghc-src-exts-dev \
    libghc-ghc-paths-dev libghc-parsec3-dev libghc-random-dev\
    libghc-ghc-mtl-dev libghc-async-dev picocom cabal-install freebsd-glue \
    libelf-freebsd-dev git gcc-aarch64-linux-gnu g++-aarch64-linux-gnu \
    qemu-efi-aarch64 qemu-system-arm qemu-utils


# install the remaining haskell package
cabal v1-update
cabal v1-install --global bytestring-trie

# get the uuu tool
wget -P /bin https://github.com/NXPmicro/mfgtools/releases/download/uuu_1.4.165/uuu
chmod 755 /bin/uuu

# create the tools directory
mkdir /source
chmod 755 /source

# clean the apt
apt-get clean && apt-get autoclean && apt-get autoremove -y

# make sure it's executable
chmod 755 /entrypoint.sh