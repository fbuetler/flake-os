#!/bin/bash

##########################################################################
# Copyright (c) 2019,2020 ETH Zurich.
# Copyright (c) 2021 The University of British Columbia.
# All rights reserved.
#
# This file is distributed under the terms in the attached LICENSE file.
# If you do not find this file, copies can be found by writing to:
# ETH Zurich D-INFK, Universitaetstrasse 6, CH-8092 Zurich. Attn: Systems Group.
##########################################################################

# set the docker image to use
BF_DOCKER=achreto/barrelfish-aos:20.04-lts

# assume the source directory is the current directory
BF_SOURCE=$(readlink -f $(git rev-parse --show-toplevel))

# we set the build directory to the source directory to avoid path problems
BF_BUILD=$BF_SOURCE/build

# pull the docker image if we don't have it yet.
docker pull $BF_DOCKER

# make sure the build directory exists
mkdir -p $BF_BUILD

# run the command in the docker image with the same userid to avoid
# permission problems later.

if [[ "$@" == "" ]]; then
    docker run -u $(id -u) -i -t \
        --mount type=bind,source=$BF_SOURCE,target=/source \
        $BF_DOCKER "$@"
else
    docker run -u $(id -u) \
        --mount type=bind,source=$BF_SOURCE,target=/source \
        $BF_DOCKER "$@"
fi


