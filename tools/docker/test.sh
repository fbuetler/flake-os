#!/bin/bash

# Copyright (c) 2021 The University of British Columbia.
# All rights reserved.
#
# This file is distributed under the terms in the attached LICENSE file.

# assume the source directory is the current directory
BF_SOURCE=$(git rev-parse --show-toplevel)

# make sure the build directory exists
mkdir -p $BF_SOURCE/build

# run the command in the docker image with the same userid to avoid
# permission problems later.
# BF_DOCKER must be set in the environment
docker run -u $(id -u) -i -t \
    --mount type=bind,source=$BF_SOURCE,target=/source \
    $BF_DOCKER
