#!/bin/bash

# Copyright (c) 2021,2022 The University of British Columbia.
# All rights reserved.
#
# This file is distributed under the terms in the attached LICENSE file.

# create the build directory if it doesn't exist
mkdir -p /source/build

# cd into the build directory
cd /source/build


if [ "$1" == "" ]; then
    exec "/bin/bash"
else
    exec "$@"
fi
