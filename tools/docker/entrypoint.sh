#!/bin/bash

# Copyright (c) 2021 The University of British Columbia.
# All rights reserved.
#
# This file is distributed under the terms in the attached LICENSE file.

cd /source

if [ "$1" == "" ]; then
    exec "/bin/bash"
else
    exec "$@"
fi
