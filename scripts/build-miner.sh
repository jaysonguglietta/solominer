#!/usr/bin/env bash
# Only executed as the isolated builder; source is the working directory.
set -euo pipefail
./autogen.sh
./configure --with-curl
make -j2
