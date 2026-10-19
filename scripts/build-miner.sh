#!/usr/bin/env bash
# Only executed as the isolated builder; source is the working directory.
set -euo pipefail
if ! pkg-config --exists jansson; then
  echo 'Fedora jansson-devel is required; refusing the bundled Jansson fallback.' >&2
  exit 1
fi
./autogen.sh
./configure --with-curl
if ! grep -q '^ac_cv_lib_jansson_json_loads=yes$' config.log; then
  echo 'Configure did not select the system Jansson library; refusing the bundled fallback.' >&2
  exit 1
fi
make -j2
