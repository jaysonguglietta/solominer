#!/usr/bin/env bash

set -euo pipefail

SERVICE_NAME="${SERVICE_NAME:-btc-solo-cpu.service}"
SERVICE_USER="${SERVICE_USER:-solominer}"
INSTALL_DIR="${INSTALL_DIR:-/opt/cpuminer-opt}"
SOURCE_REPO="${SOURCE_REPO:-https://github.com/JayDDee/cpuminer-opt.git}"
BUILD_ROOT="${BUILD_ROOT:-/tmp}"
UPDATE_PACKAGES="${UPDATE_PACKAGES:-1}"
RESTART_SERVICE="${RESTART_SERVICE:-1}"

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo "Run this script with sudo:"
    echo "  sudo $0"
    exit 1
  fi
}

require_command() {
  local command_name="$1"
  if ! command -v "${command_name}" >/dev/null 2>&1; then
    echo "Missing required command: ${command_name}" >&2
    exit 1
  fi
}

check_service_user() {
  if ! id "${SERVICE_USER}" >/dev/null 2>&1; then
    echo "Service user '${SERVICE_USER}' does not exist." >&2
    echo "Create it first, or override SERVICE_USER when running this script." >&2
    exit 1
  fi
}

update_packages() {
  if [[ "${UPDATE_PACKAGES}" != "1" ]]; then
    echo "Skipping Fedora package upgrade because UPDATE_PACKAGES=${UPDATE_PACKAGES}."
    return
  fi

  echo "Updating Fedora packages..."
  dnf -y upgrade --refresh
}

build_miner() {
  local temp_dir
  temp_dir="$(mktemp -d "${BUILD_ROOT%/}/solominer-update.XXXXXX")"
  trap 'rm -rf "${temp_dir}"' EXIT

  echo "Cloning cpuminer-opt into ${temp_dir}..."
  git clone --depth 1 "${SOURCE_REPO}" "${temp_dir}/cpuminer-opt"

  cd "${temp_dir}/cpuminer-opt"

  echo "Building cpuminer-opt..."
  if ! ./build.sh; then
    echo "build.sh failed, trying manual build path..."
    ./autogen.sh
    CFLAGS="-O3 -march=native -Wall" ./configure --with-curl
    make -j"$(nproc)"
  fi

  if [[ ! -x "${temp_dir}/cpuminer-opt/cpuminer" ]]; then
    echo "Build completed but cpuminer binary was not found." >&2
    exit 1
  fi

  echo "Installing updated miner binary..."
  install -d -o "${SERVICE_USER}" -g "${SERVICE_USER}" "${INSTALL_DIR}"
  install -o "${SERVICE_USER}" -g "${SERVICE_USER}" -m 0755 \
    "${temp_dir}/cpuminer-opt/cpuminer" \
    "${INSTALL_DIR}/cpuminer"
}

restart_service() {
  if [[ "${RESTART_SERVICE}" != "1" ]]; then
    echo "Skipping service restart because RESTART_SERVICE=${RESTART_SERVICE}."
    return
  fi

  echo "Restarting ${SERVICE_NAME}..."
  systemctl restart "${SERVICE_NAME}"
}

show_status() {
  echo
  echo "Service status:"
  systemctl --no-pager --lines=20 status "${SERVICE_NAME}" || true

  echo
  echo "Recent miner logs:"
  journalctl -u "${SERVICE_NAME}" -n 20 --no-pager || true

  echo
  echo "Current temperatures:"
  sensors -f || true

  if command -v needs-restarting >/dev/null 2>&1; then
    if ! needs-restarting -r >/dev/null 2>&1; then
      echo
      echo "A reboot is recommended to finish applying package updates."
    fi
  fi
}

main() {
  require_root
  require_command dnf
  require_command git
  require_command install
  require_command systemctl
  require_command mktemp
  require_command sensors
  check_service_user

  update_packages
  build_miner
  restart_service
  show_status
}

main "$@"
