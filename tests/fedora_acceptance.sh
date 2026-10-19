#!/usr/bin/env bash
# Run only in a clean, disposable Fedora VM. The Python fixture creates system
# users and units, then removes them; it never mines or contacts a pool.
set -euo pipefail

if [[ "${CI:-}" != true || "${SOLOMINER_DISPOSABLE_VM:-}" != 1 || "${EUID}" != 0 ]]; then
    echo 'Refusing: set CI=true SOLOMINER_DISPOSABLE_VM=1 and run as root in a disposable Fedora VM.' >&2
    exit 2
fi
if ! grep -Eq '^ID="?fedora"?$' /etc/os-release || [[ ! -d /run/systemd/system ]]; then
    echo 'Refusing: this check needs a running systemd manager on Fedora.' >&2
    exit 2
fi
if [[ -e /run/ostree-booted ]]; then
    echo 'Refusing: Fedora Atomic needs a separate layout and package-layering test.' >&2
    exit 2
fi
for tool in python3 gcc systemctl systemd-run journalctl getenforce; do
    command -v "$tool" >/dev/null || { echo "Missing prerequisite: $tool" >&2; exit 2; }
done
if [[ "$(getenforce)" != Enforcing ]]; then
    echo 'Refusing: SELinux must be enforcing for Fedora acceptance.' >&2
    exit 2
fi

python3 tests/systemd_integration.py
echo 'Fedora lifecycle fixture passed with SELinux enforcing.'
echo 'Inspect AVCs from this run: sudo ausearch -m AVC,USER_AVC -ts recent -i'
