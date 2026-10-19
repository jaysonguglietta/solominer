#!/usr/bin/bash -p
# Install as root:root, mode 0700, at /etc/solominer/update.sh.
# The checkout is deliberately fixed so a caller cannot select executable code
# from an arbitrary directory when invoking this script with sudo.
set -euo pipefail
umask 077
# Clear inherited process settings before any external command. This prevents
# sudo environment retention from changing Git transport or DNF plugin loading.
IFS=$' \t\n'
while IFS= read -r inherited; do
    case $inherited in
        BASHOPTS|SHELLOPTS|UID|EUID|PPID) continue ;;
    esac
    unset "$inherited" 2>/dev/null || exit 1
done < <(compgen -e)
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
export HOME=/root
export LANG=C.UTF-8

readonly CHECKOUT=/root/solominer
readonly SCRIPT_PATH=/etc/solominer/update.sh
readonly REMOTE=https://github.com/jaysonguglietta/solominer.git

usage() {
    cat <<'EOF'
Usage: sudo /etc/solominer/update.sh [MODE]

  --check             Fetch main and list incoming SoloMiner commits and Fedora updates (default)
  --packages          Interactively upgrade all installed Fedora RPMs
  --miner SHA          Apply reviewed, full 40-character SHA from origin/main; stage and activate
  --all SHA            Upgrade Fedora RPMs first, then apply the reviewed SoloMiner SHA
  --help               Show this help

Run --check. For code updates, review the incoming diff or current checkout,
then use the full lowercase 40-character SHA after "SoloMiner proposed:" with
--miner or --all. --packages takes no SHA.
This script does not schedule updates, upgrade Fedora releases, or reboot.
EOF
}

die() {
    printf 'SoloMiner manual update: %s\n' "$*" >&2
    exit 1
}

mode=--check
expected_sha=
case "${1:---check}" in
    --help|-h)
        (($# == 1)) || { usage >&2; exit 2; }
        usage
        exit 0
        ;;
    --check|--packages)
        (($# <= 1)) || { usage >&2; exit 2; }
        mode="${1:---check}"
        ;;
    --miner|--all)
        (($# == 2)) || { usage >&2; exit 2; }
        mode=$1
        expected_sha=$2
        [[ $expected_sha =~ ^[0-9a-f]{40}$ ]] || {
            printf 'A full lowercase 40-character commit SHA is required.\n' >&2
            exit 2
        }
        ;;
    *)
        usage >&2
        exit 2
        ;;
esac

secure_component() {
    local path=$1 type=$2 owner group perms
    [[ ! -L $path ]] || die "Symlink in trusted path: $path"
    if [[ $type == directory ]]; then
        [[ -d $path ]] || die "Missing trusted directory: $path"
    else
        [[ -f $path ]] || die "Missing trusted file: $path"
    fi
    owner=$(/usr/bin/stat -c %u -- "$path") || die "Cannot inspect $path"
    group=$(/usr/bin/stat -c %g -- "$path") || die "Cannot inspect $path"
    perms=$(/usr/bin/stat -c %a -- "$path") || die "Cannot inspect $path"
    [[ $owner == 0 && $group == 0 ]] || die "Expected root:root ownership: $path"
    (( (8#$perms & 8#022) == 0 )) || die "Group/other writable path: $path"
}

require_host_and_script() {
    (( EUID == 0 )) || die 'Run with sudo or from a root shell.'
    [[ -f /etc/fedora-release && ! -e /run/ostree-booted ]] ||
        die 'Requires traditional Fedora; rpm-ostree/Atomic hosts are unsupported.'
    [[ -d /run/systemd/system ]] || die 'A running systemd system manager is required.'
    local actual
    actual=$(/usr/bin/realpath -e -- "${BASH_SOURCE[0]}") || die 'Cannot resolve updater path.'
    [[ $actual == "$SCRIPT_PATH" ]] || die "Install the reviewed script at $SCRIPT_PATH first."
    secure_component / directory
    secure_component /etc directory
    secure_component /etc/solominer directory
    secure_component "$SCRIPT_PATH" file
    [[ $(/usr/bin/stat -c %a -- "$SCRIPT_PATH") == 700 ]] ||
        die "$SCRIPT_PATH must have mode 0700."
    [[ -x /usr/bin/git && -x /usr/bin/dnf && -x /usr/bin/python3 && -x /usr/bin/flock ]] ||
        die 'Required Git, DNF, Python, or flock executable is missing.'
}

git_safe() {
    /usr/bin/env -i PATH="$PATH" HOME=/root LANG=C.UTF-8 \
        GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null GIT_TERMINAL_PROMPT=0 \
        /usr/bin/git --no-pager -C "$CHECKOUT" -c core.hooksPath=/dev/null \
        -c core.fsmonitor=false -c credential.helper= -c core.pager=cat \
        -c protocol.file.allow=never -c protocol.ext.allow=never "$@"
}

dnf_safe() {
    /usr/bin/env -i PATH="$PATH" HOME=/root LANG=C.UTF-8 USER=root LOGNAME=root TERM=dumb \
        /usr/bin/dnf "$@"
}

python_safe() {
    /usr/bin/env -i PATH="$PATH" HOME=/root LANG=C.UTF-8 USER=root LOGNAME=root \
        /usr/bin/python3 -I -B "$@"
}

installed_cli_safe() {
    /usr/bin/env -i PATH="$PATH" HOME=/root LANG=C.UTF-8 USER=root LOGNAME=root \
        /usr/local/bin/solominer "$@"
}

check_checkout() {
    local bad top git_dir remote branch dirty
    secure_component /root directory
    secure_component "$CHECKOUT" directory
    secure_component "$CHECKOUT/.git" directory
    bad=$(/usr/bin/find "$CHECKOUT" -xdev \
        \( -type l -o ! -user root -o ! -group root -o -perm /022 \) -print -quit) ||
        die 'Cannot inspect checkout ownership and permissions.'
    [[ -z $bad ]] || die "Unsafe checkout entry (symlink, owner, or mode): $bad"
    top=$(git_safe rev-parse --show-toplevel) || die 'Not a Git checkout.'
    git_dir=$(git_safe rev-parse --absolute-git-dir) || die 'Missing Git directory.'
    [[ $top == "$CHECKOUT" && $git_dir == "$CHECKOUT/.git" ]] ||
        die 'Unexpected worktree or Git directory.'
    remote=$(git_safe remote get-url origin) || die 'Missing origin remote.'
    [[ $remote == "$REMOTE" ]] || die "Unexpected origin remote: $remote"
    branch=$(git_safe symbolic-ref -q --short HEAD) || die 'Detached HEAD is unsupported.'
    [[ $branch == main ]] || die "Expected main branch; found $branch."
    dirty=$(git_safe status --porcelain=v1 --untracked-files=all) || die 'Cannot inspect Git status.'
    [[ -z $dirty ]] || die 'Checkout has local changes or untracked files; review them first.'
}

fetch_main() {
    local proposed tree
    # Explicit URL prevents a later remote-config change from redirecting fetch.
    git_safe fetch --no-tags --no-recurse-submodules "$REMOTE" \
        refs/heads/main:refs/remotes/origin/main ||
        die 'Could not fetch the approved GitHub main branch.'
    proposed=$(git_safe rev-parse --verify 'FETCH_HEAD^{commit}') || die 'No fetched commit.'
    git_safe merge-base --is-ancestor HEAD "$proposed" ||
        die 'Local main has diverged from fetched main; resolve this manually.'
    tree=$(git_safe ls-tree -r "$proposed") || die 'Cannot inspect fetched tree.'
    if /usr/bin/grep -Eq '^(120000|160000) ' <<< "$tree"; then
        die 'Fetched tree contains symlinks or submodules; review manually.'
    fi
    printf '%s\n' "$proposed"
}

show_incoming() {
    local proposed=$1 current
    current=$(git_safe rev-parse HEAD)
    printf '\nSoloMiner current: %s\nSoloMiner proposed: %s\n' "$current" "$proposed"
    if [[ $current == "$proposed" ]]; then
        printf 'SoloMiner main is already current.\n'
    else
        printf '\nIncoming commit SHAs:\n'
        git_safe log --format=%H "HEAD..$proposed"
        printf '\nChanged files:\n'
        git_safe diff --stat --no-ext-diff --no-textconv "HEAD..$proposed"
        printf '\nReview every change before running code as root:\n'
        printf '  git -C %s diff --no-ext-diff --no-textconv HEAD %s\n' "$CHECKOUT" "$proposed"
    fi
}

check_packages() {
    local result
    printf '\nFedora package updates (entire host):\n'
    if dnf_safe check-upgrade --refresh; then
        printf 'No Fedora package updates reported.\n'
    else
        result=$?
        [[ $result == 100 ]] || die "DNF update check failed (exit $result)."
        printf 'Fedora package updates are available.\n'
    fi
}

update_packages() {
    local confirmation
    [[ -t 0 ]] || die 'Fedora package upgrades require an interactive terminal.'
    printf 'DNF can upgrade Fedora RPMs across this entire host, including services and the kernel.\n'
    read -r -p 'Type UPGRADE to continue: ' confirmation || die 'No confirmation received.'
    [[ $confirmation == UPGRADE ]] || die 'Package upgrade canceled.'
    dnf_safe upgrade --refresh || die 'DNF upgrade failed; SoloMiner code was not activated.'
    printf 'DNF finished. Review its output; reboot manually if your system requires it.\n'
}

apply_miner() {
    local proposed=$1 current
    check_checkout
    current=$(fetch_main)
    [[ $current == "$proposed" ]] ||
        die "Fetched main moved to $current; rerun --check and review the new diff."
    show_incoming "$proposed"
    git_safe merge --ff-only "$proposed" || die 'Could not fast-forward local main.'
    check_checkout
    printf '\nBuilding and staging the approved SoloMiner release. The running miner stays active.\n'
    python_safe "$CHECKOUT/scripts/solominer" update --no-restart ||
        die 'Staging failed; the active SoloMiner release was not changed.'
    printf '\nActivating the staged release with startup verification and rollback.\n'
    python_safe "$CHECKOUT/scripts/solominer" update --activate-staged ||
        die 'Activation failed; inspect the service and rollback report.'
    printf '\nPost-update diagnostics:\n'
    if ! installed_cli_safe doctor; then
        printf 'Doctor reported an issue; inspect it before relying on the miner.\n' >&2
    fi
    if ! installed_cli_safe status; then
        die 'Status reported an issue after activation; inspect the service.'
    fi
}

require_host_and_script
[[ ! -L /etc/solominer/update.lock ]] || die 'Refusing symlink update lock.'
exec 9> /etc/solominer/update.lock
/usr/bin/flock -n 9 || die 'Another manual update is running.'

case $mode in
    --check)
        check_checkout
        proposed=$(fetch_main)
        show_incoming "$proposed"
        check_packages
        ;;
    --packages)
        update_packages
        ;;
    --miner)
        apply_miner "$expected_sha"
        ;;
    --all)
        check_checkout
        proposed=$(fetch_main)
        [[ $proposed == "$expected_sha" ]] ||
            die "Fetched main moved to $proposed; rerun --check and review the new diff."
        update_packages
        apply_miner "$expected_sha"
        ;;
esac
