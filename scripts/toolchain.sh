#!/bin/sh
# SPDX-License-Identifier: BSD-3-Clause
set -eu

usage() {
    printf 'usage: scripts/toolchain.sh [--check|--install]\n' >&2
    exit 2
}

check_toolchain() {
    missing=0
    for command in cc make python3 node qemu-system-i386 nasm sha256sum timeout; do
        if path=$(command -v "$command" 2>/dev/null); then
            printf '[PASS] %-18s %s\n' "$command" "$path"
        else
            printf '[MISS] %-18s required by the full verification suite\n' "$command" >&2
            missing=1
        fi
    done

    if [ -r /usr/include/linux/kvm.h ]; then
        printf '[PASS] %-18s %s\n' 'linux/kvm.h' '/usr/include/linux/kvm.h'
    else
        printf '[MISS] %-18s required to build bemu-nano\n' 'linux/kvm.h' >&2
        missing=1
    fi

    if [ -c /dev/kvm ] && [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
        printf '[PASS] %-18s KVM gates are available\n' '/dev/kvm'
    elif [ -c /dev/kvm ]; then
        printf '[WARN] %-18s exists but is not readable and writable; check kvm group membership\n' '/dev/kvm' >&2
    else
        printf '[WARN] %-18s unavailable; build, QEMU and browser gates still work\n' '/dev/kvm' >&2
    fi

    if [ "$missing" -ne 0 ]; then
        printf 'RESULT: FAIL - install the missing toolchain components\n' >&2
        return 1
    fi
    printf 'RESULT: PASS - build and hosted-CI toolchain ready\n'
}

install_apt() {
    if [ "$(id -u)" -eq 0 ]; then
        apt-get update
        apt-get install -y build-essential nasm nodejs python3 qemu-system-x86
    else
        command -v sudo >/dev/null 2>&1 || {
            printf 'FAIL: sudo is required for package installation\n' >&2
            exit 1
        }
        sudo apt-get update
        sudo apt-get install -y build-essential nasm nodejs python3 qemu-system-x86
    fi
}

mode=${1:---check}
[ "$#" -le 1 ] || usage
case "$mode" in
    --check)
        check_toolchain
        ;;
    --install)
        if command -v apt-get >/dev/null 2>&1; then
            install_apt
        else
            printf 'FAIL: automatic installation currently supports Debian/Ubuntu (apt-get) only\n' >&2
            printf 'Run scripts/toolchain.sh --check for the exact missing commands.\n' >&2
            exit 1
        fi
        check_toolchain
        ;;
    *)
        usage
        ;;
esac
