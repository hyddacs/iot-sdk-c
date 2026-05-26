#!/usr/bin/env bash
set -euo pipefail

src="${1:-main.c}"

if ! grep -q '\\"device_code\\":%d' "$src"; then
    echo 'main upload JSON must set device_code from int ssss without quotes' >&2
    exit 1
fi

if grep -q '\\"device_code\\":\\"' "$src"; then
    echo 'main upload JSON must not encode device_code as a string' >&2
    exit 1
fi

if ! grep -q '\\"RoomTemp\\":%d' "$src"; then
    echo 'main upload JSON must set RoomTemp from int sss without quotes' >&2
    exit 1
fi

if grep -q '\\"RoomTemp\\":\\"' "$src"; then
    echo 'main upload JSON must not encode RoomTemp as a string' >&2
    exit 1
fi
