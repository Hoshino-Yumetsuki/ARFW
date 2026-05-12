#!/usr/bin/env bash
# Generate a small APFS container image for cross-platform testing
#
# Requires macOS — uses hdiutil to format an APFS volume into a sparse image,
# then copies the raw bytes out so the result is usable on any host
# (Linux/Windows CI just consumes apfs_test.raw as a flat file)
#
# Usage: ./make_fixture.sh [size_mb]
#   size_mb defaults to 64

set -euo pipefail

SIZE_MB="${1:-64}"
DIR="$(cd "$(dirname "$0")" && pwd)"
RAW="$DIR/apfs_test.raw"
DMG="$DIR/apfs_test.dmg"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

if [[ "$(uname -s)" != "Darwin" ]]; then
    echo "make_fixture.sh requires macOS (hdiutil)." >&2
    exit 2
fi

echo "Building ${SIZE_MB} MiB APFS container at $RAW"

# Create a fresh APFS-formatted disk image. hdiutil produces a UDIF-compressed
# container; we attach it, populate it, then export raw bytes
rm -f "$DMG" "$RAW"
hdiutil create -size "${SIZE_MB}m" -fs APFS -volname ApfsTest \
    -layout NONE -type UDIF "$DMG" >/dev/null

# Attach without mounting so we can mount manually
ATTACH_OUT="$(hdiutil attach -nomount -plist "$DMG")"
# The mountable APFS volume entry has volume-kind=apfs; its parent container
# is the disk we need to detach at teardown
VOL_DEV="$(echo "$ATTACH_OUT" | python3 -c '
import plistlib, sys
plist = plistlib.loads(sys.stdin.buffer.read())
for ent in plist["system-entities"]:
    if ent.get("volume-kind") == "apfs":
        print(ent["dev-entry"])
        break
')"
if [[ -z "$VOL_DEV" ]]; then
    echo "Failed to find APFS volume in attached image" >&2
    echo "$ATTACH_OUT" >&2
    exit 1
fi
# Parent container is the device with the APFS partition GUID hint
CONTAINER_DEV="$(echo "$ATTACH_OUT" | python3 -c '
import plistlib, sys
plist = plistlib.loads(sys.stdin.buffer.read())
for ent in plist["system-entities"]:
    if ent.get("content-hint", "").upper().startswith("EF57347C"):
        print(ent["dev-entry"])
        break
')"
echo "Volume at $VOL_DEV, container at ${CONTAINER_DEV:-unknown}"

MOUNT="$WORK/mnt"
mkdir -p "$MOUNT"
diskutil mount -mountPoint "$MOUNT" "$VOL_DEV"

# Populate with a minimal but representative tree: a small file, an empty
# directory, and a multi-extent file. Tests rely on these names
echo "hello apfs" > "$MOUNT/hello.txt"
mkdir "$MOUNT/empty_dir"
mkdir "$MOUNT/sub"
dd if=/dev/urandom of="$MOUNT/sub/random.bin" bs=4096 count=16 status=none

diskutil unmount "$MOUNT"
hdiutil detach "${CONTAINER_DEV:-$VOL_DEV}" >/dev/null

# Convert UDIF -> raw (read/write, fixed-size) for cross-platform use
hdiutil convert "$DMG" -format UDRW -o "$DIR/apfs_test_rw" >/dev/null
mv "$DIR/apfs_test_rw.dmg" "$RAW"
rm -f "$DMG"

echo "Fixture ready: $RAW ($(du -h "$RAW" | awk '{print $1}'))"
