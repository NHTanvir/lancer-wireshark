#!/usr/bin/env bash
set -euo pipefail

REPO="$(cd "$(dirname "$0")" && pwd)"
BUILD="$REPO/build"

echo "================================================"
echo "  lancer-wireshark Workspace Build"
echo "================================================"
echo ""
echo "  Repo   : $REPO"
echo "  Output : $BUILD"
echo ""

echo "[1/2] Building workspace (release)..."
cargo build --release --workspace

echo "[2/2] Copying binaries to build/..."
mkdir -p "$BUILD"
for b in \
    lancer-wireshark \
    lancer-wireshark-cli \
    editcap \
    mergecap \
    capinfos \
    text2pcap \
    randpkt \
    rawshark \
    sharkd \
    dumpcap ; do
    if [ -f "$REPO/target/release/$b" ]; then
        cp "$REPO/target/release/$b" "$BUILD/"
        echo "  + $b"
    fi
done

echo ""
echo "================================================"
echo "  Done! Binaries in $BUILD/"
echo "================================================"

if [ "${1:-}" = "--install" ]; then
    DESTDIR="${DESTDIR:-$HOME/.local}"
    mkdir -p "$DESTDIR/bin"
    cp "$BUILD"/* "$DESTDIR/bin/"
    cat <<EOF >"$DESTDIR/share/applications/lancer-wireshark.desktop"
[Desktop Entry]
Name=lancer-wireshark
Comment=Rust clone of wireshark — capture & dissection
Exec=$DESTDIR/bin/lancer-wireshark
Type=Application
Categories=Network;Monitor;
EOF
    echo "Installed to $DESTDIR/bin (.desktop in $DESTDIR/share/applications)"
fi
