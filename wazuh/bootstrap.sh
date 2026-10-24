#!/usr/bin/env bash
# One-line install on a Wazuh server (downloads this repo, then runs wazuh/install.sh):
#   curl -sL https://raw.githubusercontent.com/Salarsefat/iot-soc-anomaly-lab/main/wazuh/bootstrap.sh | sudo bash
set -euo pipefail
REPO="${IOTSOC_REPO:-Salarsefat/iot-soc-anomaly-lab}"
BRANCH="${IOTSOC_BRANCH:-main}"
DEST=/opt/iotsoc/src
[ "$(id -u)" -eq 0 ] || { echo "run with sudo"; exit 1; }
mkdir -p /opt/iotsoc
tmp=$(mktemp -d)
echo "==> Downloading $REPO ($BRANCH)"
curl -fsSL "https://github.com/$REPO/archive/refs/heads/$BRANCH.tar.gz" -o "$tmp/src.tar.gz"
if command -v tar >/dev/null; then
  tar xzf "$tmp/src.tar.gz" -C "$tmp"
else
  python3 -c "import tarfile,sys; tarfile.open(sys.argv[1]).extractall(sys.argv[2])" "$tmp/src.tar.gz" "$tmp"
fi
rm -rf "$DEST"
mv "$tmp"/*-"$BRANCH" "$DEST"
rm -rf "$tmp"
echo "==> Source in $DEST"
exec bash "$DEST/wazuh/install.sh"
