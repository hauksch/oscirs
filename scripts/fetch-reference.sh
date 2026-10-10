#!/usr/bin/env bash
# Fetch the pinned Java reference implementation into reference/osci-bib-java.
# Update REF_TAG/REF_COMMIT together when moving to a newer upstream version.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
REF_TAG="2.6.1"
REF_COMMIT="f2e4a6acf9e6cc653cb35c6184bd794abec929d4"
DEST="$ROOT/reference/osci-bib-java"

if [ -d "$DEST/.git" ]; then
  echo "reference already present at $DEST"
else
  git clone https://gitlab.opencode.de/governikus/osci/osci-bib-java.git "$DEST"
fi

git -C "$DEST" fetch --tags --force --quiet
git -C "$DEST" checkout --force --quiet "$REF_COMMIT"
echo "Pinned to tag $REF_TAG (commit $REF_COMMIT)"
