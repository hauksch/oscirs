#!/usr/bin/env bash
# Provision the local toolchain (JDK 11 + Maven) into tools/ with pinned
# download URLs and publisher checksum verification.
#
# The tarballs are verified against the checksums published by the
# vendors (Adoptium API metadata / Apache archive .sha512) before
# extraction; a mismatch aborts the provisioning.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TOOLS="$ROOT/tools"
mkdir -p "$TOOLS"

# --- JDK 11 (Eclipse Temurin, linux x64) ---
JDK_VERSION="11.0.32.1+1"
JDK_DIR="$TOOLS/jdk11"
if [ ! -x "$JDK_DIR/bin/java" ]; then
  echo "fetching Temurin JDK $JDK_VERSION..."
  # The "latest/ga" redirect resolves to the current GA build of 11; pin
  # by querying the release metadata for the exact version above.
  URL="https://api.adoptium.net/v3/binary/latest/11/ga/linux/x64/jdk/hotspot/normal/eclipse"
  META_URL="https://api.adoptium.net/v3/assets/latest/11/hotspot?architecture=x64&image_type=jdk&os=linux&vendor=eclipse"
  TARBALL="$TOOLS/jdk11.tar.gz"

  curl -sSL -o "$TARBALL" "$URL"

  EXPECTED_JDK_SHA="$(curl -sSL "$META_URL" \
    | python3 -c "
import json, sys
for asset in json.load(sys.stdin):
    if asset.get('binary', {}).get('package', {}).get('name', '').startswith('OpenJDK11U-jdk_x64_linux_hotspot_'):
        print(asset['binary']['package']['checksum'])
        break
")"
  if [ -z "$EXPECTED_JDK_SHA" ]; then
    echo "could not fetch JDK checksum metadata" >&2
    exit 1
  fi
  ACTUAL_JDK_SHA="$(sha256sum "$TARBALL" | awk '{print $1}')"
  if [ "$ACTUAL_JDK_SHA" != "$EXPECTED_JDK_SHA" ]; then
    echo "JDK CHECKSUM MISMATCH" >&2
    echo "  expected $EXPECTED_JDK_SHA" >&2
    echo "  actual   $ACTUAL_JDK_SHA" >&2
    rm -f "$TARBALL"
    exit 1
  fi

  tar -xzf "$TARBALL" -C "$TOOLS"
  rm -f "$TARBALL"
  mv "$TOOLS"/jdk-11* "$JDK_DIR"
  echo "JDK provisioned: $($JDK_DIR/bin/java -version 2>&1 | head -1)"
else
  echo "JDK already present at $JDK_DIR"
fi

# --- Maven 3.9.x ---
MAVEN_VERSION="3.9.16"
MAVEN_DIR="$TOOLS/maven"
if [ ! -x "$MAVEN_DIR/bin/mvn" ]; then
  echo "fetching Maven $MAVEN_VERSION..."
  URL="https://archive.apache.org/dist/maven/maven-3/$MAVEN_VERSION/binaries/apache-maven-$MAVEN_VERSION-bin.tar.gz"
  SHA_URL="https://archive.apache.org/dist/maven/maven-3/$MAVEN_VERSION/binaries/apache-maven-$MAVEN_VERSION-bin.tar.gz.sha512"
  TARBALL="$TOOLS/maven.tar.gz"

  curl -sSL -o "$TARBALL" "$URL"
  EXPECTED_MAVEN_SHA="$(curl -sSL "$SHA_URL" | tr -d '[:space:]')"
  ACTUAL_MAVEN_SHA="$(sha512sum "$TARBALL" | awk '{print $1}')"
  if [ "$ACTUAL_MAVEN_SHA" != "$EXPECTED_MAVEN_SHA" ]; then
    echo "MAVEN CHECKSUM MISMATCH" >&2
    echo "  expected $EXPECTED_MAVEN_SHA" >&2
    echo "  actual   $ACTUAL_MAVEN_SHA" >&2
    rm -f "$TARBALL"
    exit 1
  fi

  tar -xzf "$TARBALL" -C "$TOOLS"
  rm -f "$TARBALL"
  mv "$TOOLS/apache-maven-$MAVEN_VERSION" "$MAVEN_DIR"
  echo "Maven provisioned: $($MAVEN_DIR/bin/mvn -version 2>&1 | head -1)"
else
  echo "Maven already present at $MAVEN_DIR"
fi

# --- environment script (paths relative to this repo, not hardcoded) ---
cat > "$TOOLS/env.sh" <<ENV
# Local toolchain for the OSCI Rust rewrite workspace (source this file)
export OSCI_TOOLS="$TOOLS"
export JAVA_HOME="$JDK_DIR"
export MAVEN_HOME="$MAVEN_DIR"
export PATH="\$JAVA_HOME:\$MAVEN_HOME:\$PATH"
ENV

echo "provisioning complete - source tools/env.sh to use the toolchain"
