#!/usr/bin/env bash
# Compile the Java oracle harness (oracle/) against pinned third-party jars.
#
# Supply chain: the jar files are pinned by exact version AND SHA-256.
# They are resolved from the local Maven repository (~/.m2) that the
# reference build populated, and each is checksum-verified before use -
# a stale, mismatched or tampered jar in the shared ~/.m2 cache fails the
# build instead of silently loading into the oracle JVM.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/oracle/build"

# artifact -> (exact filename, sha256) - versions match the reference
# library's pom (BouncyCastle 1.85.2) and its resolved slf4j.
BCPROV_NAME="bcprov-jdk18on-1.85.2.jar"
BCPROV_SHA="986b0fb92ec10e0c66b43e036ce0077e6150cfaecd1db9fb92b56672e157afe5"
SLF4J_NAME="slf4j-api-2.0.13.jar"
SLF4J_SHA="e7c2a48e8515ba1f49fa637d57b4e2f590b3f5bd97407ac699c3aa5efb1204a9"

find_pinned() {
  local group_path="$1" name="$2" expected="$3"
  local path="$HOME/.m2/repository/$group_path/$name"
  if [ ! -f "$path" ]; then
    echo "pinned jar missing: $path" >&2
    echo "build the reference once (mvn verify) or fetch the artifact from Maven Central" >&2
    exit 1
  fi
  local actual
  actual="$(sha256sum "$path" | awk '{print $1}')"
  if [ "$actual" != "$expected" ]; then
    echo "CHECKSUM MISMATCH for $path" >&2
    echo "  expected $expected" >&2
    echo "  actual   $actual" >&2
    echo "refusing to build the oracle against this jar" >&2
    exit 1
  fi
  printf '%s' "$path"
}

OSCI_JAR="$(find "$ROOT/reference/osci-bib-java" -name 'osci-bibliothek-*.jar' ! -name '*sources*' ! -name '*javadoc*' ! -name '*tests*' 2>/dev/null | sort | tail -1)"
if [ -z "$OSCI_JAR" ]; then
  echo "osci-bibliothek jar not found in reference/ - run 'mvn verify' there first" >&2
  exit 1
fi

BCPROV="$(find_pinned "org/bouncycastle/bcprov-jdk18on/1.85.2" "$BCPROV_NAME" "$BCPROV_SHA")"
SLF4J="$(find_pinned "org/slf4j/slf4j-api/2.0.13" "$SLF4J_NAME" "$SLF4J_SHA")"

if [ -x "$ROOT/tools/jdk11/bin/javac" ]; then
  JAVAC="$ROOT/tools/jdk11/bin/javac"
else
  JAVAC="$(command -v javac || true)"
  [ -n "$JAVAC" ] || { echo "no javac found (put a JDK 11 in tools/ or on PATH)" >&2; exit 1; }
fi

rm -rf "$OUT"
mkdir -p "$OUT"
# shellcheck disable=SC2046
"$JAVAC" --release 11 -nowarn -cp "$OSCI_JAR:$BCPROV" -d "$OUT" $(find "$ROOT/oracle/src" -name '*.java')
echo "$OSCI_JAR:$BCPROV:$SLF4J" > "$OUT/classpath.txt"
echo "oracle compiled to $OUT (jars checksum-verified)"
