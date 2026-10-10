#!/usr/bin/env bash
# Compile the Java oracle harness (oracle/) against BouncyCastle.
# Uses the workspace JDK from tools/, falls back to system java; the bcprov
# jar is resolved from the local Maven repository left behind by the
# reference build (scripts/fetch-reference.sh + mvn verify).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/oracle/build"
BCPROV="$(find "$HOME/.m2/repository/org/bouncycastle/bcprov-jdk18on" -name 'bcprov-jdk18on-*.jar' 2>/dev/null | sort | tail -1)"

if [ -z "$BCPROV" ]; then
  echo "bcprov jar not found in ~/.m2 - build the reference once (mvn verify) or run:" >&2
  echo "  mvn -q dependency:get -Dartifact=org.bouncycastle:bcprov-jdk18on:1.85.2" >&2
  exit 1
fi

if [ -x "$ROOT/tools/jdk11/bin/javac" ]; then
  JAVAC="$ROOT/tools/jdk11/bin/javac"
else
  JAVAC="$(command -v javac || true)"
  [ -n "$JAVAC" ] || { echo "no javac found (put a JDK 11 in tools/ or on PATH)" >&2; exit 1; }
fi

rm -rf "$OUT"
mkdir -p "$OUT"
# shellcheck disable=SC2046
"$JAVAC" --release 11 -nowarn -cp "$BCPROV" -d "$OUT" $(find "$ROOT/oracle/src" -name '*.java')
echo "$BCPROV" > "$OUT/classpath.txt"
echo "oracle compiled to $OUT"
