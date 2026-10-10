#!/usr/bin/env bash
# Extract the golden test corpus from the pinned Java reference into testcorpus/.
# Idempotent: wipes and rebuilds testcorpus/. Never hand-edit extracted files.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
REF="$ROOT/reference/osci-bib-java"
CORPUS="$ROOT/testcorpus"
RES="$REF/osci-bibliothek-lib/osci-bibliothek/src/test/resources/de/osci/osci12/samples"
PW="123456"

[ -d "$REF/.git" ] || { echo "reference clone missing - run scripts/fetch-reference.sh first" >&2; exit 1; }

rm -rf "$CORPUS"
mkdir -p "$CORPUS"/{messages,media,certs,xsd}

# 1. Wire-format fixtures (.osci, .mime) and expected-content XML artifacts
cp "$RES"/files/*.osci "$RES"/files/*.mime "$CORPUS/messages/"
cp "$RES"/files/AccDelNestedCocos.xml "$RES"/files/EncryptedDialogInit2.xml "$RES"/files/simpleXml.xml "$CORPUS/messages/"

# 2. Media payloads referenced by tests
cp "$RES"/files/simple.jpg "$RES"/files/simple.xml "$CORPUS/media/"

# 3. Certificates and keystores (mirror the zertifikate/ layout, keep sources)
cp "$RES"/files/TestCert.crt "$RES"/files/TestCert.p12 "$CORPUS/certs/"
cp "$RES"/zertifikate/*.p12 "$RES"/zertifikate/*.cer "$CORPUS/certs/" 2>/dev/null || true
cp -R "$RES"/zertifikate/alt "$RES"/zertifikate/BOS "$CORPUS/certs/"

# 4. PEM conversions so Rust tests never need to parse PKCS#12:
#    <name>.pem = private key(s) + cert(s), <name>-cert.pem = certs only.
#    Old keystores use RC2/SHA1 PBEs; OpenSSL 3 serves those only via the
#    legacy provider. A plain run can also die midway with a partial file,
#    so retry on nonzero exit, not just on missing output.
for p12 in $(find "$CORPUS/certs" -name '*.p12'); do
  base="${p12%.p12}"
  if ! openssl pkcs12 -in "$p12" -passin "pass:$PW" -nodes -out "$base.pem" 2>/dev/null; then
    openssl pkcs12 -provider legacy -provider default -in "$p12" -passin "pass:$PW" -nodes -out "$base.pem" 2>/dev/null \
      || echo "WARN: pkcs12->pem failed for $p12" >&2
  fi
  openssl pkcs12 -in "$p12" -passin "pass:$PW" -nokeys -out "$base-cert.pem" 2>/dev/null \
    || openssl pkcs12 -provider legacy -provider default -in "$p12" -passin "pass:$PW" -nokeys -out "$base-cert.pem" 2>/dev/null \
    || true
done
missing=$(find "$CORPUS/certs" -maxdepth 1 -name '*.pem' ! -name '*-cert.pem' -exec grep -L "BEGIN PRIVATE KEY" {} \;)
[ -z "$missing" ] || echo "WARN: keystore PEMs without private key (check manually): $missing" >&2

# .cer/.crt stay DER - Rust (x509-parser) reads DER natively, and converting
# them to <name>.pem would clobber the keystore dumps of the same basename.

# 5. XSD corpus: message schemas + catalog + external standards + codegen modules
cp -R "$REF/osci-bibliothek-lib/osci-schema/src/main/resources/schema/." "$CORPUS/xsd/"
for m in schema-message-meta-data schema-ws-addr schema-wssecurity-secext schema-xoev-basisdatentypen; do
  d="$REF/osci-bibliothek-lib/$m/src/main/resources"
  if [ -d "$d" ]; then
    mkdir -p "$CORPUS/xsd/$m"
    find "$d" -maxdepth 1 \( -name '*.xsd' -o -name '*.xjb' \) -exec cp {} "$CORPUS/xsd/$m/" \;
  fi
done

# 6. Provenance record
{
  echo "# Test corpus provenance"
  echo
  echo "- Source: https://gitlab.opencode.de/governikus/osci/osci-bib-java.git"
  echo "- Pinned: tag 2.6.1, commit $(git -C "$REF" rev-parse HEAD) ($(git -C "$REF" log -1 --format=%cd --date=short))"
  echo "- Extracted: $(date +%Y-%m-%d) by scripts/extract-testcorpus.sh"
  echo "- Keystore password: 123456"
  echo "- License: EUPL-1.2 OR MIT (inherited from source repository)"
  echo "- Do not hand-edit files here; regenerate via the script."
} > "$CORPUS/ORIGIN.md"

echo "Corpus extracted: $(find "$CORPUS" -type f | wc -l) files"
