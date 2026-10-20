#!/usr/bin/env bash
# Validate a document against the normative OSCI schemas (issue #3: "the
# schemas are the contract").
#
#   scripts/xsd-validate.sh <document.xml> <schema.xsd> [more docs...]
#
# The vendored schemas reference remote W3C/Soap URLs from xsd:import and
# xsd:redefine. Rather than patching the normative files, the script
# copies testcorpus/xsd into a temp sandbox and rewrites those locations
# to the local extern/ copies before running the validator (lxml/libxml2,
# which handles the xsd:redefine constructs the schemas use).
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"

python_bin=""
if [ -n "${XSD_PYTHON:-}" ]; then
    python_bin="$XSD_PYTHON"
elif python3 -c "import lxml" >/dev/null 2>&1; then
    python_bin="python3"
elif [ -x "$root/.venv-xsd/bin/python" ]; then
    python_bin="$root/.venv-xsd/bin/python"
else
    echo "xsd-validate: need python3+lxml (pip install lxml) or XSD_PYTHON" >&2
    exit 2
fi

exec "$python_bin" "$root/scripts/xsd_validate.py" "$@"
