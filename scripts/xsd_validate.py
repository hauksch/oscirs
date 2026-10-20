#!/usr/bin/env python3
"""XSD validation gate (see scripts/xsd-validate.sh).

Copies testcorpus/xsd into a temp sandbox, rewrites the remote
xsd:import/xsd:redefine schemaLocations to the vendored extern/ copies,
and validates the given document with lxml (libxml2 semantics: the
OSCI schemas use xsd:redefine).

usage: xsd_validate.py <document.xml> <schema.xsd>
"""

import os
import re
import shutil
import sys
import tempfile

from lxml import etree

XSD_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "testcorpus", "xsd")

# remote schemaLocation -> vendored file (relative to the xsd root)
REMOTE_MAP = {
    "http://www.w3.org/2001/xml.xsd": "extern/xml.xsd",
    "http://schemas.xmlsoap.org/soap/envelope/": "extern/soap-envelope.xsd",
    "https://www.w3.org/2008/xmlsec/Drafts/xmlenc-core-11/xenc-schema-11.xsd": "extern/xenc-schema-11.xsd",
    "http://www.w3.org/TR/2001/CR-xmldsig-core-20010419/xmldsig-core-schema.xsd": "extern/xmldsig-core-schema.xsd",
    "http://www.w3.org/TR/2002/REC-xmldsig-core-20020212/xmldsig-core-schema.xsd": "extern/xmldsig-core-schema.xsd",
    "http://www.w3.org/TR/xmlenc-core/xenc-schema.xsd": "extern/xenc-schema.xsd",
    "http://www.w3.org/TR/2002/REC-xmlenc-core-20021210/xenc-schema.xsd": "extern/xenc-schema.xsd",
}


def build_sandbox() -> str:
    sandbox = tempfile.mkdtemp(prefix="osci-xsd-")
    xsd_dir = os.path.join(sandbox, "xsd")
    shutil.copytree(os.path.abspath(XSD_ROOT), xsd_dir)
    extern = os.path.join(xsd_dir, "extern")
    for dirpath, _, files in os.walk(xsd_dir):
        for name in files:
            if not name.endswith(".xsd"):
                continue
            path = os.path.join(dirpath, name)
            with open(path, encoding="utf-8") as f:
                text = f.read()
            rewritten = text
            for remote, local in REMOTE_MAP.items():
                # absolute path: correct regardless of the importing
                # file's directory (root schemas and extern/ both). The
                # attribute name is part of the pattern so namespace=
                # attributes carrying the same URL are left alone.
                target = os.path.join(xsd_dir, local)
                rewritten = rewritten.replace(
                    f'schemaLocation="{remote}"', f'schemaLocation="{target}"'
                )
                rewritten = rewritten.replace(
                    f"schemaLocation='{remote}'", f"schemaLocation='{target}'"
                )
            # vendored typo (order.xsd, ProcessCardType): trailing space
            # inside the QName fails schema compilation on recent libxml2
            rewritten = rewritten.replace('type="xsd:dateTime "', 'type="xsd:dateTime"')
            # Several Header content models end with an OPTIONAL osci
            # element directly followed by <xsd:any namespace="##other">.
            # That pair violates the XSD Unique Particle Attribution rule
            # (an osci extension header matches both particles); Xerces
            # and older libxml2 tolerate it, current libxml2 refuses to
            # compile the schema. The sandbox drops the wildcard from the
            # Header models - the gate therefore does not cover vendor
            # extension headers; the normative files stay untouched.
            def _drop_wildcard(m: "re.Match[str]") -> str:
                return re.sub(r"<xsd:any [^>]*/>", "", m.group(0))

            rewritten = re.sub(
                r'<xsd:complexType name="Header">.*?</xsd:complexType>',
                _drop_wildcard,
                rewritten,
                flags=re.S,
            )
            if rewritten != text:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(rewritten)
    return xsd_dir


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print("usage: xsd_validate.py <document.xml> <schema.xsd>", file=sys.stderr)
        return 2
    doc_arg, schema_name = argv[1], argv[2]
    xsd_dir = build_sandbox()
    failures = 0
    schema = None
    try:
        schema = etree.XMLSchema(etree.parse(os.path.join(xsd_dir, schema_name)))
        parsed = etree.parse(doc_arg)
        schema.assertValid(parsed)
        print(f"OK   {doc_arg} ({schema_name})")
    except (etree.XMLSchemaParseError, etree.DocumentInvalid, etree.XMLSyntaxError, OSError) as e:
        failures += 1
        print(f"FAIL {doc_arg} ({schema_name}): {e}", file=sys.stderr)
        if schema is not None:
            for err in schema.error_log:
                print(f"     {err}", file=sys.stderr)
    shutil.rmtree(xsd_dir, ignore_errors=True)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
