//! Order-preserving serializer for parsed XML trees: writes elements with
//! their original qnames, attribute order and self-closing style, so that
//! `serialize(parse(source)) == source` for ordinary (entity-free)
//! documents - the byte-exact roundtrip used by the header gates.

use std::io::{self, Write};

use super::writer::{escape_attr, escape_text};
use super::{Element, Node};

/// Serialize one element (including its subtree).
pub fn serialize_element(element: &Element, out: &mut impl Write) -> io::Result<()> {
    let qname = element.qname();
    out.write_all(b"<")?;
    out.write_all(qname.as_bytes())?;
    for (k, v) in &element.attrs {
        out.write_all(b" ")?;
        out.write_all(k.as_bytes())?;
        out.write_all(b"=\"")?;
        escape_attr(v, out)?;
        out.write_all(b"\"")?;
    }
    if element.self_closing && element.children.is_empty() {
        return out.write_all(b"/>");
    }
    out.write_all(b">")?;
    for child in &element.children {
        match child {
            Node::Element(e) => serialize_element(e, out)?,
            Node::Text(t) => escape_text(t, out)?,
        }
    }
    out.write_all(b"</")?;
    out.write_all(qname.as_bytes())?;
    out.write_all(b">")
}

/// Serialize to a String (canonical helper for tests).
pub fn serialize_to_string(element: &Element) -> String {
    let mut buf = Vec::new();
    serialize_element(element, &mut buf).expect("vec write");
    String::from_utf8(buf).expect("xml is utf-8")
}

/// Serialize a whole document including the raw prolog and epilog
/// (byte-exact roundtrip companion to the parser).
pub fn serialize_document(doc: &super::Document, out: &mut impl Write) -> io::Result<()> {
    out.write_all(doc.prolog.as_bytes())?;
    serialize_element(&doc.root, out)?;
    out.write_all(doc.epilog.as_bytes())
}

pub fn document_to_string(doc: &super::Document) -> String {
    let mut buf = Vec::new();
    serialize_document(doc, &mut buf).expect("vec write");
    String::from_utf8(buf).expect("xml is utf-8")
}
