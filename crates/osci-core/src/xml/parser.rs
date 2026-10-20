//! Strict, XXE-safe XML tree parser with Xerces-compatible normalization.
//!
//! Mirrors the parser configuration of `de.osci.helper.ParserHelper`:
//! - DOCTYPE declarations are rejected outright (`disallow-doctype-decl`),
//!   which also neutralizes XXE (external entities cannot be declared),
//! - undeclared entity references are rejected,
//! - well-formedness is enforced (matching tags, single root, duplicate
//!   attributes, nothing but PIs after the root),
//! - line endings are normalized before entity resolution (XML 2.11:
//!   CRLF and CR become LF in text, CDATA, PIs and attribute values),
//! - attribute values additionally replace literal tab/LF/CR with spaces
//!   (XML 3.3.3 CDATA normalization); character references such as `&#xD;`
//!   survive both normalizations.

use std::collections::HashSet;

use quick_xml::Reader;
use quick_xml::events::Event;

use super::{Document, Element, Node};

/// Maximum accepted element nesting depth (OSCI messages are shallow;
/// hostile deep nesting would overflow the stack in recursive walks).
const MAX_ELEMENT_DEPTH: usize = 256;

#[derive(Debug, thiserror::Error)]
pub enum XmlError {
    #[error("malformed XML: {0}")]
    Malformed(String),
    #[error("DOCTYPE declarations are not accepted")]
    Doctype,
    #[error("entity references are not accepted: {0}")]
    EntityRef(String),
    #[error("duplicate attribute {0}")]
    DuplicateAttribute(String),
    #[error("unbound namespace prefix: {0}")]
    UnboundPrefix(String),
}

/// Largest offset <= i that is a char boundary. quick-xml reports byte
/// positions; the prolog/epilog slices must stay total on arbitrary
/// (hostile) input.
fn floor_boundary(input: &str, mut i: usize) -> usize {
    i = i.min(input.len());
    while !input.is_char_boundary(i) {
        i -= 1;
    }
    i
}

/// Parse an XML document (already UTF-8) into a tree.
pub fn parse(input: &str) -> Result<Document, XmlError> {
    // a leading BOM is legal XML (encoding information, not content);
    // quick-xml's event offsets skip it, which would desynchronize the
    // prolog/epilog byte slices below
    let input = input.strip_prefix('\u{feff}').unwrap_or(input);
    let mut reader = Reader::from_str(input);
    reader.config_mut().check_comments = true;

    let mut doc = Document::default();
    let mut stack: Vec<Element> = Vec::new();
    let mut root_taken = false;
    let mut pending_text = String::new();
    // byte offset after the last processed event, for prolog/epilog capture
    let mut prev_end = 0usize;
    let mut epilog_start: Option<usize> = None;
    // Bound namespace prefixes, for the Xerces-style "unbound prefix" check.
    let mut ns_stack: Vec<HashSet<String>> = vec![HashSet::new()];

    loop {
        let event = reader.read_event();
        if event.is_ok() && stack.is_empty() && root_taken && epilog_start.is_none() {
            // the root element just closed: everything from here on is epilog
        }
        match event {
            Ok(Event::Start(e)) => {
                if stack.is_empty() && !root_taken {
                    doc.prolog = input[..floor_boundary(input, prev_end)].to_string();
                }
                // Depth cap: deeply nested documents overflow the stack in
                // the recursive tree drop and canonicalization walks
                // (uncatchable DoS).
                if stack.len() >= MAX_ELEMENT_DEPTH {
                    return Err(XmlError::Malformed(format!(
                        "element nesting exceeds {MAX_ELEMENT_DEPTH}"
                    )));
                }
                flush_text(&mut stack, &mut pending_text);
                let element = start_element(&e, &ns_stack)?;
                push_bindings(&mut ns_stack, &element);
                stack.push(element);
            }
            Ok(Event::End(e)) => {
                flush_text(&mut stack, &mut pending_text);
                let name = e.name().as_ref().to_string();
                let Some(finished) = stack.pop() else {
                    return Err(XmlError::Malformed(format!("unexpected </{name}>")));
                };
                let qname = finished.qname();
                if qname != name {
                    return Err(XmlError::Malformed(format!(
                        "mismatched tags: <{qname}> closed by </{name}>"
                    )));
                }
                ns_stack.pop();
                match stack.last_mut() {
                    Some(p) => p.children.push(Node::Element(finished)),
                    None => {
                        if root_taken {
                            return Err(XmlError::Malformed("multiple root elements".into()));
                        }
                        doc.root = finished;
                        root_taken = true;
                        epilog_start = Some(reader.buffer_position() as usize);
                    }
                }
            }
            Ok(Event::Empty(e)) => {
                flush_text(&mut stack, &mut pending_text);
                let mut element = start_element(&e, &ns_stack)?;
                element.self_closing = true;
                match stack.last_mut() {
                    Some(p) => {
                        p.children.push(Node::Element(element));
                        // bindings of an empty element are never visible to
                        // siblings; nothing pushed for it
                    }
                    None => {
                        if root_taken {
                            return Err(XmlError::Malformed("multiple root elements".into()));
                        }
                        doc.root = element;
                        root_taken = true;
                    }
                }
            }
            Ok(Event::Text(t)) => {
                // Raw (still escaped) content; line endings normalize
                // before entity resolution.
                let raw = t.as_ref();
                let normalized = normalize_line_endings(raw);
                let text = unescape(&normalized)?;
                pending_text.push_str(&text);
            }
            Ok(Event::CData(t)) => {
                // CDATA content is raw: normalize line endings only.
                pending_text.push_str(&normalize_line_endings(t.as_ref()));
            }
            Ok(Event::Comment(_)) => { /* dropped, like useComment=false */ }
            Ok(Event::Decl(_)) => { /* the xml declaration is not a PI */ }
            Ok(Event::PI(pi)) => {
                let (target, data) = split_pi(pi.as_ref())?;
                if stack.is_empty() && !root_taken {
                    doc.pis_before_root.push((target, data));
                } else if root_taken && stack.is_empty() {
                    doc.pis_after_root.push((target, data));
                }
                // PIs inside the document are legal XML; CanParser drops
                // them from the canonical form, so we keep parsing.
            }
            Ok(Event::DocType(_)) => return Err(XmlError::Doctype),
            Ok(Event::GeneralRef(reference)) => {
                // quick-xml delivers each `&ref;` / `&#n;` in text as its
                // own event; resolve the predefined and character
                // references, reject anything else (no DTDs are accepted).
                pending_text.push_str(&resolve_reference(reference.as_ref())?);
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(XmlError::Malformed(e.to_string())),
        }
        prev_end = reader.buffer_position() as usize;
    }

    if let Some(start) = epilog_start {
        let start = floor_boundary(input, start);
        doc.epilog = input[start..].to_string();
    }

    if let Some(open) = stack.first() {
        return Err(XmlError::Malformed(format!(
            "unclosed element <{}>",
            open.qname()
        )));
    }
    if !root_taken {
        return Err(XmlError::Malformed("no root element".into()));
    }
    Ok(doc)
}

fn flush_text(stack: &mut [Element], pending: &mut String) {
    if pending.is_empty() {
        return;
    }
    if let Some(top) = stack.last_mut() {
        top.children.push(Node::Text(std::mem::take(pending)));
    } else {
        pending.clear();
    }
}

fn start_element(
    e: &quick_xml::events::BytesStart<'_>,
    ns_stack: &[HashSet<String>],
) -> Result<Element, XmlError> {
    let qname = e.name().as_ref().to_string();
    let (prefix, local) = match qname.split_once(':') {
        Some((p, l)) => (p.to_string(), l.to_string()),
        None => (String::new(), qname.clone()),
    };

    let mut attrs = Vec::new();
    let mut seen = HashSet::new();
    for attr in e.attributes().with_checks(true) {
        let attr = attr.map_err(|err| XmlError::Malformed(err.to_string()))?;
        let key = attr.key.as_ref().to_string();
        if !seen.insert(key.clone()) {
            return Err(XmlError::DuplicateAttribute(key));
        }
        // Raw value: literal tab/LF/CR become spaces (CDATA attribute
        // normalization), then entities are resolved.
        let raw = attr.value.as_ref();
        let normalized: Vec<u8> = raw
            .as_bytes()
            .iter()
            .map(|&b| match b {
                b'\t' | b'\n' | b'\r' => b' ',
                _ => b,
            })
            .collect();
        let normalized = String::from_utf8_lossy(&normalized);
        let value = unescape(&normalized)?;
        attrs.push((key, value));
    }

    // Namespace prefixes must be bound in scope (this element or an
    // ancestor), like Xerces enforces.
    let mut scope: HashSet<String> = ns_stack.last().cloned().unwrap_or_default();
    for (k, _) in &attrs {
        if let Some(p) = k.strip_prefix("xmlns:") {
            scope.insert(p.to_string());
        } else if k == "xmlns" {
            scope.insert(String::new());
        }
    }
    // The `xml` prefix is implicitly bound (XML 1.0 section 4), like every
    // conforming parser assumes.
    let bound = |p: &str| p == "xml" || scope.contains(p);
    if !prefix.is_empty() && !bound(&prefix) {
        return Err(XmlError::UnboundPrefix(prefix));
    }
    for (k, _) in &attrs {
        if let Some((p, _)) = k.split_once(':')
            && p != "xmlns"
            && !bound(p)
        {
            return Err(XmlError::UnboundPrefix(p.to_string()));
        }
    }

    Ok(Element {
        prefix,
        local,
        attrs,
        children: Vec::new(),
        self_closing: false,
    })
}

fn push_bindings(ns_stack: &mut Vec<HashSet<String>>, element: &Element) {
    let mut scope = ns_stack.last().cloned().unwrap_or_default();
    for (k, _) in &element.attrs {
        if let Some(p) = k.strip_prefix("xmlns:") {
            scope.insert(p.to_string());
        } else if k == "xmlns" {
            scope.insert(String::new());
        }
    }
    ns_stack.push(scope);
}

/// XML 2.11 line-ending normalization on raw (still escaped) content:
/// CRLF -> LF, lone CR -> LF. Character references are ASCII text and
/// remain untouched.
fn normalize_line_endings(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\r' => {
                out.push(b'\n');
                if i + 1 < bytes.len() && bytes[i + 1] == b'\n' {
                    i += 1;
                }
            }
            b => out.push(b),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Resolve predefined and character references; unknown entities are an
/// error (no DTDs are accepted, so no custom entities can exist).
fn unescape(raw: &str) -> Result<String, XmlError> {
    quick_xml::escape::unescape(raw)
        .map(|cow| cow.into_owned())
        .map_err(|e| XmlError::EntityRef(e.to_string()))
}

fn split_pi(raw: &str) -> Result<(String, String), XmlError> {
    match raw.split_once(char::is_whitespace) {
        Some((target, data)) => Ok((target.to_string(), data.to_string())),
        None => Ok((raw.to_string(), String::new())),
    }
}

/// Resolve one entity/character reference (the name between `&` and `;`).
/// Only the five predefined entities and numeric references exist, since
/// DOCTYPE (and with it custom entities) is rejected outright.
fn resolve_reference(name: &str) -> Result<String, XmlError> {
    let simple = match name {
        "amp" => Some("&"),
        "lt" => Some("<"),
        "gt" => Some(">"),
        "quot" => Some("\""),
        "apos" => Some("'"),
        _ => None,
    };
    if let Some(c) = simple {
        return Ok(c.to_string());
    }
    if let Some(number) = name.strip_prefix('#') {
        let code = if let Some(hex) = number
            .strip_prefix('x')
            .or_else(|| number.strip_prefix('X'))
        {
            u32::from_str_radix(hex, 16)
        } else {
            number.parse::<u32>()
        }
        .map_err(|_| XmlError::EntityRef(name.to_string()))?;
        let c = char::from_u32(code).ok_or_else(|| XmlError::EntityRef(name.to_string()))?;
        return Ok(c.to_string());
    }
    Err(XmlError::EntityRef(name.to_string()))
}
