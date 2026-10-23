//! The MessageMetaData custom-header extension
//! (`extension-message-meta-data` module of the reference): a structured
//! custom header in the `http://www.osci.eu/ws/2014/10/transport`
//! namespace carrying XTA delivery attributes, originator/destination
//! identifiers and WS-Addressing message identification.

use crate::xml::{Document, Element};

pub const MMD_NS: &str = "http://www.osci.eu/ws/2014/10/transport";
pub const WSA_NS: &str = "http://www.w3.org/2005/08/addressing";

/// One `Identifier` of an originator or destination role.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MmdIdentifier {
    pub name: Option<String>,
    pub kind: Option<String>,
    pub value: String,
}

/// Parsed MessageMetaData header.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MessageMetaData {
    pub service_quality: Option<String>,
    /// Originators: Author (and Reader) entries.
    pub authors: Vec<MmdIdentifier>,
    /// Destinations: Reader (and Addressee) entries.
    pub readers: Vec<MmdIdentifier>,
    /// WS-Addressing MessageID.
    pub message_id: Option<String>,
}

/// Locate the MessageMetaData element: as a header child of a full SOAP
/// message, or as the root of a bare header fragment (the extension
/// fixture stores the element standalone, any prefix - it uses `ns4`).
pub fn find_mmd_element(doc: &Document) -> Option<&Element> {
    if doc.root.local == "MessageMetaData" {
        return Some(&doc.root);
    }
    let header = crate::soap::find_header(doc)?;
    let root_bindings = crate::xml::declared_bindings(&doc.root);
    header
        .elements()
        .find(|&child| {
            child.local == "MessageMetaData"
                && crate::xml::resolve_prefix(
                    &crate::xml::declared_bindings_plus(child, &root_bindings),
                    &child.prefix,
                ) == Some(MMD_NS)
        })
        .map(|v| v as _)
}

/// Parse the MessageMetaData content.
pub fn parse_mmd(element: &Element) -> MessageMetaData {
    let mut mmd = MessageMetaData::default();
    fn descendants<'a>(e: &'a Element, local: &str, out: &mut Vec<&'a Element>) {
        for c in e.elements() {
            if c.local == local {
                out.push(c);
            }
            descendants(c, local, out);
        }
    }
    let mut qualities = Vec::new();
    descendants(element, "ServiceQuality", &mut qualities);
    mmd.service_quality = qualities.first().map(|q| q.text());

    for container in element.elements() {
        let targets: &mut Vec<MmdIdentifier> = if container.local == "Originators" {
            &mut mmd.authors
        } else if container.local == "Destinations" {
            &mut mmd.readers
        } else {
            continue;
        };
        for role in container.elements() {
            for identifier in role.elements().filter(|e| e.local == "Identifier") {
                targets.push(MmdIdentifier {
                    name: identifier.attr("name").map(str::to_string),
                    kind: identifier.attr("type").map(str::to_string),
                    value: identifier.text(),
                });
            }
        }
    }

    let mut message_ids = Vec::new();
    descendants(element, "MessageID", &mut message_ids);
    mmd.message_id = message_ids.first().map(|m| m.text());
    mmd
}
