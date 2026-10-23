//! XML infrastructure for the OSCI 1.2 library: a strict, XXE-safe tree
//! parser; a namespace-prefix-exact writer; and the restricted C14N 1.0
//! canonicalizer (port of `de.osci.helper.CanParser` / `Canonizer`).

pub mod c14n;
pub mod parser;
pub mod serialize;
pub mod writer;

use std::collections::BTreeMap;

/// SOAP 1.1 envelope namespace (detects the envelope prefix on the wire).
pub const SOAP_ENVELOPE_NS: &str = "http://schemas.xmlsoap.org/soap/envelope/";
/// XML-DSig namespace (used to locate references in signature verification).
pub const XMLDSIG_NS: &str = "http://www.w3.org/2000/09/xmldsig#";
/// OSCI core namespace (signature header elements live here).
pub const OSCI_NS: &str = "http://www.osci.de/2002/04/osci";

/// A parsed XML document.
#[derive(Debug, Clone, Default)]
pub struct Document {
    /// Processing instructions before the root element, in order.
    pub pis_before_root: Vec<(String, String)>,
    /// Processing instructions after the root element, in order.
    pub pis_after_root: Vec<(String, String)>,
    /// Raw bytes before the root element (declaration, PIs, whitespace),
    /// kept for byte-exact reserialization.
    pub prolog: String,
    /// Raw bytes after the root element.
    pub epilog: String,
    pub root: Element,
}

impl Document {
    /// Depth-first search for an element carrying the given `Id`.
    pub fn find_by_id<'a>(&'a self, id: &str) -> Option<&'a Element> {
        self.root.find_by_id(id)
    }
}

/// One element with children.
#[derive(Debug, Clone, Default)]
pub struct Element {
    /// Prefix as written ("" when absent).
    pub prefix: String,
    pub local: String,
    /// Raw attribute list in document order (namespace declarations
    /// included, qname exactly as written).
    pub attrs: Vec<(String, String)>,
    pub children: Vec<Node>,
    /// Written as `<x/>` in the source (affects byte-exact serialization
    /// only; semantically identical to an empty element).
    pub self_closing: bool,
}

impl Element {
    pub fn qname(&self) -> String {
        if self.prefix.is_empty() {
            self.local.clone()
        } else {
            format!("{}:{}", self.prefix, self.local)
        }
    }

    /// First attribute value by raw qname.
    pub fn attr(&self, name: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    /// Value of the `Id` attribute (unqualified), like SAX `getValue("Id")`.
    pub fn id_attr(&self) -> Option<&str> {
        self.attr("Id")
    }

    /// Concatenated text content of this element (children texts joined,
    /// element descendants not descended into - mirrors how the Java code
    /// reads simple content elements).
    pub fn text(&self) -> String {
        let mut out = String::new();
        for child in &self.children {
            if let Node::Text(t) = child {
                out.push_str(t);
            }
        }
        out
    }

    pub fn elements(&self) -> impl Iterator<Item = &Element> {
        self.children.iter().filter_map(|c| match c {
            Node::Element(e) => Some(e),
            _ => None,
        })
    }

    /// Depth-first search for an element carrying the given `Id`.
    pub fn find_by_id<'a>(&'a self, id: &str) -> Option<&'a Element> {
        if self.id_attr() == Some(id) {
            return Some(self);
        }
        self.elements().find_map(|e| e.find_by_id(id))
    }
}

#[derive(Debug, Clone)]
pub enum Node {
    Element(Element),
    /// Character data; CDATA sections are merged into text nodes (their
    /// content is stored unescaped, exactly like a parser hands it over).
    Text(String),
}

/// Namespace scope: prefix ("" for the default namespace, bound via
/// `xmlns`) -> URI.
pub type NsBindings = BTreeMap<String, String>;

/// Bindings declared on one element (its `xmlns*` attributes).
pub fn declared_bindings(element: &Element) -> NsBindings {
    let mut map = NsBindings::new();
    for (k, v) in &element.attrs {
        if let Some(prefix) = k.strip_prefix("xmlns:") {
            map.insert(prefix.to_string(), v.clone());
        } else if k == "xmlns" {
            map.insert(String::new(), v.clone());
        }
    }
    map
}

/// The scope in which `element`'s children are evaluated: the inherited
/// bindings overlaid with the element's own declarations.
pub fn declared_bindings_plus(element: &Element, inherited: &NsBindings) -> NsBindings {
    let mut map = inherited.clone();
    for (k, v) in declared_bindings(element) {
        map.insert(k, v);
    }
    map
}

/// Resolve a prefix against a binding map; `None` when unbound.
pub fn resolve_prefix<'m>(bindings: &'m NsBindings, prefix: &str) -> Option<&'m str> {
    bindings.get(prefix).map(String::as_str)
}
