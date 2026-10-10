//! XML writer with explicit namespace prefixes and document-order
//! attributes. The OSCI message format fixes prefixes on the wire (they
//! are part of the API), so callers pass qnames verbatim; no namespace
//! resolution happens here.

use std::io::{self, Write};

/// Escape text content: `&`, `<`, `>` and CR (C14N text rules).
pub fn escape_text(s: &str, out: &mut impl Write) -> io::Result<()> {
    for c in s.chars() {
        match c {
            '&' => out.write_all(b"&amp;")?,
            '<' => out.write_all(b"&lt;")?,
            '>' => out.write_all(b"&gt;")?,
            '\r' => out.write_all(b"&#xD;")?,
            _ => out.write_fmt(format_args!("{c}"))?,
        }
    }
    Ok(())
}

/// Escape an attribute value: text rules plus `"` and literal tab/LF
/// (C14N attribute rules).
pub fn escape_attr(s: &str, out: &mut impl Write) -> io::Result<()> {
    for c in s.chars() {
        match c {
            '&' => out.write_all(b"&amp;")?,
            '<' => out.write_all(b"&lt;")?,
            '>' => out.write_all(b"&gt;")?,
            '"' => out.write_all(b"&quot;")?,
            '\t' => out.write_all(b"&#x9;")?,
            '\n' => out.write_all(b"&#xA;")?,
            '\r' => out.write_all(b"&#xD;")?,
            _ => out.write_fmt(format_args!("{c}"))?,
        }
    }
    Ok(())
}

/// Streaming writer for OSCI messages.
pub struct XmlWriter<W: Write> {
    inner: W,
}

impl<W: Write> XmlWriter<W> {
    pub fn new(inner: W) -> Self {
        Self { inner }
    }

    /// Write the standard XML declaration used by OSCI messages.
    pub fn write_decl(&mut self) -> io::Result<()> {
        self.inner
            .write_all(b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>")
    }

    /// Open an element with attributes in the exact given order:
    /// `<qname k1="v1" k2="v2">`.
    pub fn start(&mut self, qname: &str, attrs: &[(&str, &str)]) -> io::Result<()> {
        self.inner.write_all(b"<")?;
        self.inner.write_all(qname.as_bytes())?;
        for (k, v) in attrs {
            self.inner.write_all(b" ")?;
            self.inner.write_all(k.as_bytes())?;
            self.inner.write_all(b"=\"")?;
            escape_attr(v, &mut self.inner)?;
            self.inner.write_all(b"\"")?;
        }
        self.inner.write_all(b">")
    }

    /// Close an element: `</qname>`.
    pub fn end(&mut self, qname: &str) -> io::Result<()> {
        self.inner.write_all(b"</")?;
        self.inner.write_all(qname.as_bytes())?;
        self.inner.write_all(b">")
    }

    /// Write escaped text content.
    pub fn text(&mut self, content: &str) -> io::Result<()> {
        escape_text(content, &mut self.inner)
    }

    /// Write bytes verbatim (pre-escaped fragments, base64 blocks).
    pub fn raw(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.inner.write_all(bytes)
    }

    pub fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }

    pub fn into_inner(self) -> W {
        self.inner
    }
}
