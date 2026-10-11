//! MIME multipart parser for the OSCI 1.2 transport library
//! (port of `de.osci.helper.MIMEParser` / `MIMEPartInputStream`).
//!
//! Behavior quirks inherited from the Java original:
//! - headers and part headers are read leniently (LF, CRLF and lone CR line
//!   endings; folding via leading whitespace; lines without a colon are
//!   skipped; EOF mid-header-block discards the block and ends the parts),
//! - `MIME-Version`, when present, must be `1.0`,
//! - the `boundary` parameter of the outer `Content-Type` is required,
//!   quoted parameter values are unquoted,
//! - every part requires a `Content-Type` header; a `charset` parameter, if
//!   present, must be UTF-8 (case-insensitive),
//! - `Content-ID` angle brackets are stripped, `Content-Length` is parsed
//!   as a number when present,
//! - part content is delimited by the byte marker `CRLF "--" boundary` -
//!   files with pure-LF line endings parse their headers but their parts
//!   cannot be read ("EOS before marker"), exactly like the Java library,
//! - a part's delimiting marker (and everything after it) is retained for
//!   the following `next_part()` call; the closing `--boundary--` drains
//!   and consumes the epilogue.

use std::collections::HashMap;
use std::io::{self, Read};

/// Maximum accepted line length in bytes (Java: 1 MB).
pub const MAX_LINE_SIZE: usize = 1024 * 1024;

const CHARSET: &str = "UTF-8";

fn format_error(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

pub struct MimeParser<R: Read> {
    inner: R,
    boundary: String,
    /// Lookahead bytes shared between part reading and header lines.
    pending: Vec<u8>,
    pending_pos: usize,
    /// Set once `next_part()` has reported the end of the multipart body.
    ended: bool,
}

impl<R: Read> MimeParser<R> {
    /// Parse the outer MIME headers and extract the boundary.
    pub fn new(inner: R) -> io::Result<Self> {
        let mut parser = Self {
            inner,
            boundary: String::new(),
            pending: Vec::new(),
            pending_pos: 0,
            ended: false,
        };
        let Some(headers) = parser.read_headers()? else {
            return Err(format_error("no MIME header found"));
        };
        if let Some(version) = headers.get("mime-version")
            && version != "1.0"
        {
            return Err(format_error("unsupported MIME version"));
        }
        let Some(content_type) = headers.get("content-type") else {
            return Err(format_error("missing Content-Type header"));
        };
        let params = parse_header_params("content-type", content_type);
        parser.boundary = params
            .get("boundary")
            .ok_or_else(|| format_error("missing boundary parameter"))?
            .clone();
        Ok(parser)
    }

    pub fn boundary(&self) -> &str {
        &self.boundary
    }

    /// Advance to the next part. `Ok(None)` marks the end of the multipart
    /// body; calling again afterwards is an error (as in the Java library).
    pub fn next_part(&mut self) -> io::Result<Option<MimePart<'_, R>>> {
        if self.ended {
            return Err(format_error("no further MIME part"));
        }

        let mut line = loop {
            match self.read_line()? {
                None => return Err(format_error("MIME part boundary expected")),
                Some(l) if l.trim().is_empty() => continue,
                Some(l) => break l,
            }
        };
        line = line.trim().to_string();

        if line == format!("--{}--", self.boundary) {
            self.ended = true;
            // Drain and discard the epilogue.
            let mut sink = [0u8; 8192];
            self.pending.clear();
            self.pending_pos = 0;
            loop {
                match self.inner.read(&mut sink)? {
                    0 => break,
                    _ => continue,
                }
            }
            return Ok(None);
        }
        if line != format!("--{}", self.boundary) {
            return Err(format_error("MIME part boundary expected"));
        }

        let Some(headers) = self.read_headers()? else {
            self.ended = true;
            return Ok(None);
        };

        let Some(content_type_value) = headers.get("content-type") else {
            return Err(format_error("missing Content-Type header in MIME part"));
        };
        let ct = parse_header_params("content-type", content_type_value);
        if let Some(charset) = ct.get("charset")
            && !charset.eq_ignore_ascii_case(CHARSET)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid charset {charset}"),
            ));
        }
        let content_type = ct.get("content-type").cloned().unwrap_or_default();
        let content_id = match headers.get("content-id") {
            Some(id) => id.strip_prefix('<').map_or_else(
                || id.clone(),
                |s| {
                    // Java unconditionally drops the last character when
                    // the value starts with '<'.
                    s[..s.len().saturating_sub(1)].to_string()
                },
            ),
            None => return Err(format_error("missing Content-ID header in MIME part")),
        };
        let length = match headers.get("content-length") {
            Some(l) => l
                .parse::<i64>()
                .map_err(|_| format_error("invalid Content-Length header"))?,
            None => -1,
        };

        Ok(Some(MimePart {
            marker: format!("\r\n--{}", self.boundary).into_bytes(),
            content_type,
            encoding: headers.get("content-transfer-encoding").cloned(),
            content_id,
            length,
            headers,
            parser: self,
            closed: false,
        }))
    }

    fn read_headers(&mut self) -> io::Result<Option<HashMap<String, String>>> {
        let mut headers = HashMap::new();

        // Skip leading empty lines; EOF here means "no header block".
        let mut header = loop {
            match self.read_line()? {
                None => return Ok(None),
                Some(l) if l.trim().is_empty() => continue,
                Some(l) => break l,
            }
        };

        while !header.is_empty() {
            let mut next = match self.read_line()? {
                // EOF inside the header block discards it, like the Java
                // NullPointerException handler.
                None => return Ok(None),
                Some(l) => l,
            };
            while !next.is_empty() && next.chars().next().is_some_and(char::is_whitespace) {
                header += &next;
                next = match self.read_line()? {
                    None => return Ok(None),
                    Some(l) => l,
                };
            }
            if let Some((name, value)) = header.split_once(':') {
                headers.insert(name.trim().to_lowercase(), value.trim().to_string());
            }
            // Lines without a colon are skipped, like the Java
            // StringIndexOutOfBounds handler.
            header = next.trim().to_string();
        }

        if headers.is_empty() {
            return Ok(None);
        }
        Ok(Some(headers))
    }

    /// Read one header/body line in any of the three line-ending styles.
    /// Returns `None` at EOF when no bytes were collected.
    fn read_line(&mut self) -> io::Result<Option<String>> {
        let mut out = Vec::new();
        let mut counter = 0usize;
        loop {
            let byte = match self.read_byte()? {
                None => {
                    if out.is_empty() {
                        return Ok(None);
                    }
                    break;
                }
                Some(b) => b,
            };
            if byte == 0x0D {
                match self.read_byte()? {
                    Some(0x0A) | None => break,
                    Some(b2) => {
                        out.push(0x0D);
                        out.push(b2);
                    }
                }
            } else if byte == 0x0A {
                break;
            } else {
                out.push(byte);
            }
            counter += 1;
            if counter >= MAX_LINE_SIZE {
                return Err(format_error("MIME line exceeds maximum length"));
            }
        }
        Ok(Some(String::from_utf8_lossy(&out).into_owned()))
    }

    fn read_byte(&mut self) -> io::Result<Option<u8>> {
        if self.pending_pos < self.pending.len() {
            let b = self.pending[self.pending_pos];
            self.pending_pos += 1;
            return Ok(Some(b));
        }
        let mut byte = [0u8; 1];
        match self.inner.read(&mut byte)? {
            0 => Ok(None),
            _ => Ok(Some(byte[0])),
        }
    }

    fn compact_pending(&mut self) {
        if self.pending_pos > 0 {
            self.pending.drain(..self.pending_pos);
            self.pending_pos = 0;
        }
    }
}

/// Split `Content-Type: media/type; key=value; key2="value 2"` into its
/// media type (under `field`) and parameters, mirroring the Java
/// `StringTokenizer(header, "; ")` behavior.
fn parse_header_params(field: &str, value: &str) -> HashMap<String, String> {
    let mut params = HashMap::new();
    let mut tokens = value.split([';', ' ']).filter(|t| !t.is_empty());
    if let Some(media) = tokens.next() {
        params.insert(field.to_string(), media.trim().to_string());
    }
    for token in tokens {
        if let Some((key, raw)) = token.split_once('=') {
            let value = raw.trim();
            let value = if value.len() >= 2 && value.starts_with('"') && value.ends_with('"') {
                &value[1..value.len() - 1]
            } else {
                value
            };
            params.insert(key.trim().to_string(), value.trim().to_string());
        }
    }
    params
}

/// One MIME part's raw content. The content is delimited on the fly by the
/// `CRLF "--" boundary` marker; reading past the end yields EOF. Dropping
/// the part without reading to the end drains it first (Java `close()`).
pub struct MimePart<'a, R: Read> {
    parser: &'a mut MimeParser<R>,
    marker: Vec<u8>,
    content_type: String,
    encoding: Option<String>,
    content_id: String,
    length: i64,
    headers: HashMap<String, String>,
    closed: bool,
}

impl<R: Read> std::fmt::Debug for MimePart<'_, R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MimePart")
            .field("content_type", &self.content_type)
            .field("content_id", &self.content_id)
            .field("encoding", &self.encoding)
            .field("length", &self.length)
            .field("closed", &self.closed)
            .finish()
    }
}

impl<R: Read> MimePart<'_, R> {
    pub fn content_type(&self) -> &str {
        &self.content_type
    }

    pub fn encoding(&self) -> Option<&str> {
        self.encoding.as_deref()
    }

    pub fn content_id(&self) -> &str {
        &self.content_id
    }

    /// Declared `Content-Length` or -1 when absent.
    pub fn length(&self) -> i64 {
        self.length
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).map(String::as_str)
    }

    /// Drain to the boundary marker (or error), like the Java `close()`.
    pub fn finish(mut self) -> io::Result<()> {
        let mut sink = [0u8; 8192];
        loop {
            match self.read(&mut sink) {
                Ok(0) => return Ok(()),
                Ok(_) => continue,
                Err(e) => return Err(e),
            }
        }
    }
}

impl<R: Read> Read for MimePart<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.closed || buf.is_empty() {
            return Ok(0);
        }
        let parser = &mut *self.parser;
        loop {
            parser.compact_pending();
            if parser.pending.is_empty() {
                // Refill the lookahead directly from the source.
                let mut chunk = [0u8; 8192];
                let n = parser.inner.read(&mut chunk)?;
                if n == 0 {
                    return Err(format_error("EOS before marker."));
                }
                parser.pending.extend_from_slice(&chunk[..n]);
            }

            let data = &parser.pending[parser.pending_pos..];
            if let Some(i) = verified_marker(data, &self.marker) {
                let out_len = buf.len().min(i);
                buf[..out_len].copy_from_slice(&data[..out_len]);
                parser.pending_pos += out_len;
                if i <= buf.len() {
                    // The whole pre-marker content was delivered; the part
                    // ends here and the marker stays in the lookahead.
                    self.closed = true;
                }
                return Ok(out_len);
            }

            // Deliver everything except a trailing partial marker; keep the
            // partial in the lookahead until it resolves either way.
            let deliverable = data.len() - partial_marker_suffix(data, &self.marker);
            if deliverable == 0 {
                continue; // need more bytes to resolve the boundary
            }
            let out_len = deliverable.min(buf.len());
            buf[..out_len].copy_from_slice(&data[..out_len]);
            parser.pending_pos += out_len;
            return Ok(out_len);
        }
    }
}

impl<R: Read> Drop for MimePart<'_, R> {
    fn drop(&mut self) {
        if !self.closed {
            // Drain like Java close(): loop until the marker (or an error,
            // which is ignored on drop). A single read is not enough when
            // the part spans several refill blocks.
            let mut sink = [0u8; 8192];
            loop {
                match self.read(&mut sink) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => continue,
                }
            }
        }
    }
}

/// Longest proper suffix of `data` that is a prefix of `marker` (a marker
/// split across refill boundaries).
fn partial_marker_suffix(data: &[u8], marker: &[u8]) -> usize {
    let max = (data.len() - 1).min(marker.len() - 1);
    for len in (1..=max).rev() {
        if data[data.len() - len..] == marker[..len] {
            return len;
        }
    }
    0
}

/// Find the marker at a real boundary position: the bytes following the
/// marker must be `--` (closing boundary) or CRLF/LF (next part boundary).
/// A marker inside content that continues with anything else is content.
fn verified_marker(haystack: &[u8], marker: &[u8]) -> Option<usize> {
    if marker.is_empty() || haystack.len() < marker.len() {
        return None;
    }
    let mut from = 0;
    while from + marker.len() <= haystack.len() {
        let rel = find_subslice(&haystack[from..], marker)?;
        let at = from + rel;
        let after = &haystack[at + marker.len()..];
        let is_boundary = after.is_empty()
            || after.starts_with(b"--")
            || after.starts_with(b"\r\n")
            || after.starts_with(b"\n");
        if is_boundary {
            // "after is empty" is provisional: resolved by the partial
            // marker holdback in the next refill
            return Some(at);
        }
        from = at + 1;
    }
    None
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}
