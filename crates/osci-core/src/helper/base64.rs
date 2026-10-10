//! Streaming Base64 codec, byte-compatible with the OSCI 1.2 Java library
//! (`de.osci.helper.Base64*`).
//!
//! Wire-format quirks that are part of the OSCI message format:
//! - the encoder inserts a bare LF (`\n`) after every 76 output characters,
//!   including a trailing LF when the encoded data ends exactly on a
//!   76-character boundary,
//! - the decoder silently ignores every byte that is neither in the standard
//!   alphabet nor `=` (whitespace inside and after the data is legal),
//! - `=` is only accepted as the 3rd or 4th character of a quad; a quad
//!   ending in a single `=` consumes and discards one further input byte,
//! - a final unterminated quad (EOF before padding) is dropped without error.

use std::io::{self, Read, Write};

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const PAD: u8 = b'=';
const LINE_BREAK: u8 = b'\n';
const LINE_WIDTH: usize = 76;

/// Encode to a `String`, with the OSCI line-break convention.
pub fn encode(data: &[u8]) -> String {
    let mut out = Vec::with_capacity(calc_b64_length(data.len() as u64) as usize);
    let mut enc = Base64Encoder::new(&mut out);
    enc.write_all(data).expect("vec write");
    enc.finish().expect("vec write");
    String::from_utf8(out).expect("base64 is ascii")
}

/// Decode, ignoring non-alphabet bytes (see module docs).
pub fn decode(data: &str) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut dec = Base64Decoder::new(data.as_bytes());
    dec.read_to_end(&mut out)?;
    Ok(out)
}

/// Encoded length on the wire for `len` input bytes, including line breaks.
/// Mirrors `Base64.calcB64Length`: `0` maps to `0`.
pub fn calc_b64_length(len: u64) -> u64 {
    if len == 0 {
        return 0;
    }
    let l = ((len - 1) / 3) * 4 + 4;
    l + l / 76
}

/// Streaming encoder. `finish()` applies padding (and the final line break)
/// and returns the inner writer; dropping without `finish()` emits neither.
pub struct Base64Encoder<W: Write> {
    inner: W,
    buf: u32,
    in_wait: u8,
    chars_written: usize,
}

impl<W: Write> Base64Encoder<W> {
    pub fn new(inner: W) -> Self {
        Self {
            inner,
            buf: 0,
            in_wait: 0,
            chars_written: 0,
        }
    }

    /// Complete the encoding (padding + final line break), flush and hand
    /// back the inner writer.
    pub fn finish(mut self) -> io::Result<W> {
        self.complete_encoding()?;
        self.inner.flush()?;
        Ok(self.inner)
    }

    fn write_quad(&mut self, quad: [u8; 4]) -> io::Result<()> {
        self.inner.write_all(&quad)?;
        self.chars_written += 4;
        if self.chars_written == LINE_WIDTH {
            self.inner.write_all(&[LINE_BREAK])?;
            self.chars_written = 0;
        }
        Ok(())
    }

    fn complete_encoding(&mut self) -> io::Result<()> {
        let mut quad = [PAD; 4];
        match self.in_wait {
            0 => return Ok(()),
            1 => {
                self.buf <<= 4;
                quad[1] = ALPHABET[(self.buf & 0x3f) as usize];
                self.buf >>= 6;
                quad[0] = ALPHABET[(self.buf & 0x3f) as usize];
            }
            2 => {
                self.buf <<= 2;
                quad[2] = ALPHABET[(self.buf & 0x3f) as usize];
                self.buf >>= 6;
                quad[1] = ALPHABET[(self.buf & 0x3f) as usize];
                self.buf >>= 6;
                quad[0] = ALPHABET[(self.buf & 0x3f) as usize];
            }
            _ => unreachable!("in_wait is bounded by 3"),
        }
        self.in_wait = 0;
        self.buf = 0;
        self.write_quad(quad)
    }
}

impl<W: Write> Write for Base64Encoder<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        for &b in buf {
            self.buf = (self.buf << 8) | u32::from(b);
            self.in_wait += 1;
            if self.in_wait == 3 {
                let quad = [
                    ALPHABET[((self.buf >> 18) & 0x3f) as usize],
                    ALPHABET[((self.buf >> 12) & 0x3f) as usize],
                    ALPHABET[((self.buf >> 6) & 0x3f) as usize],
                    ALPHABET[(self.buf & 0x3f) as usize],
                ];
                self.buf = 0;
                self.in_wait = 0;
                self.write_quad(quad)?;
            }
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Streaming decoder over any reader; see module docs for the accepted
/// (lenient) input grammar.
pub struct Base64Decoder<R: Read> {
    inner: R,
    store: [u8; 3],
    pos: usize,
    nos: usize,
    eof: bool,
}

impl<R: Read> Base64Decoder<R> {
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            store: [0; 3],
            pos: 0,
            nos: 0,
            eof: false,
        }
    }

    fn read_one(&mut self) -> io::Result<Option<u8>> {
        let mut byte = [0u8; 1];
        match self.inner.read(&mut byte)? {
            0 => Ok(None),
            _ => Ok(Some(byte[0])),
        }
    }

    /// Decode the next quad into `store`. Returns `false` at end of input.
    fn get_store(&mut self) -> io::Result<bool> {
        self.pos = 0;
        let mut acc: u32 = 0;
        let mut bytes_read = 0usize;

        while bytes_read < 4 {
            let Some(byte) = self.read_one()? else {
                // EOF: an unterminated final quad is dropped silently.
                self.nos = 0;
                self.eof = true;
                return Ok(false);
            };
            match decode_int(byte) {
                -1 => continue,
                -2 => {
                    if bytes_read != 2 && bytes_read != 3 {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "Invalid placement of '=' in the stream",
                        ));
                    }
                    break;
                }
                v => {
                    acc = (acc << 6) | v as u32;
                    bytes_read += 1;
                }
            }
        }

        match bytes_read {
            4 => {
                self.nos = 3;
                self.store = [(acc >> 16) as u8, (acc >> 8) as u8, acc as u8];
            }
            2 => {
                // "xx=": one output byte; one further input byte is consumed
                // and discarded, exactly like the Java implementation.
                self.nos = 1;
                self.read_one()?;
                self.store[0] = (acc >> 4) as u8;
            }
            3 => {
                // "xxx=": two output bytes.
                self.nos = 2;
                self.store[0] = (acc >> 10) as u8;
                self.store[1] = (acc >> 2) as u8;
            }
            _ => unreachable!("padding placement was validated above"),
        }
        Ok(true)
    }
}

impl<R: Read> Read for Base64Decoder<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut filled = 0usize;
        while filled < buf.len() {
            if self.pos >= self.nos && (self.eof || !self.get_store()?) {
                break;
            }
            while filled < buf.len() && self.pos < self.nos {
                buf[filled] = self.store[self.pos];
                filled += 1;
                self.pos += 1;
            }
        }
        Ok(filled)
    }
}

fn decode_int(src: u8) -> i8 {
    match src {
        b'A'..=b'Z' => (src - b'A') as i8,
        b'a'..=b'z' => (src - b'a') as i8 + 26,
        b'0'..=b'9' => (src - b'0') as i8 + 52,
        b'+' => 62,
        b'/' => 63,
        b'=' => -2,
        _ => -1,
    }
}
