//! In-memory buffer that swaps to a temporary file once it exceeds a size
//! limit (port of `de.osci.osci12.common.SwapBuffer`).
//!
//! Data is buffered in RAM until writing more bytes would exceed
//! `max_buffer_size`, then everything spills to a temp file. When the buffer
//! is marked `confidential`, the spill file is AES-256-GCM encrypted with a
//! process-wide random key (chunked frames, so both directions stay
//! streaming; the on-disk format is internal to this library). Reads can be
//! repeated via `reset()`/`input()`, mirroring the `OSCIDataSource`
//! contract.
//!
//! Deviation from Java: the default limit is a fixed 4 MiB instead of "1%
//! of the JVM free heap" (which has no meaningful Rust equivalent).

use std::fs::File;
use std::io::{self, BufWriter, Read, Seek, Write};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use osci_crypto::algorithms::{DEFAULT_SYMMETRIC_CIPHER, SymCipher};
use osci_crypto::symcipher::oneshot;
use rand::RngCore;

/// Default in-memory limit before swapping to disk.
pub const DEFAULT_MAX_BUFFER_SIZE: u64 = 4 * 1024 * 1024;
/// Plaintext bytes per encrypted frame in the spill file.
const FRAME_SIZE: usize = 64 * 1024;
/// Sanity bound for frames read back from disk (a corrupt length field
/// must not trigger huge allocations).
const MAX_FRAME_LEN: usize = FRAME_SIZE + 1024;

fn temp_key() -> &'static [u8; 32] {
    static KEY: OnceLock<[u8; 32]> = OnceLock::new();
    KEY.get_or_init(|| {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        bytes
    })
}

fn frame_cipher() -> SymCipher {
    SymCipher::from_uri(DEFAULT_SYMMETRIC_CIPHER).expect("default cipher is a known URI")
}

/// Sealed content, ready to be read (repeatedly).
enum Data {
    Memory(Vec<u8>),
    PlainFile(PathBuf),
    EncryptedFile(PathBuf),
}

enum WriterState {
    Memory(Vec<u8>),
    Plain {
        writer: BufWriter<File>,
        path: PathBuf,
    },
    Encrypted {
        writer: BufWriter<File>,
        plain: Vec<u8>,
        path: PathBuf,
    },
}

enum Source {
    Plain(File),
    Encrypted(DecryptReader),
}

/// Streaming decryptor over the chunked-frame spill format:
/// `[u32 BE frame_len][12B IV][frame_len - 28 bytes ciphertext+tag]`,
/// terminated by a zero-length frame.
struct DecryptReader {
    file: File,
    plain: Vec<u8>,
    pos: usize,
    eof: bool,
}

impl DecryptReader {
    fn open(mut file: File) -> io::Result<Self> {
        file.rewind()?;
        Ok(Self {
            file,
            plain: Vec::new(),
            pos: 0,
            eof: false,
        })
    }

    fn read_frame(&mut self) -> io::Result<()> {
        let mut header = [0u8; 4];
        if read_exact_or_eof(&mut self.file, &mut header)? {
            self.eof = true;
            return Ok(());
        }
        let frame_len = u32::from_be_bytes(header) as usize;
        if frame_len == 0 {
            self.eof = true;
            return Ok(());
        }
        if frame_len > MAX_FRAME_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "swap buffer frame corrupt",
            ));
        }
        let mut frame = vec![0u8; frame_len];
        self.file.read_exact(&mut frame)?;
        let plain = oneshot::decrypt(frame_cipher(), temp_key(), &frame)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "swap buffer frame corrupt"))?;
        self.plain = plain;
        self.pos = 0;
        Ok(())
    }
}

impl Read for DecryptReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        while !self.eof && self.pos >= self.plain.len() {
            self.read_frame()?;
        }
        if self.eof && self.pos >= self.plain.len() {
            return Ok(0);
        }
        let n = buf.len().min(self.plain.len() - self.pos);
        buf[..n].copy_from_slice(&self.plain[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

fn read_exact_or_eof(file: &mut File, buf: &mut [u8]) -> io::Result<bool> {
    let mut filled = 0;
    while filled < buf.len() {
        match file.read(&mut buf[filled..])? {
            0 => return Ok(true), // clean EOF at a frame boundary
            n => filled += n,
        }
    }
    Ok(false)
}

pub struct SwapBuffer {
    confidential: bool,
    max_buffer_size: u64,
    byte_count: u64,
    /// Present while the buffer accepts writes; `None` once sealed for reading.
    writer: Option<WriterState>,
    data: Option<Data>,
    source: Option<Source>,
    /// Read position for memory-backed data (the reader owns no copy).
    memory_pos: usize,
}

impl Default for SwapBuffer {
    fn default() -> Self {
        Self::with_limit(DEFAULT_MAX_BUFFER_SIZE)
    }
}

impl SwapBuffer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_limit(max_buffer_size: u64) -> Self {
        Self {
            confidential: false,
            max_buffer_size,
            byte_count: 0,
            writer: Some(WriterState::Memory(Vec::new())),
            data: None,
            source: None,
            memory_pos: 0,
        }
    }

    /// Set whether spill files are encrypted. NB: this must be decided
    /// before the first spill - a flag flip after the buffer swapped to
    /// disk leaves the already-written file in its previous state.
    pub fn set_confidential(&mut self, confidential: bool) {
        self.confidential = confidential;
    }

    pub fn is_confidential(&self) -> bool {
        self.confidential
    }

    /// Number of bytes written so far.
    pub fn length(&self) -> u64 {
        self.byte_count
    }

    /// Path of the spill file, if the buffer has swapped to disk.
    pub fn spill_path(&self) -> Option<&Path> {
        match &self.writer {
            Some(WriterState::Plain { path, .. }) | Some(WriterState::Encrypted { path, .. }) => {
                return Some(path);
            }
            _ => {}
        }
        match &self.data {
            Some(Data::PlainFile(path)) | Some(Data::EncryptedFile(path)) => Some(path),
            _ => None,
        }
    }

    /// Start (or continue) writing. Fails once the buffer has been sealed
    /// for reading.
    pub fn output(&mut self) -> io::Result<SwapBufferWriter<'_>> {
        if self.writer.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "SwapBuffer is in read mode and cannot be written",
            ));
        }
        Ok(SwapBufferWriter { buffer: self })
    }

    /// Seal the write side (if still open) and read from the beginning.
    /// Subsequent calls continue the same read position.
    pub fn input(&mut self) -> io::Result<SwapBufferReader<'_>> {
        self.seal()?;
        if self.source.is_none() {
            self.open_source()?;
        }
        Ok(SwapBufferReader { buffer: self })
    }

    /// Rewind and read the data again from the beginning.
    pub fn reset(&mut self) -> io::Result<()> {
        self.seal()?;
        self.memory_pos = 0;
        self.open_source()
    }

    /// Delete the spill file (no-op when the data stayed in memory).
    pub fn delete_temp_file(&mut self) -> io::Result<()> {
        if let Some(path) = self.spill_path().map(Path::to_path_buf) {
            std::fs::remove_file(path)?;
        }
        self.source = None;
        self.data = None;
        Ok(())
    }

    fn seal(&mut self) -> io::Result<()> {
        let Some(writer) = self.writer.take() else {
            return Ok(());
        };
        match writer {
            WriterState::Memory(data) => {
                self.data = Some(Data::Memory(data));
            }
            WriterState::Plain { mut writer, path } => {
                writer.flush()?;
                writer.get_ref().sync_all()?;
                self.data = Some(Data::PlainFile(path));
            }
            WriterState::Encrypted {
                mut writer,
                mut plain,
                path,
            } => {
                if !plain.is_empty() {
                    write_encrypted_frame(&mut writer, &plain)?;
                    plain.clear();
                }
                writer.write_all(&0u32.to_be_bytes())?;
                writer.flush()?;
                writer.get_ref().sync_all()?;
                self.data = Some(Data::EncryptedFile(path));
            }
        }
        Ok(())
    }

    fn open_source(&mut self) -> io::Result<()> {
        // Memory-backed data is read straight from the stored bytes (the
        // reader keeps the position); only file-backed sources need an
        // opened handle. This avoids deep-copying the buffer per reader.
        self.source = match self.data.as_ref() {
            Some(Data::Memory(_)) | None => None,
            Some(Data::PlainFile(path)) => Some(Source::Plain(File::open(path)?)),
            Some(Data::EncryptedFile(path)) => {
                Some(Source::Encrypted(DecryptReader::open(File::open(path)?)?))
            }
        };
        Ok(())
    }

    fn spill_to_file(&mut self) -> io::Result<()> {
        // the file is created BEFORE the buffered bytes are taken out of
        // the writer state: a failed open (disk full, no tmpdir, perms)
        // must leave the memory buffer intact - taking first would
        // silently discard the whole prefix (review finding)
        let mut path = std::env::temp_dir();
        path.push(format!(
            "osci-{}-{}",
            std::process::id(),
            rand::thread_rng().next_u32()
        ));
        // 0600: the spill file may hold plaintext (non-confidential mode)
        // and must not be readable by other users on multi-user hosts.
        #[cfg(unix)]
        let file = {
            use std::os::unix::fs::OpenOptionsExt as _;
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)?
        };
        #[cfg(not(unix))]
        let file = File::create_new(&path)?;
        let writer = BufWriter::new(file);
        // infallible from here: take the buffered bytes and swap the
        // writer state in one straight-line stretch (no clone of the
        // buffer needed, and the failed-open path above left it intact)
        let buffered = match self.writer.as_mut() {
            Some(WriterState::Memory(buffered)) => std::mem::take(buffered),
            _ => return Ok(()),
        };
        self.writer = Some(if self.confidential {
            WriterState::Encrypted {
                writer,
                plain: Vec::new(),
                path,
            }
        } else {
            WriterState::Plain { writer, path }
        });
        self.write_through_counted(&buffered, false)
    }

    fn write_through(&mut self, buf: &[u8]) -> io::Result<()> {
        self.write_through_counted(buf, true)
    }

    /// `count` is false when replaying already-counted bytes during a
    /// spill, so `length()` does not double-count the swapped prefix.
    fn write_through_counted(&mut self, buf: &[u8], count: bool) -> io::Result<()> {
        match self.writer.as_mut().expect("writer present while writing") {
            WriterState::Memory(data) => data.extend_from_slice(buf),
            WriterState::Plain { writer, .. } => writer.write_all(buf)?,
            WriterState::Encrypted { writer, plain, .. } => {
                plain.extend_from_slice(buf);
                while plain.len() >= FRAME_SIZE {
                    let frame: Vec<u8> = plain.drain(..FRAME_SIZE).collect();
                    write_encrypted_frame(writer, &frame)?;
                }
            }
        }
        if count {
            self.byte_count += buf.len() as u64;
        }
        Ok(())
    }
}

fn write_encrypted_frame(writer: &mut impl Write, plain: &[u8]) -> io::Result<()> {
    let mut iv = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut iv);
    let frame = oneshot::encrypt(frame_cipher(), temp_key(), &iv, plain)
        .map_err(|_| io::Error::other("swap buffer encryption failed"))?;
    writer.write_all(&(frame.len() as u32).to_be_bytes())?;
    writer.write_all(&frame)
}

pub struct SwapBufferWriter<'a> {
    buffer: &'a mut SwapBuffer,
}

impl Write for SwapBufferWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let would_exceed = matches!(self.buffer.writer, Some(WriterState::Memory(_)))
            && self.buffer.byte_count + buf.len() as u64 > self.buffer.max_buffer_size;
        if would_exceed {
            self.buffer.spill_to_file()?;
        }
        self.buffer.write_through(buf)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        match self.buffer.writer.as_mut() {
            Some(WriterState::Plain { writer, .. }) => writer.flush(),
            Some(WriterState::Encrypted { writer, .. }) => writer.flush(),
            _ => Ok(()),
        }
    }
}

pub struct SwapBufferReader<'a> {
    buffer: &'a mut SwapBuffer,
}

impl Read for SwapBufferReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // memory-backed: read straight from the stored bytes at the
        // buffer's read position (no copy of the buffer itself)
        if let Some(Data::Memory(data)) = &self.buffer.data {
            let pos = self.buffer.memory_pos;
            if pos >= data.len() {
                return Ok(0);
            }
            let n = buf.len().min(data.len() - pos);
            buf[..n].copy_from_slice(&data[pos..pos + n]);
            self.buffer.memory_pos += n;
            return Ok(n);
        }
        match self.buffer.source.as_mut() {
            Some(Source::Plain(file)) => file.read(buf),
            Some(Source::Encrypted(reader)) => reader.read(buf),
            None => Ok(0),
        }
    }
}

impl Drop for SwapBuffer {
    fn drop(&mut self) {
        let _ = self.delete_temp_file();
    }
}
