//! The lossless object archive: every object as it arrived, with its timing.
//!
//! Written for every room, encrypted or not, because it needs nothing from the
//! payload: a ciphertext object is archived exactly as a plaintext one is, and
//! the customer opens it later with their own keys. It is also the format that
//! cannot be wrong about media -- nothing is parsed, reordered or re-timed -- so
//! anything derived from it, CMAF included, can be rebuilt from it.
//!
//! # Layout
//!
//! One file per track per segment. Big-endian throughout.
//!
//! ```text
//! file    := magic header record*
//! magic   := "MOQOMAR1"
//! header  := len:u32 json:len crc:u32          crc32c(json)
//! record  := kind:u8 len:u32 body:len crc:u32  crc32c(kind ‖ len ‖ body)
//!
//! kind 0x01 object   group:u64 object:u64 received:u64 plen:u32 properties:plen payload
//! kind 0x02 session  ordinal:u32 at:u64       a (re)subscription began
//! kind 0x03 departed at:u64                   the publisher went away
//! kind 0xFF end      objects:u64 bytes:u64 at:u64
//! ```
//!
//! `received` and `at` are microseconds since the Unix epoch on the recorder's
//! clock. `properties` is the MOQT wire encoding of the object's properties,
//! which is where the publisher's capture time travels. A file without an
//! `end` record was cut short -- a crash, a lost disk -- and every record before
//! the tear is still valid on its own, which is what the per-record checksum
//! buys.

use std::io::{self, Read, Write};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use moqom_client::ObjectProperties;
use moqom_proto::control::properties::Properties;
use serde::{Deserialize, Serialize};

use crate::crc32c::{Crc32c, checksum};

/// The first eight bytes of every archive file.
pub const MAGIC: &[u8; 8] = b"MOQOMAR1";

const OBJECT: u8 = 0x01;
const SESSION: u8 = 0x02;
const DEPARTED: u8 = 0x03;
const END: u8 = 0xFF;

/// Longest record body a reader will allocate for. Well past any object a relay
/// forwards, and small enough that a corrupt length cannot exhaust memory.
pub const MAX_RECORD: usize = 64 << 20;

/// What a file is, stated once at its start.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Header {
    /// Always `moqom-archive`.
    pub format: String,
    /// Layout version; this module writes `1`.
    pub version: u32,
    /// The recording this file belongs to.
    pub recording: String,
    /// The publisher's namespace, field by field.
    pub namespace: Vec<String>,
    /// The track name within it.
    pub track: String,
    /// Which claim of the recording wrote this file, from 1.
    pub attempt: u32,
    /// Position of this file within the track for this attempt, from 1.
    pub segment: u32,
    /// Whether payloads are ciphertext.
    pub encrypted: bool,
    /// When the file was opened, in Unix microseconds.
    pub opened_micros: u64,
}

impl Header {
    /// A version-1 header.
    #[must_use]
    pub fn new(recording: &str, namespace: Vec<String>, track: &str) -> Self {
        Self {
            format: "moqom-archive".to_owned(),
            version: 1,
            recording: recording.to_owned(),
            namespace,
            track: track.to_owned(),
            attempt: 1,
            segment: 1,
            encrypted: false,
            opened_micros: 0,
        }
    }
}

/// One object, as archived.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Archived {
    /// Group ID.
    pub group: u64,
    /// Object ID within the group.
    pub object: u64,
    /// When the recorder received it, Unix microseconds.
    pub received_micros: u64,
    /// What the publisher said about it.
    pub properties: ObjectProperties,
    /// The payload, untouched.
    pub payload: Bytes,
}

/// One record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Record {
    /// An object.
    Object(Archived),
    /// A subscription began. Objects after this came on a new subscription,
    /// so a gap in IDs straddling one is a reconnect rather than loss on a
    /// live path.
    Session {
        /// Counts from 1 across the recorder's attempt, so a file opened
        /// mid-attempt starts with the ordinal of the session it opened in.
        ordinal: u32,
        /// Unix microseconds.
        at_micros: u64,
    },
    /// The publisher stopped publishing this namespace.
    Departed {
        /// Unix microseconds.
        at_micros: u64,
    },
    /// The file was finalised.
    End {
        /// Objects in this file.
        objects: u64,
        /// Payload bytes in this file.
        payload_bytes: u64,
        /// Unix microseconds.
        at_micros: u64,
    },
}

/// Writes one archive file.
pub struct Writer<W: Write> {
    inner: W,
    file_crc: Crc32c,
    bytes: u64,
    objects: u64,
    payload_bytes: u64,
    scratch: BytesMut,
}

impl<W: Write> Writer<W> {
    /// Start a file, writing the magic and the header.
    ///
    /// # Errors
    /// The underlying write.
    pub fn create(inner: W, header: &Header) -> io::Result<Self> {
        let mut writer = Self {
            inner,
            file_crc: Crc32c::new(),
            bytes: 0,
            objects: 0,
            payload_bytes: 0,
            scratch: BytesMut::new(),
        };
        let json = serde_json::to_vec(header).map_err(io::Error::other)?;
        let mut head = BytesMut::with_capacity(MAGIC.len() + 8 + json.len());
        head.put_slice(MAGIC);
        head.put_u32(length(json.len())?);
        head.put_slice(&json);
        head.put_u32(checksum(&json));
        writer.emit(&head)?;
        Ok(writer)
    }

    /// Append an object.
    ///
    /// # Errors
    /// The underlying write, or an object larger than [`MAX_RECORD`].
    pub fn object(&mut self, object: &Archived) -> io::Result<()> {
        let mut properties = BytesMut::new();
        object.properties.to_wire().encode(&mut properties);

        let mut body = std::mem::take(&mut self.scratch);
        body.clear();
        body.put_u64(object.group);
        body.put_u64(object.object);
        body.put_u64(object.received_micros);
        body.put_u32(length(properties.len())?);
        body.put_slice(&properties);
        body.put_slice(&object.payload);
        self.record(OBJECT, &body)?;
        self.scratch = body;

        self.objects += 1;
        self.payload_bytes += object.payload.len() as u64;
        Ok(())
    }

    /// Mark the start of a subscription.
    ///
    /// # Errors
    /// The underlying write.
    pub fn session(&mut self, ordinal: u32, at_micros: u64) -> io::Result<()> {
        let mut body = [0u8; 12];
        body[..4].copy_from_slice(&ordinal.to_be_bytes());
        body[4..].copy_from_slice(&at_micros.to_be_bytes());
        self.record(SESSION, &body)
    }

    /// Mark the publisher leaving.
    ///
    /// # Errors
    /// The underlying write.
    pub fn departed(&mut self, at_micros: u64) -> io::Result<()> {
        self.record(DEPARTED, &at_micros.to_be_bytes())
    }

    /// Write the end record and hand back the sink, flushed.
    ///
    /// # Errors
    /// The underlying write or flush.
    pub fn finish(mut self, at_micros: u64) -> io::Result<Finished<W>> {
        let mut body = [0u8; 24];
        body[..8].copy_from_slice(&self.objects.to_be_bytes());
        body[8..16].copy_from_slice(&self.payload_bytes.to_be_bytes());
        body[16..].copy_from_slice(&at_micros.to_be_bytes());
        self.record(END, &body)?;
        self.inner.flush()?;
        Ok(Finished {
            inner: self.inner,
            bytes: self.bytes,
            objects: self.objects,
            crc32c: self.file_crc.value(),
        })
    }

    /// Bytes written so far, header included.
    #[must_use]
    pub const fn bytes(&self) -> u64 {
        self.bytes
    }

    /// Objects written so far.
    #[must_use]
    pub const fn objects(&self) -> u64 {
        self.objects
    }

    /// Flush buffered bytes to the sink.
    ///
    /// # Errors
    /// The underlying flush.
    pub fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }

    fn record(&mut self, kind: u8, body: &[u8]) -> io::Result<()> {
        if body.len() > MAX_RECORD {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("a {}-byte record is over the archive's limit", body.len()),
            ));
        }
        let mut frame = [0u8; 5];
        frame[0] = kind;
        frame[1..].copy_from_slice(&length(body.len())?.to_be_bytes());
        let mut crc = Crc32c::new();
        crc.update(&frame);
        crc.update(body);
        self.emit(&frame)?;
        self.emit(body)?;
        self.emit(&crc.value().to_be_bytes())
    }

    fn emit(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.inner.write_all(bytes)?;
        self.file_crc.update(bytes);
        self.bytes += bytes.len() as u64;
        Ok(())
    }
}

/// A finalised file.
pub struct Finished<W> {
    /// The sink, flushed.
    pub inner: W,
    /// Its length.
    pub bytes: u64,
    /// Objects in it.
    pub objects: u64,
    /// CRC32C of the whole file, which the object store verifies on upload.
    pub crc32c: u32,
}

fn length(len: usize) -> io::Result<u32> {
    u32::try_from(len).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "record too long"))
}

/// Why an archive could not be read further.
#[derive(Debug, thiserror::Error)]
pub enum ReadError {
    /// Not an archive.
    #[error("not a MOQOM archive")]
    NotAnArchive,
    /// A record's checksum does not match.
    #[error("record {0} is corrupt")]
    Corrupt(u64),
    /// The file ends inside a record, which is what a crash leaves.
    #[error("the file ends inside record {0}")]
    Truncated(u64),
    /// A record that cannot be decoded.
    #[error("record {0} is malformed")]
    Malformed(u64),
    /// The underlying read.
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// Reads an archive file.
pub struct Reader<R: Read> {
    inner: R,
    header: Header,
    index: u64,
    ended: bool,
}

impl<R: Read> Reader<R> {
    /// Open a file, reading and checking its header.
    ///
    /// # Errors
    /// [`ReadError`] for anything that is not a well-formed archive start.
    pub fn open(mut inner: R) -> Result<Self, ReadError> {
        let mut magic = [0u8; 8];
        inner
            .read_exact(&mut magic)
            .map_err(|_| ReadError::NotAnArchive)?;
        if &magic != MAGIC {
            return Err(ReadError::NotAnArchive);
        }
        let len = read_u32(&mut inner).map_err(|_| ReadError::NotAnArchive)? as usize;
        if len > MAX_RECORD {
            return Err(ReadError::NotAnArchive);
        }
        let mut json = vec![0u8; len];
        inner
            .read_exact(&mut json)
            .map_err(|_| ReadError::NotAnArchive)?;
        let crc = read_u32(&mut inner).map_err(|_| ReadError::NotAnArchive)?;
        if crc != checksum(&json) {
            return Err(ReadError::NotAnArchive);
        }
        let header = serde_json::from_slice(&json).map_err(|_| ReadError::NotAnArchive)?;
        Ok(Self {
            inner,
            header,
            index: 0,
            ended: false,
        })
    }

    /// The file's header.
    #[must_use]
    pub const fn header(&self) -> &Header {
        &self.header
    }

    /// The next record, or `None` at a clean end of file.
    ///
    /// # Errors
    /// [`ReadError`]; a torn final record is [`ReadError::Truncated`].
    pub fn next_record(&mut self) -> Result<Option<Record>, ReadError> {
        if self.ended {
            return Ok(None);
        }
        let index = self.index;
        let mut frame = [0u8; 5];
        match read_full(&mut self.inner, &mut frame)? {
            0 => return Ok(None),
            5 => {}
            _ => return Err(ReadError::Truncated(index)),
        }
        let len = u32::from_be_bytes([frame[1], frame[2], frame[3], frame[4]]) as usize;
        if len > MAX_RECORD {
            return Err(ReadError::Corrupt(index));
        }
        let mut body = vec![0u8; len];
        if read_full(&mut self.inner, &mut body)? != len {
            return Err(ReadError::Truncated(index));
        }
        let mut crc_bytes = [0u8; 4];
        if read_full(&mut self.inner, &mut crc_bytes)? != 4 {
            return Err(ReadError::Truncated(index));
        }
        let mut crc = Crc32c::new();
        crc.update(&frame);
        crc.update(&body);
        if crc.value() != u32::from_be_bytes(crc_bytes) {
            return Err(ReadError::Corrupt(index));
        }
        self.index += 1;
        let record = decode(frame[0], Bytes::from(body)).ok_or(ReadError::Malformed(index))?;
        if matches!(record, Record::End { .. }) {
            self.ended = true;
        }
        Ok(Some(record))
    }
}

fn decode(kind: u8, mut body: Bytes) -> Option<Record> {
    match kind {
        OBJECT => {
            if body.remaining() < 28 {
                return None;
            }
            let group = body.get_u64();
            let object = body.get_u64();
            let received_micros = body.get_u64();
            let plen = body.get_u32() as usize;
            if body.remaining() < plen {
                return None;
            }
            let mut properties = body.split_to(plen);
            let properties = Properties::decode(&mut properties, plen).ok()?;
            Some(Record::Object(Archived {
                group,
                object,
                received_micros,
                properties: ObjectProperties::from_wire(&properties),
                payload: body,
            }))
        }
        SESSION if body.remaining() == 12 => Some(Record::Session {
            ordinal: body.get_u32(),
            at_micros: body.get_u64(),
        }),
        DEPARTED if body.remaining() == 8 => Some(Record::Departed {
            at_micros: body.get_u64(),
        }),
        END if body.remaining() == 24 => Some(Record::End {
            objects: body.get_u64(),
            payload_bytes: body.get_u64(),
            at_micros: body.get_u64(),
        }),
        _ => None,
    }
}

fn read_u32<R: Read>(inner: &mut R) -> io::Result<u32> {
    let mut bytes = [0u8; 4];
    inner.read_exact(&mut bytes)?;
    Ok(u32::from_be_bytes(bytes))
}

/// Read until `buf` is full or the source ends, returning how much was read.
fn read_full<R: Read>(inner: &mut R, buf: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match inner.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(filled)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header() -> Header {
        let mut header = Header::new(
            "rec-1",
            vec![
                "acme".into(),
                "r".into(),
                "room-42".into(),
                "ada".into(),
                "dev".into(),
            ],
            "video/720p",
        );
        header.encrypted = true;
        header.opened_micros = 1_000;
        header
    }

    fn object(group: u64, object: u64, payload: &'static [u8]) -> Archived {
        Archived {
            group,
            object,
            received_micros: 2_000 + object,
            properties: ObjectProperties::default().captured_at_micros(1_500 + object),
            payload: Bytes::from_static(payload),
        }
    }

    fn written() -> (Vec<u8>, u32) {
        let mut writer = Writer::create(Vec::new(), &header()).expect("a header");
        writer.session(1, 1_900).expect("a session");
        writer
            .object(&object(4, 0, b"keyframe"))
            .expect("an object");
        writer
            .object(&Archived {
                properties: ObjectProperties::default()
                    .captured_at_micros(1_501)
                    .opening(Bytes::from_static(b"\0\0\0\x02ps")),
                ..object(4, 1, b"")
            })
            .expect("an empty object");
        writer.departed(3_000).expect("a departure");
        let finished = writer.finish(3_100).expect("finished");
        assert_eq!(finished.objects, 2);
        assert_eq!(finished.bytes, finished.inner.len() as u64);
        (finished.inner, finished.crc32c)
    }

    #[test]
    fn everything_written_reads_back() {
        let (bytes, crc) = written();
        assert_eq!(crc, checksum(&bytes), "the file checksum covers every byte");

        let mut reader = Reader::open(bytes.as_slice()).expect("an archive");
        assert_eq!(reader.header(), &header());
        let mut records = Vec::new();
        while let Some(record) = reader.next_record().expect("a record") {
            records.push(record);
        }
        assert_eq!(records.len(), 5);
        assert_eq!(
            records[0],
            Record::Session {
                ordinal: 1,
                at_micros: 1_900
            }
        );
        assert_eq!(records[1], Record::Object(object(4, 0, b"keyframe")));
        let Record::Object(second) = &records[2] else {
            panic!("an object")
        };
        assert!(
            second.payload.is_empty(),
            "an empty payload is a legal object"
        );
        assert_eq!(
            second.properties.configuration.as_deref(),
            Some(&b"\0\0\0\x02ps"[..])
        );
        assert_eq!(records[3], Record::Departed { at_micros: 3_000 });
        assert_eq!(
            records[4],
            Record::End {
                objects: 2,
                payload_bytes: 8,
                at_micros: 3_100
            }
        );
    }

    /// What a crash leaves: every whole record before the tear still reads.
    #[test]
    fn a_torn_file_keeps_what_came_before() {
        let (bytes, _) = written();
        let torn = &bytes[..bytes.len() - 10];
        let mut reader = Reader::open(torn).expect("an archive");
        let mut good = 0;
        let failure = loop {
            match reader.next_record() {
                Ok(Some(_)) => good += 1,
                Ok(None) => panic!("a torn file must not read as complete"),
                Err(error) => break error,
            }
        };
        assert_eq!(good, 4);
        assert!(matches!(failure, ReadError::Truncated(4)), "{failure}");
    }

    #[test]
    fn a_flipped_bit_is_caught() {
        let (mut bytes, _) = written();
        let at = bytes.len() - 40;
        bytes[at] ^= 0x10;
        let mut reader = Reader::open(bytes.as_slice()).expect("an archive");
        let mut failure = None;
        while failure.is_none() {
            match reader.next_record() {
                Ok(Some(_)) => {}
                Ok(None) => break,
                Err(error) => failure = Some(error),
            }
        }
        assert!(
            matches!(failure, Some(ReadError::Corrupt(_))),
            "{failure:?}"
        );
    }

    #[test]
    fn other_bytes_are_not_an_archive() {
        assert!(matches!(
            Reader::open(&b"ftypisom........"[..]),
            Err(ReadError::NotAnArchive)
        ));
    }
}
