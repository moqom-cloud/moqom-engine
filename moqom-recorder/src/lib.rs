//! The hosted MOQOM recorder.
//!
//! A recorder is a viewer. It joins a room with a subscribe-only token bound to
//! its own key, follows the room's namespace for publishers arriving and
//! leaving, reads each publisher's catalog, and subscribes to every track the
//! catalog lists. What it receives it writes down; it never publishes, so the
//! people in the room cannot see it on the wire. They are told about it
//! instead, by the recording watchdog the control plane attaches to the room
//! before a recorder is assigned.
//!
//! Two kinds of output:
//!
//! - **The archive** ([`archive`]), always. Every object exactly as it arrived
//!   -- payload, group and object IDs, wire properties, arrival time -- with
//!   markers where the recorder reconnected or the publisher left. It is the
//!   lossless record, and in an end-to-end encrypted room it is the only one:
//!   the recorder holds no media key, so it stores ciphertext a participant's
//!   key can open later and nothing else can.
//! - **CMAF** ([`fmp4`]), for rooms that are not encrypted, when the codec can
//!   be carried without transcoding: H.264, HEVC, Opus.
//!
//! Files are spooled locally and handed to a [`store::Store`] once finished.

pub mod archive;
pub mod catalog;
pub mod crc32c;
pub mod fmp4;
pub mod generated;
pub mod http;
pub mod link;
pub mod manifest;
pub mod recorder;
pub mod store;
pub mod track;

pub use recorder::{Recorder, RecorderConfig, Summary};
