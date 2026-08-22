//! Turning coded video into the objects MOQOM publishes.
//!
//! Framing only: what a frame is, where it begins, whether it can be decoded on
//! its own, and what a decoder needs configured before it can try. Nothing here
//! decodes, and nothing here speaks MOQT — which is why it can be shared by the
//! `moqom` binary that publishes a file and the load generator that measures a
//! relay with one, without either of them linking the other.
//!
//! It exists as its own crate for that second reason. A capacity number taken
//! with synthetic frames of a constant size measures something a real stream
//! does not do: real video arrives in bursts, a keyframe is an order of
//! magnitude larger than the frames after it, and a group boundary falls where
//! the encoder put one rather than on a round count. Measuring with the same
//! parser the product ships is the only way the number transfers.

pub mod annexb;
