//! A stream of control frames, which is what a session actually sees.
//!
//! The `decoders` target runs every type against the same bytes, which is broad
//! but does not model a peer. This one reads frames back to back until the
//! input is exhausted, so it explores the state that matters in practice: a
//! decoder that consumes the wrong number of bytes desynchronises everything
//! after it, and only a multi-message target can catch that.
//!
//! It also exercises the layering rule that a body is parsed only from a
//! complete, delimited frame — the assumption
//! `DecodeError::in_complete_message` depends on.

#![no_main]

use libfuzzer_sys::fuzz_target;
use moqom_proto::control::{ControlFrame, MessageType};
use moqom_proto::testing::assert_decoder_contract;

fuzz_target!(|data: &[u8]| {
    let mut cursor = data;
    let mut previous = cursor.len();

    while let Ok(frame) = ControlFrame::decode(&mut cursor) {
        assert!(
            cursor.len() < previous,
            "frame decode made no progress, which would spin a session forever"
        );
        previous = cursor.len();

        // The body is complete by construction here, so every body decoder gets
        // input it is actually entitled to assume.
        let body = frame.body.as_ref();
        match frame.message_type {
            MessageType::Setup => assert_decoder_contract::<moqom_proto::control::Setup>(body),
            MessageType::Goaway => assert_decoder_contract::<moqom_proto::control::Goaway>(body),
            MessageType::Subscribe => {
                assert_decoder_contract::<moqom_proto::control::Subscribe>(body);
            }
            MessageType::SubscribeOk => {
                assert_decoder_contract::<moqom_proto::control::SubscribeOk>(body);
            }
            MessageType::RequestOk => {
                assert_decoder_contract::<moqom_proto::control::RequestOk>(body);
            }
            MessageType::RequestError => {
                assert_decoder_contract::<moqom_proto::control::RequestError>(body);
            }
            _ => {}
        }
    }
});
