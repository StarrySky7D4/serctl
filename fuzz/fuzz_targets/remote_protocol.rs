#![no_main]
#![forbid(unsafe_code)]

use libfuzzer_sys::fuzz_target;
use serctl_remote_protocol::{
    decode_exact, read_frame_from, FrameKind, HEADER_BYTES, MAGIC, MAX_FRAME_PAYLOAD,
    PROTOCOL_VERSION,
};
use std::io::Cursor;

fn parse(bytes: &[u8]) {
    let _ = decode_exact(bytes);
    let _ = read_frame_from(&mut Cursor::new(bytes));
}

fuzz_target!(|data: &[u8]| {
    // Cover the physical frame boundary and streaming reader directly.
    parse(data);

    // Use the first byte as a frame-kind selector and put the remaining bytes
    // behind a valid bounded header. This retains arbitrary raw-header
    // coverage while driving every kind-specific payload decoder deeply.
    if let Some((&selector, payload)) = data.split_first() {
        if payload.len() <= MAX_FRAME_PAYLOAD {
            let kinds = [
                FrameKind::Hello,
                FrameKind::Start,
                FrameKind::Stdout,
                FrameKind::Stderr,
                FrameKind::Heartbeat,
                FrameKind::Cancel,
                FrameKind::Exit,
                FrameKind::Receipt,
                FrameKind::Error,
                FrameKind::QueryReceipt,
            ];
            let kind = kinds[usize::from(selector) % kinds.len()];
            let mut framed = Vec::with_capacity(HEADER_BYTES + payload.len());
            framed.extend_from_slice(&MAGIC);
            framed.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
            framed.push(kind as u8);
            framed.push(0);
            framed.extend_from_slice(&0_u64.to_be_bytes());
            framed.extend_from_slice(&(payload.len() as u32).to_be_bytes());
            framed.extend_from_slice(payload);
            parse(&framed);
        }
    }
});
