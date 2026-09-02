#![no_main]
#![forbid(unsafe_code)]

use futures_executor::block_on;
use libfuzzer_sys::fuzz_target;
use serctl_transfer_protocol::{
    read_frame, FrameKind, MAGIC, MAX_CHUNK_BYTES, MAX_CONTROL_BYTES, VERSION,
};
use sha2::{Digest, Sha256};

fn parse(bytes: &[u8]) {
    let mut input = bytes;
    let _ = block_on(read_frame(&mut input));
}

fuzz_target!(|data: &[u8]| {
    // Exercise the complete header parser with the fuzzer's raw bytes.
    parse(data);

    // Also force arbitrary bounded bytes through both production body parsers.
    // Raw mutations otherwise spend most cycles rediscovering the fixed
    // header, and almost never produce a Data frame with a valid chunk hash.
    if let Some((&selector, payload)) = data.split_first() {
        if selector & 1 == 0 && payload.len() <= MAX_CONTROL_BYTES {
            let mut framed = Vec::with_capacity(12 + payload.len());
            framed.extend_from_slice(&MAGIC);
            framed.extend_from_slice(&VERSION.to_be_bytes());
            framed.push(FrameKind::Control as u8);
            framed.push(0);
            framed.extend_from_slice(&(payload.len() as u32).to_be_bytes());
            framed.extend_from_slice(payload);
            parse(&framed);
        } else if !payload.is_empty() && payload.len() <= MAX_CHUNK_BYTES {
            let mut framed = Vec::with_capacity(12 + 56 + payload.len());
            framed.extend_from_slice(&MAGIC);
            framed.extend_from_slice(&VERSION.to_be_bytes());
            framed.push(FrameKind::Data as u8);
            framed.push(0);
            framed.extend_from_slice(&((56 + payload.len()) as u32).to_be_bytes());
            framed.extend_from_slice(&[0_u8; 16]);
            framed.extend_from_slice(&0_u64.to_be_bytes());
            framed.extend_from_slice(&Sha256::digest(payload));
            framed.extend_from_slice(payload);
            parse(&framed);
        }
    } else {
        // Retain a well-formed empty control frame in the seedless case.
        let mut framed = Vec::with_capacity(12 + data.len());
        framed.extend_from_slice(&MAGIC);
        framed.extend_from_slice(&VERSION.to_be_bytes());
        framed.push(FrameKind::Control as u8);
        framed.push(0);
        framed.extend_from_slice(&(data.len() as u32).to_be_bytes());
        framed.extend_from_slice(data);
        parse(&framed);
    }
});
