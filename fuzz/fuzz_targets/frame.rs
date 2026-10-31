#![no_main]

use bibavpn::frame::{
    read_padded_frame, read_padded_frame_borrow, read_padded_frame_bytes, read_padded_frame_into,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let borrowed = read_padded_frame_borrow(data).ok();
    assert_eq!(read_padded_frame(data).ok().as_deref(), borrowed);
    assert_eq!(
        read_padded_frame_into(data.to_vec()).ok().as_deref(),
        borrowed
    );
    assert_eq!(
        read_padded_frame_bytes(bytes::Bytes::copy_from_slice(data))
            .ok()
            .as_deref(),
        borrowed
    );
});
