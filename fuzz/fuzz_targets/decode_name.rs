#![no_main]
use libfuzzer_sys::fuzz_target;
use digg::protocol::name::decode_name;

// Exercise the compression-pointer name decoder at a spread of offsets.
fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let offset = (data[0] as usize) % data.len();
    let _ = decode_name(data, offset);
});
