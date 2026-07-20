#![no_main]
use libfuzzer_sys::fuzz_target;
use digg::protocol::record::ResourceRecord;

fuzz_target!(|data: &[u8]| {
    let _ = ResourceRecord::decode(data, 0);
});
