#![no_main]
use libfuzzer_sys::fuzz_target;
use digg::protocol::message::DnsMessage;

// The top-level entry point: any byte string must parse to Ok or Err, never panic.
fuzz_target!(|data: &[u8]| {
    let _ = DnsMessage::parse(data);
});
