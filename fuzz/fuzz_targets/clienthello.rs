#![no_main]

use biba::client_hello_spec_from_tls_record;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = client_hello_spec_from_tls_record(data, false, false);
    let _ = client_hello_spec_from_tls_record(data, true, false);
});
