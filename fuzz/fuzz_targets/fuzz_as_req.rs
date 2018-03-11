#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate kerberos_parser;

use kerberos_parser::krb5_parser::parse_as_req;

fuzz_target!(|data: &[u8]| {
    let _ = parse_as_req(data);
});
