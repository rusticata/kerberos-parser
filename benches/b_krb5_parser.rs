#![feature(test)]

extern crate test;
use test::Bencher;

extern crate kerberos_parser;
extern crate nom;

use kerberos_parser::krb5_parser::*;

static KRB5_TICKET: &[u8] = include_bytes!("../assets/krb5-ticket.bin");

#[bench]
fn bench_parse_ticket(b: &mut Bencher) {
    b.iter(|| {
        let res = parse_krb5_ticket(KRB5_TICKET);
        match res {
            Ok((rem, tkt)) => {
                assert!(rem.is_empty());
                assert_eq!(tkt.tkt_vno, 5);
            }
            _ => assert!(false),
        }
    });
}
