extern crate nom;
extern crate kerberos_parser;

use nom::IResult;
use kerberos_parser::krb5::*;
use kerberos_parser::krb5_parser::*;

#[test]
fn test_parse_kerberos_string() {
    let bytes = &[0x1b, 0x04, 0x63, 0x69, 0x66, 0x73];
    let empty = &b""[..];
    let expected = IResult::Done(empty,Realm(String::from("cifs")));

    let res = parse_krb5_realm(bytes);
    assert_eq!(res,expected);
}

#[test]
fn test_parse_realm() {
    let bytes = &[0x1b, 0x05, 0x4a, 0x6f, 0x6e, 0x65, 0x73];
    let empty = &b""[..];
    let expected = IResult::Done(empty,Realm(String::from("Jones")));

    let res = parse_krb5_realm(bytes);
    assert_eq!(res,expected);
}

#[test]
fn test_parse_principalname() {
    let bytes = &[
        0x30, 0x81, 0x11,
            0xa0, 0x03, 0x02, 0x01, 0x00,
            0xa1, 0x0a, 0x30, 0x81, 0x07, 0x1b, 0x05, 0x4a, 0x6f, 0x6e, 0x65, 0x73
    ];
    let empty = &b""[..];
    let expected = IResult::Done(empty,PrincipalName{
        name_type: 0,
        name_string: vec![String::from("Jones")]
    });

    let res = parse_krb5_principalname(bytes);
    assert_eq!(res,expected);
}

#[test]
fn test_parse_principalname2() {
    let bytes = &[
        0x30, 0x27,
        0xa0, 0x03, 0x02, 0x01, 0x02,
        0xa1, 0x20, 0x30, 0x1e,
            0x1b, 0x04, 0x63, 0x69, 0x66, 0x73,
            0x1b, 0x16, 0x41, 0x64, 0x6d, 0x69, 0x6e, 0x2d, 0x50, 0x43, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x6f, 0x73, 0x6f, 0x2e, 0x6c, 0x6f, 0x63, 0x61, 0x6c,
    ];
    let empty = &b""[..];
    let expected = IResult::Done(empty,PrincipalName{
        name_type: 2,
        name_string: vec![String::from("cifs"),String::from("Admin-PC.contoso.local")]
    });

    let res = parse_krb5_principalname(bytes);
    assert_eq!(res,expected);
}

static KRB5_TICKET: &'static [u8] = include_bytes!("../assets/krb5-ticket.bin");
#[test]
fn test_parse_ticket() {
    let bytes = KRB5_TICKET;

    let res = parse_krb5_ticket(bytes);
    // println!("parse_krb5_ticket: {:?}", res);
    match res {
        IResult::Done(rem,tkt) => {
            assert!(rem.is_empty());
            assert_eq!(tkt.tkt_vno, 5);
            assert_eq!(tkt.realm, Realm(String::from("CONTOSO.LOCAL")));
            assert_eq!(tkt.sname, PrincipalName{ name_type:2, name_string:vec![String::from("cifs"),String::from("Admin-PC.contoso.local")] });
            let enc = parse_encrypted(tkt.enc_part).unwrap().1;
            // println!("enc: {:?}", enc);
            assert_eq!(enc.etype,18);
            assert_eq!(enc.kvno,Some(1));
        },
        _ => assert!(false)
    }
}

static AS_REQ: &'static [u8] = include_bytes!("../assets/as-req.bin");
#[test]
fn test_parse_as_req() {
    let bytes = AS_REQ;

    let res = parse_as_req(bytes);
    // println!("parse_as_req: {:?}", res);
    match res {
        IResult::Done(rem,req) => {
            assert!(rem.is_empty());
            assert_eq!(req.pvno, 5);
            assert_eq!(req.msg_type, 10);
            assert_eq!(req.req_body.realm, Realm(String::from("DENYDC")));
            assert_eq!(req.req_body.cname,
                       Some(PrincipalName{ name_type:1, name_string:vec![String::from("des")] }));
            assert_eq!(req.req_body.sname,
                       Some(PrincipalName{ name_type:2, name_string:vec![String::from("krbtgt"),String::from("DENYDC")] }));
        },
        _ => assert!(false)
    }
}

