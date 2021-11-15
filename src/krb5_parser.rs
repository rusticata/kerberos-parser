//! Kerberos 5 parsing functions

use der_parser::ber::*;
use der_parser::der::*;
use der_parser::error::*;
use nom::combinator::{complete, map, map_res, opt, verify};
use nom::error::{make_error, ErrorKind};
use nom::multi::many1;
use nom::{Err, IResult};
use std::str;

use crate::krb5::*;

/// Parse a signed 32 bits integer
///
/// <pre>
/// Int32           ::= INTEGER (-2147483648..2147483647)
///                     -- signed values representable in 32 bits
/// </pre>
pub fn parse_der_int32(i: &[u8]) -> IResult<&[u8], i32, BerError> {
    map_res(parse_der_integer, |x: DerObject| match x.content {
        BerObjectContent::Integer(i) => match i.len() {
            1 => Ok(i[0] as i8 as i32),
            2 => Ok((i[0] as i8 as i32) << 8 | (i[1] as i32)),
            3 => Ok((i[0] as i8 as i32) << 16 | (i[1] as i32) << 8 | (i[2] as i32)),
            4 => Ok((i[0] as i8 as i32) << 24
                | (i[1] as i32) << 16
                | (i[2] as i32) << 8
                | (i[3] as i32)),
            _ => Err(BerError::IntegerTooLarge),
        },
        _ => Err(BerError::BerTypeError),
    })(i)
}

//  Microseconds    ::= INTEGER (0..999999)
//                      -- microseconds
fn parse_der_microseconds(i: &[u8]) -> IResult<&[u8], u32, BerError> {
    verify(parse_der_u32, |x: &u32| *x <= 999_999)(i)
}

/// Parse a Kerberos string object
///
/// <pre>
/// KerberosString  ::= GeneralString (IA5String)
/// </pre>
pub fn parse_kerberos_string(i: &[u8]) -> IResult<&[u8], String, BerError> {
    match parse_der_generalstring(i) {
        Ok((rem, ref obj)) => {
            if let BerObjectContent::GeneralString(s) = obj.content {
                match str::from_utf8(s) {
                    Ok(r) => Ok((rem, r.to_owned())),
                    Err(_) => Err(Err::Error(make_error(i, ErrorKind::IsNot))),
                }
            } else {
                Err(Err::Error(make_error(i, ErrorKind::Tag)))
            }
        }
        Err(e) => Err(e),
    }
}

fn parse_kerberos_string_sequence(i: &[u8]) -> IResult<&[u8], Vec<String>, BerError> {
    parse_ber_sequence_of_v(parse_kerberos_string)(i)
}

/// Parse Kerberos flags
///
/// <pre>
/// KerberosFlags   ::= BIT STRING (SIZE (32..MAX))
///                     -- minimum number of bits shall be sent,
///                     -- but no fewer than 32
/// </pre>
#[inline]
pub fn parse_kerberos_flags(i: &[u8]) -> IResult<&[u8], DerObject, BerError> {
    parse_der_bitstring(i)
}

/// Parse of a Kerberos Realm
///
/// <pre>
/// Realm           ::= KerberosString
/// </pre>
#[inline]
pub fn parse_krb5_realm(i: &[u8]) -> IResult<&[u8], Realm, BerError> {
    map(parse_kerberos_string, Realm)(i)
}

/// Parse Kerberos PrincipalName
///
/// <pre>
/// PrincipalName   ::= SEQUENCE {
///         name-type       [0] Int32,
///         name-string     [1] SEQUENCE OF KerberosString
/// }
/// </pre>
pub fn parse_krb5_principalname(i: &[u8]) -> IResult<&[u8], PrincipalName, BerError> {
    parse_ber_sequence_defined_g(|i, _| {
        let (i, name_type) =
            parse_ber_tagged_explicit_g(0, |a, _| map(parse_der_int32, NameType)(a))(i)?;
        let (i, name_string) =
            parse_ber_tagged_explicit_g(1, |a, _| parse_kerberos_string_sequence(a))(i)?;
        Ok((
            i,
            PrincipalName {
                name_type,
                name_string,
            },
        ))
    })(i)
}

/// Parse of a Kerberos Time
///
/// <pre>
/// KerberosTime    ::= GeneralizedTime -- with no fractional seconds
/// </pre>
#[inline]
pub fn parse_kerberos_time(i: &[u8]) -> IResult<&[u8], DerObject, BerError> {
    parse_der_generalizedtime(i)
}

/// Parse Kerberos HostAddress
///
/// <pre>
/// HostAddress     ::= SEQUENCE  {
///         addr-type       [0] Int32,
///         address         [1] OCTET STRING
/// }
/// </pre>
pub fn parse_krb5_hostaddress(i: &[u8]) -> IResult<&[u8], HostAddress, BerError> {
    parse_ber_sequence_defined_g(|i, _| {
        let (i, addr_type) =
            parse_ber_tagged_explicit_g(0, |a, _| map(parse_der_int32, AddressType)(a))(i)?;
        let (i, address) = parse_ber_tagged_explicit_g(1, |a, _| {
            map_res(parse_ber_octetstring, |o| o.as_slice())(a)
        })(i)?;
        Ok((i, HostAddress { addr_type, address }))
    })(i)
}

/// Parse Kerberos HostAddresses
///
/// <pre>
/// -- NOTE: HostAddresses is always used as an OPTIONAL field and
/// -- should not be empty.
/// HostAddresses   -- NOTE: subtly different from rfc1510,
///                 -- but has a value mapping and encodes the same
///         ::= SEQUENCE OF HostAddress
/// </pre>
pub fn parse_krb5_hostaddresses(i: &[u8]) -> IResult<&[u8], Vec<HostAddress>, BerError> {
    parse_ber_sequence_of_v(parse_krb5_hostaddress)(i)
}

/// Parse Kerberos Ticket
///
/// <pre>
/// Ticket          ::= [APPLICATION 1] SEQUENCE {
///         tkt-vno         [0] INTEGER (5),
///         realm           [1] Realm,
///         sname           [2] PrincipalName,
///         enc-part        [3] EncryptedData -- EncTicketPart
/// }
/// </pre>
pub fn parse_krb5_ticket(i: &[u8]) -> IResult<&[u8], Ticket, BerError> {
    parse_ber_tagged_explicit_g(BerTag(1), |i, hdr| {
        if !hdr.is_application() {
            return Err(Err::Error(BerError::InvalidTag));
        }
        parse_ber_sequence_defined_g(|i, _| {
            let (i, tkt_vno) = parse_ber_tagged_explicit_g(0, |a, _| parse_der_u32(a))(i)?;
            if tkt_vno != 5 {
                return Err(Err::Error(BerError::Custom(5)));
            }
            let (i, realm) = parse_ber_tagged_explicit_g(1, |a, _| parse_krb5_realm(a))(i)?;
            let (i, sname) = parse_ber_tagged_explicit_g(2, |a, _| parse_krb5_principalname(a))(i)?;
            let (i, enc_part) = parse_ber_tagged_explicit_g(3, |a, _| parse_encrypted(a))(i)?;
            let tkt = Ticket {
                tkt_vno,
                realm,
                sname,
                enc_part,
            };
            Ok((i, tkt))
        })(i)
    })(i)
}

/// Parse Kerberos EncryptedData
///
/// <pre>
/// EncryptedData   ::= SEQUENCE {
///         etype   [0] Int32 -- EncryptionType --,
///         kvno    [1] UInt32 OPTIONAL,
///         cipher  [2] OCTET STRING -- ciphertext
/// }
/// </pre>
pub fn parse_encrypted(i: &[u8]) -> IResult<&[u8], EncryptedData, BerError> {
    parse_ber_sequence_defined_g(|i, _| {
        let (i, etype) =
            parse_ber_tagged_explicit_g(0, |a, _| map(parse_der_int32, EncryptionType)(a))(i)?;
        let (i, kvno) = opt(complete(parse_ber_tagged_explicit_g(1, |a, _| {
            parse_der_u32(a)
        })))(i)?;
        let (i, cipher) =
            parse_ber_tagged_explicit_g(2, |a, _| map_res(parse_der, |o| o.as_slice())(a))(i)?;
        let enc = EncryptedData {
            etype,
            kvno,
            cipher,
        };
        Ok((i, enc))
    })(i)
}

/// Parse a Kerberos KDC Request
///
/// <pre>
/// KDC-REQ         ::= SEQUENCE {
///         -- NOTE: first tag is [1], not [0]
///         pvno            [1] INTEGER (5) ,
///         msg-type        [2] INTEGER (10 -- AS -- | 12 -- TGS --),
///         padata          [3] SEQUENCE OF PA-DATA OPTIONAL
///                             -- NOTE: not empty --,
///         req-body        [4] KDC-REQ-BODY
/// }
/// </pre>
pub fn parse_kdc_req(i: &[u8]) -> IResult<&[u8], KdcReq, BerError> {
    parse_ber_sequence_defined_g(|i, _| {
        let (i, pvno) = parse_ber_tagged_explicit_g(1, |a, _| parse_der_u32(a))(i)?;
        let (i, msg_type) =
            parse_ber_tagged_explicit_g(2, |a, _| map(parse_der_u32, MessageType)(a))(i)?;
        let (i, padata) = parse_ber_tagged_explicit_g(3, |a, _| parse_krb5_padata_sequence(a))(i)
            .unwrap_or_else(|_| (i, Vec::new()));
        let (i, req_body) = parse_ber_tagged_explicit_g(4, |a, _| parse_kdc_req_body(a))(i)?;
        let req = KdcReq {
            pvno,
            msg_type,
            padata,
            req_body,
        };
        Ok((i, req))
    })(i)
}

/// Parse the body of a Kerberos KDC Request
///
/// <pre>
/// KDC-REQ-BODY    ::= SEQUENCE {
///         kdc-options             [0] KDCOptions,
///         cname                   [1] PrincipalName OPTIONAL
///                                     -- Used only in AS-REQ --,
///         realm                   [2] Realm
///                                     -- Server's realm
///                                     -- Also client's in AS-REQ --,
///         sname                   [3] PrincipalName OPTIONAL,
///         from                    [4] KerberosTime OPTIONAL,
///         till                    [5] KerberosTime,
///         rtime                   [6] KerberosTime OPTIONAL,
///         nonce                   [7] UInt32,
///         etype                   [8] SEQUENCE OF Int32 -- EncryptionType
///                                     -- in preference order --,
///         addresses               [9] HostAddresses OPTIONAL,
///         enc-authorization-data  [10] EncryptedData OPTIONAL
///                                     -- AuthorizationData --,
///         additional-tickets      [11] SEQUENCE OF Ticket OPTIONAL
///                                        -- NOTE: not empty
/// }
/// </pre>
pub fn parse_kdc_req_body(i: &[u8]) -> IResult<&[u8], KdcReqBody, BerError> {
    parse_ber_sequence_defined_g(|i, _| {
        let (i, kdc_options) = parse_ber_tagged_explicit_g(0, |a, _| parse_kerberos_flags(a))(i)?;
        let (i, cname) = opt(complete(parse_ber_tagged_explicit_g(1, |a, _| {
            parse_krb5_principalname(a)
        })))(i)?;
        let (i, realm) = parse_ber_tagged_explicit_g(2, |a, _| parse_krb5_realm(a))(i)?;
        let (i, sname) = opt(complete(parse_ber_tagged_explicit_g(3, |a, _| {
            parse_krb5_principalname(a)
        })))(i)?;
        let (i, from) = opt(complete(parse_ber_tagged_explicit_g(4, |a, _| {
            parse_kerberos_time(a)
        })))(i)?;
        let (i, till) = parse_ber_tagged_explicit_g(5, |a, _| parse_kerberos_time(a))(i)?;
        let (i, rtime) = opt(complete(parse_ber_tagged_explicit_g(6, |a, _| {
            parse_kerberos_time(a)
        })))(i)?;
        let (i, nonce) = parse_ber_tagged_explicit_g(7, |a, _| parse_der_u32(a))(i)?;
        let (i, etype) = parse_ber_tagged_explicit_g(8, |a, _| {
            map(parse_ber_sequence_of_v(parse_der_int32), |v| {
                v.iter().map(|&x| EncryptionType(x)).collect()
            })(a)
        })(i)?;
        let (i, addresses) = opt(complete(parse_ber_tagged_explicit_g(9, |a, _| {
            parse_krb5_hostaddresses(a)
        })))(i)?;
        let addresses = addresses.unwrap_or_default();
        let (i, enc_authorization_data) =
            opt(complete(parse_ber_tagged_explicit_g(10, |a, _| {
                parse_encrypted(a)
            })))(i)?;
        let (i, additional_tickets) = opt(complete(parse_ber_tagged_explicit_g(11, |a, _| {
            many1(complete(parse_krb5_ticket))(a)
        })))(i)?;
        let additional_tickets = additional_tickets.unwrap_or_default();
        let body = KdcReqBody {
            kdc_options,
            cname,
            realm,
            sname,
            from,
            till,
            rtime,
            nonce,
            etype,
            addresses,
            enc_authorization_data,
            additional_tickets,
        };
        Ok((i, body))
    })(i)
}

/// Parse a Kerberos AS Request
///
/// <pre>
/// AS-REQ          ::= [APPLICATION 10] KDC-REQ
/// </pre>
pub fn parse_as_req(i: &[u8]) -> IResult<&[u8], KdcReq, BerError> {
    parse_ber_tagged_explicit_g(BerTag(10), |i, hdr| {
        if !hdr.is_application() {
            return Err(Err::Error(BerError::InvalidTag));
        }
        parse_kdc_req(i)
    })(i)
}

/// Parse a Kerberos TGS Request
///
/// <pre>
/// TGS-REQ          ::= [APPLICATION 12] KDC-REQ
/// </pre>
pub fn parse_tgs_req(i: &[u8]) -> IResult<&[u8], KdcReq, BerError> {
    parse_ber_tagged_explicit_g(BerTag(12), |i, hdr| {
        if !hdr.is_application() {
            return Err(Err::Error(BerError::InvalidTag));
        }
        parse_kdc_req(i)
    })(i)
}

/// Parse a Kerberos KDC Reply
///
/// <pre>
/// KDC-REP         ::= SEQUENCE {
///         pvno            [0] INTEGER (5),
///         msg-type        [1] INTEGER (11 -- AS -- | 13 -- TGS --),
///         padata          [2] SEQUENCE OF PA-DATA OPTIONAL
///                                 -- NOTE: not empty --,
///         crealm          [3] Realm,
///         cname           [4] PrincipalName,
///         ticket          [5] Ticket,
///         enc-part        [6] EncryptedData
///                                 -- EncASRepPart or EncTGSRepPart,
///                                 -- as appropriate
/// }
/// </pre>
pub fn parse_kdc_rep(i: &[u8]) -> IResult<&[u8], KdcRep, BerError> {
    parse_ber_sequence_defined_g(|i, _| {
        let (i, pvno) = parse_ber_tagged_explicit_g(0, |a, _| parse_der_u32(a))(i)?;
        let (i, msg_type) =
            parse_ber_tagged_explicit_g(1, |a, _| map(parse_der_u32, MessageType)(a))(i)?;
        let (i, padata) = parse_ber_tagged_explicit_g(2, |a, _| parse_krb5_padata_sequence(a))(i)
            .unwrap_or_else(|_| (i, Vec::new()));
        let (i, crealm) = parse_ber_tagged_explicit_g(3, |a, _| parse_krb5_realm(a))(i)?;
        let (i, cname) = parse_ber_tagged_explicit_g(4, |a, _| parse_krb5_principalname(a))(i)?;
        let (i, ticket) = parse_ber_tagged_explicit_g(5, |a, _| parse_krb5_ticket(a))(i)?;
        let (i, enc_part) = parse_ber_tagged_explicit_g(6, |a, _| parse_encrypted(a))(i)?;
        let rep = KdcRep {
            pvno,
            msg_type,
            padata,
            crealm,
            cname,
            ticket,
            enc_part,
        };
        Ok((i, rep))
    })(i)
}

/// Parse a Kerberos AS Reply
///
/// <pre>
/// AS-REP          ::= [APPLICATION 11] KDC-REP
/// </pre>
pub fn parse_as_rep(i: &[u8]) -> IResult<&[u8], KdcRep, BerError> {
    parse_ber_tagged_explicit_g(BerTag(11), |i, hdr| {
        if !hdr.is_application() {
            return Err(Err::Error(BerError::InvalidTag));
        }
        parse_kdc_rep(i)
    })(i)
}

/// Parse a Kerberos TGS Reply
///
/// <pre>
/// TGS-REP          ::= [APPLICATION 13] KDC-REP
/// </pre>
pub fn parse_tgs_rep(i: &[u8]) -> IResult<&[u8], KdcRep, BerError> {
    parse_ber_tagged_explicit_g(BerTag(13), |i, hdr| {
        if !hdr.is_application() {
            return Err(Err::Error(BerError::InvalidTag));
        }
        parse_kdc_rep(i)
    })(i)
}

/// Parse a Kerberos Error
///
/// <pre>
/// KRB-ERROR       ::= [APPLICATION 30] SEQUENCE {
///         pvno            [0] INTEGER (5),
///         msg-type        [1] INTEGER (30),
///         ctime           [2] KerberosTime OPTIONAL,
///         cusec           [3] Microseconds OPTIONAL,
///         stime           [4] KerberosTime,
///         susec           [5] Microseconds,
///         error-code      [6] Int32,
///         crealm          [7] Realm OPTIONAL,
///         cname           [8] PrincipalName OPTIONAL,
///         realm           [9] Realm -- service realm --,
///         sname           [10] PrincipalName -- service name --,
///         e-text          [11] KerberosString OPTIONAL,
///         e-data          [12] OCTET STRING OPTIONAL
/// }
/// </pre>
pub fn parse_krb_error(i: &[u8]) -> IResult<&[u8], KrbError, BerError> {
    parse_ber_tagged_explicit_g(BerTag(30), |i, hdr| {
        if !hdr.is_application() {
            return Err(Err::Error(BerError::InvalidTag));
        }
        parse_ber_sequence_defined_g(|i, _| {
            let (i, pvno) = parse_ber_tagged_explicit_g(0, |a, _| parse_der_u32(a))(i)?;
            let (i, msg_type) =
                parse_ber_tagged_explicit_g(1, |a, _| map(parse_der_u32, MessageType)(a))(i)?;
            let (i, ctime) = opt(complete(parse_ber_tagged_explicit_g(2, |a, _| {
                parse_kerberos_time(a)
            })))(i)?;
            let (i, cusec) = opt(complete(parse_ber_tagged_explicit_g(3, |a, _| {
                parse_der_microseconds(a)
            })))(i)?;
            let (i, stime) = parse_ber_tagged_explicit_g(4, |a, _| parse_kerberos_time(a))(i)?;
            let (i, susec) = parse_ber_tagged_explicit_g(5, |a, _| parse_der_microseconds(a))(i)?;
            let (i, error_code) =
                parse_ber_tagged_explicit_g(6, |a, _| map(parse_der_int32, ErrorCode)(a))(i)?;
            let (i, crealm) = opt(complete(parse_ber_tagged_explicit_g(7, |a, _| {
                parse_krb5_realm(a)
            })))(i)?;
            let (i, cname) = opt(complete(parse_ber_tagged_explicit_g(8, |a, _| {
                parse_krb5_principalname(a)
            })))(i)?;
            let (i, realm) = parse_ber_tagged_explicit_g(9, |a, _| parse_krb5_realm(a))(i)?;
            let (i, sname) =
                parse_ber_tagged_explicit_g(10, |a, _| parse_krb5_principalname(a))(i)?;
            let (i, etext) = opt(complete(parse_ber_tagged_explicit_g(11, |a, _| {
                parse_kerberos_string(a)
            })))(i)?;
            let (i, edata) = opt(complete(parse_ber_tagged_explicit_g(12, |a, _| {
                parse_der_octetstring(a)
            })))(i)?;
            let err = KrbError {
                pvno,
                msg_type,
                ctime,
                cusec,
                stime,
                susec,
                error_code,
                crealm,
                cname,
                realm,
                sname,
                etext,
                edata,
            };
            Ok((i, err))
        })(i)
    })(i)
}

/// Parse Kerberos PA-Data
///
/// <pre>
/// PA-DATA         ::= SEQUENCE {
///         -- NOTE: first tag is [1], not [0]
///         padata-type     [1] Int32,
///         padata-value    [2] OCTET STRING -- might be encoded AP-REQ
/// }
/// </pre>
pub fn parse_krb5_padata(i: &[u8]) -> IResult<&[u8], PAData, BerError> {
    parse_ber_sequence_defined_g(|i, _| {
        let (i, padata_type) =
            parse_ber_tagged_explicit_g(1, |a, _| map(parse_der_int32, PAType)(a))(i)?;
        let (i, padata_value) =
            parse_ber_tagged_explicit_g(2, |a, _| map_res(parse_der, |o| o.as_slice())(a))(i)?;
        let padata = PAData {
            padata_type,
            padata_value,
        };
        Ok((i, padata))
    })(i)
}

fn parse_krb5_padata_sequence(i: &[u8]) -> IResult<&[u8], Vec<PAData>, BerError> {
    parse_ber_sequence_of_v(parse_krb5_padata)(i)
}

/// Parse a Kerberos AP Request
///
/// <pre>
/// AP-REQ          ::= [APPLICATION 14] SEQUENCE {
///         pvno            [0] INTEGER (5),
///         msg-type        [1] INTEGER (14),
///         ap-options      [2] APOptions,
///         ticket          [3] Ticket,
///         authenticator   [4] EncryptedData -- Authenticator
/// }
///
/// APOptions       ::= KerberosFlags
///         -- reserved(0),
///         -- use-session-key(1),
///         -- mutual-required(2)
/// </pre>
pub fn parse_ap_req(i: &[u8]) -> IResult<&[u8], ApReq, BerError> {
    parse_ber_tagged_explicit_g(BerTag(14), |i, hdr| {
        if !hdr.is_application() {
            return Err(Err::Error(BerError::InvalidTag));
        }
        parse_ber_sequence_defined_g(|i, _| {
            let (i, pvno) = parse_ber_tagged_explicit_g(0, |a, _| parse_der_u32(a))(i)?;
            let (i, msg_type) =
                parse_ber_tagged_explicit_g(1, |a, _| map(parse_der_u32, MessageType)(a))(i)?;
            let (i, ap_options) =
                parse_ber_tagged_explicit_g(2, |a, _| parse_kerberos_flags(a))(i)?;
            let (i, ticket) = parse_ber_tagged_explicit_g(3, |a, _| parse_krb5_ticket(a))(i)?;
            let (i, authenticator) = parse_ber_tagged_explicit_g(4, |a, _| parse_encrypted(a))(i)?;
            let req = ApReq {
                pvno,
                msg_type,
                ap_options,
                ticket,
                authenticator,
            };
            Ok((i, req))
        })(i)
    })(i)
}

/// Parse a Kerberos AP Reply
///
/// <pre>
/// AP-REP          ::= [APPLICATION 15] SEQUENCE {
///         pvno            [0] INTEGER (5),
///         msg-type        [1] INTEGER (15),
///         enc-part        [2] EncryptedData -- EncAPRepPart
/// }
/// </pre>
pub fn parse_ap_rep(i: &[u8]) -> IResult<&[u8], ApRep, BerError> {
    parse_ber_tagged_explicit_g(BerTag(15), |i, hdr| {
        if !hdr.is_application() {
            return Err(Err::Error(BerError::InvalidTag));
        }
        parse_ber_sequence_defined_g(|i, _| {
            let (i, pvno) = parse_ber_tagged_explicit_g(0, |a, _| parse_der_u32(a))(i)?;
            let (i, msg_type) =
                parse_ber_tagged_explicit_g(1, |a, _| map(parse_der_u32, MessageType)(a))(i)?;
            let (i, enc_part) = parse_ber_tagged_explicit_g(2, |a, _| parse_encrypted(a))(i)?;
            let rep = ApRep {
                pvno,
                msg_type,
                enc_part,
            };
            Ok((i, rep))
        })(i)
    })(i)
}
