//! Kerberos 5 parsing functions

use der_parser::asn1_rs::{
    BitString, Class, Error, FromDer, GeneralString, GeneralizedTime, OptTaggedParser, ParseResult,
    Sequence, TaggedExplicit, TaggedParser,
};
use der_parser::ber::*;
use nom::combinator::{map, verify};
use nom::{Err, IResult};

use crate::krb5::*;
use Class::ContextSpecific as CS;

/// Parse a signed 32 bits integer
///
/// <pre>
/// Int32           ::= INTEGER (-2147483648..2147483647)
///                     -- signed values representable in 32 bits
/// </pre>
#[inline]
pub fn parse_der_int32(i: &[u8]) -> IResult<&[u8], i32, Error> {
    i32::from_der(i)
}

//  Microseconds    ::= INTEGER (0..999999)
//                      -- microseconds
fn parse_der_microseconds(i: &[u8]) -> IResult<&[u8], u32, Error> {
    verify(u32::from_der, |x: &u32| *x <= 999_999)(i)
}

/// Parse a Kerberos string object
///
/// <pre>
/// KerberosString  ::= GeneralString (IA5String)
/// </pre>
pub fn parse_kerberos_string(i: &[u8]) -> IResult<&[u8], String, Error> {
    map(GeneralString::from_der, |s| s.string())(i)
}

fn parse_kerberos_string_sequence(i: &[u8]) -> IResult<&[u8], Vec<String>, Error> {
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
pub fn parse_kerberos_flags(i: &[u8]) -> IResult<&[u8], BitString<'_>, Error> {
    BitString::from_der(i)
}

/// Parse a Kerberos Realm
///
/// <pre>
/// Realm           ::= KerberosString
/// </pre>
impl<'a> FromDer<'a> for Realm {
    fn from_der(bytes: &'a [u8]) -> ParseResult<'a, Self> {
        map(parse_kerberos_string, Realm)(bytes)
    }
}

#[inline]
pub fn parse_krb5_realm(i: &[u8]) -> IResult<&[u8], Realm, Error> {
    Realm::from_der(i)
}

/// Parse Kerberos PrincipalName
///
/// <pre>
/// PrincipalName   ::= SEQUENCE {
///         name-type       [0] Int32,
///         name-string     [1] SEQUENCE OF KerberosString
/// }
/// </pre>
#[deprecated(
    since = "0.8.0",
    note = "Parsing functions are deprecated. Users should instead use the FromDer trait"
)]
#[inline]
pub fn parse_krb5_principalname(i: &[u8]) -> IResult<&[u8], PrincipalName, Error> {
    PrincipalName::from_der(i)
}

/// Parse Kerberos PrincipalName
///
/// <pre>
/// PrincipalName   ::= SEQUENCE {
///         name-type       [0] Int32,
///         name-string     [1] SEQUENCE OF KerberosString
/// }
/// </pre>
impl<'a> FromDer<'a> for PrincipalName {
    fn from_der(bytes: &'a [u8]) -> ParseResult<'a, Self> {
        Sequence::from_der_and_then(bytes, |i| {
            let (i, name_type) = TaggedParser::from_der_and_then(CS, 0, i, i32::from_der)?;
            let name_type = NameType(name_type);
            let (i, name_string) =
                TaggedParser::from_der_and_then(CS, 1, i, parse_kerberos_string_sequence)?;
            Ok((
                i,
                PrincipalName {
                    name_type,
                    name_string,
                },
            ))
        })
    }
}

/// Parse a Kerberos Time
///
/// <pre>
/// KerberosTime    ::= GeneralizedTime -- with no fractional seconds
/// </pre>
#[inline]
pub fn parse_kerberos_time(i: &[u8]) -> IResult<&[u8], GeneralizedTime, Error> {
    GeneralizedTime::from_der(i)
}

/// Parse Kerberos HostAddress
///
/// <pre>
/// HostAddress     ::= SEQUENCE  {
///         addr-type       [0] Int32,
///         address         [1] OCTET STRING
/// }
/// </pre>
#[deprecated(
    since = "0.8.0",
    note = "Parsing functions are deprecated. Users should instead use the FromDer trait"
)]
#[inline]
pub fn parse_krb5_hostaddress(i: &[u8]) -> IResult<&[u8], HostAddress<'_>, Error> {
    HostAddress::from_der(i)
}

impl<'a> FromDer<'a> for HostAddress<'a> {
    fn from_der(bytes: &'a [u8]) -> ParseResult<'a, Self> {
        Sequence::from_der_and_then(bytes, |i| {
            let (i, addr_type) = TaggedParser::from_der_and_then(CS, 0, i, i32::from_der)?;
            let addr_type = AddressType(addr_type);
            let (i, address) = TaggedParser::from_der_and_then(CS, 1, i, <&[u8]>::from_der)?;
            Ok((i, HostAddress { addr_type, address }))
        })
    }
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
pub fn parse_krb5_hostaddresses(i: &[u8]) -> IResult<&[u8], Vec<HostAddress<'_>>, Error> {
    parse_ber_sequence_of_v(HostAddress::from_der)(i)
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
#[deprecated(
    since = "0.8.0",
    note = "Parsing functions are deprecated. Users should instead use the FromDer trait"
)]
#[inline]
pub fn parse_krb5_ticket(i: &[u8]) -> IResult<&[u8], Ticket<'_>, Error> {
    Ticket::from_der(i)
}

impl<'a> FromDer<'a> for Ticket<'a> {
    fn from_der(bytes: &'a [u8]) -> ParseResult<'a, Self, Error> {
        TaggedParser::from_der_and_then(Class::Application, 1, bytes, |inner| {
            Sequence::from_der_and_then(inner, |i| {
                let (i, tkt_vno) = TaggedParser::from_der_and_then(CS, 0, i, u32::from_der)?;
                if tkt_vno != 5 {
                    return Err(Err::Error(Error::invalid_value(
                        Tag::Sequence,
                        "Invalid Kerberos version (not 5)".to_string(),
                    )));
                }
                let (i, realm) = TaggedParser::from_der_and_then(CS, 1, i, Realm::from_der)?;
                let (i, sname) =
                    TaggedParser::from_der_and_then(CS, 2, i, PrincipalName::from_der)?;
                let (i, enc_part) =
                    TaggedParser::from_der_and_then(CS, 3, i, EncryptedData::from_der)?;
                let tkt = Ticket {
                    tkt_vno,
                    realm,
                    sname,
                    enc_part,
                };
                Ok((i, tkt))
            })
        })
    }
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
#[deprecated(
    since = "0.8.0",
    note = "Parsing functions are deprecated. Users should instead use the FromDer trait"
)]
#[inline]
pub fn parse_encrypted(i: &[u8]) -> IResult<&[u8], EncryptedData<'_>, Error> {
    EncryptedData::from_der(i)
}

impl<'a> FromDer<'a> for EncryptedData<'a> {
    fn from_der(bytes: &'a [u8]) -> ParseResult<'a, Self, Error> {
        Sequence::from_der_and_then(bytes, |i| {
            let (i, etype) = TaggedParser::from_der_and_then(CS, 0, i, i32::from_der)?;
            let etype = EncryptionType(etype);
            let (i, kvno) =
                OptTaggedParser::new(CS, Tag(1)).parse_der(i, |_, data| u32::from_der(data))?;
            let (i, cipher) = TaggedParser::from_der_and_then(CS, 2, i, <&[u8]>::from_der)?;
            let enc = EncryptedData {
                etype,
                kvno,
                cipher,
            };
            Ok((i, enc))
        })
    }
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
#[deprecated(
    since = "0.8.0",
    note = "Parsing functions are deprecated. Users should instead use the FromDer trait"
)]
#[inline]
pub fn parse_kdc_req(i: &[u8]) -> IResult<&[u8], KdcReq<'_>, Error> {
    KdcReq::from_der(i)
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
impl<'a> FromDer<'a> for KdcReq<'a> {
    fn from_der(bytes: &'a [u8]) -> ParseResult<'a, Self, Error> {
        Sequence::from_der_and_then(bytes, |i| {
            let (i, pvno) = TaggedParser::from_der_and_then(CS, 1, i, u32::from_der)?;
            let (i, msg_type) = TaggedParser::from_der_and_then(CS, 2, i, u32::from_der)?;
            let msg_type = MessageType(msg_type);
            let (i, padata) = OptTaggedParser::new(CS, Tag(3))
                .parse_der(i, |_, data| parse_krb5_padata_sequence(data))?;
            let padata = padata.unwrap_or_default();
            let (i, req_body) = TaggedParser::from_der_and_then(CS, 4, i, KdcReqBody::from_der)?;
            let req = KdcReq {
                pvno,
                msg_type,
                padata,
                req_body,
            };
            Ok((i, req))
        })
    }
}

#[deprecated(
    since = "0.8.0",
    note = "Parsing functions are deprecated. Users should instead use the FromDer trait"
)]
#[inline]
pub fn parse_kdc_req_body(i: &[u8]) -> IResult<&[u8], KdcReqBody<'_>, Error> {
    KdcReqBody::from_der(i)
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
impl<'a> FromDer<'a> for KdcReqBody<'a> {
    fn from_der(bytes: &'a [u8]) -> ParseResult<'a, Self, Error> {
        Sequence::from_der_and_then(bytes, |i| {
            let (i, kdc_options) = TaggedParser::from_der_and_then(CS, 0, i, parse_kerberos_flags)?;
            let (i, cname) = OptTaggedParser::new(CS, Tag(1))
                .parse_der(i, |_, data| PrincipalName::from_der(data))?;
            let (i, realm) = TaggedParser::from_der_and_then(CS, 2, i, Realm::from_der)?;
            let (i, sname) = OptTaggedParser::new(CS, Tag(3))
                .parse_der(i, |_, data| PrincipalName::from_der(data))?;
            let (i, from) = OptTaggedParser::new(CS, Tag(4))
                .parse_der(i, |_, data| parse_kerberos_time(data))?;
            let (i, till) = TaggedParser::from_der_and_then(CS, 5, i, parse_kerberos_time)?;
            let (i, rtime) = OptTaggedParser::new(CS, Tag(6))
                .parse_der(i, |_, data| parse_kerberos_time(data))?;
            let (i, nonce) = TaggedParser::from_der_and_then(CS, 7, i, u32::from_der)?;
            let (i, etype) = TaggedParser::from_der_and_then(CS, 8, i, |data| {
                let (rem, v) = <Vec<i32>>::from_der(data)?;
                let v = v.iter().map(|&e| EncryptionType(e)).collect();
                Ok((rem, v))
            })?;
            let (i, addresses) = OptTaggedParser::new(CS, Tag(9))
                .parse_der(i, |_, data| parse_krb5_hostaddresses(data))?;
            let addresses = addresses.unwrap_or_default();
            let (i, enc_authorization_data) = OptTaggedParser::new(CS, Tag(10))
                .parse_der(i, |_, data| EncryptedData::from_der(data))?;
            let (i, additional_tickets) = OptTaggedParser::new(CS, Tag(11))
                .parse_der(i, |_, data| <Vec<Ticket>>::from_der(data))?;
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
        })
    }
}

/// Parse a Kerberos AS Request
///
/// <pre>
/// AS-REQ          ::= [APPLICATION 10] KDC-REQ
/// </pre>
pub fn parse_as_req(i: &[u8]) -> IResult<&[u8], KdcReq<'_>, Error> {
    TaggedParser::from_der_and_then(Class::Application, 10, i, KdcReq::from_der)
}

/// Parse a Kerberos TGS Request
///
/// <pre>
/// TGS-REQ          ::= [APPLICATION 12] KDC-REQ
/// </pre>
pub fn parse_tgs_req(i: &[u8]) -> IResult<&[u8], KdcReq<'_>, Error> {
    TaggedParser::from_der_and_then(Class::Application, 12, i, KdcReq::from_der)
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
#[deprecated(
    since = "0.8.0",
    note = "Parsing functions are deprecated. Users should instead use the FromDer trait"
)]
#[inline]
pub fn parse_kdc_rep(i: &[u8]) -> IResult<&[u8], KdcRep<'_>, Error> {
    KdcRep::from_der(i)
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
impl<'a> FromDer<'a> for KdcRep<'a> {
    fn from_der(bytes: &'a [u8]) -> ParseResult<'a, Self, Error> {
        Sequence::from_der_and_then(bytes, |i| {
            let (i, pvno) = TaggedParser::from_der_and_then(CS, 0, i, u32::from_der)?;
            let (i, msg_type) = TaggedParser::from_der_and_then(CS, 1, i, u32::from_der)?;
            let msg_type = MessageType(msg_type);
            let (i, padata) = OptTaggedParser::new(CS, Tag(2))
                .parse_der(i, |_, data| parse_krb5_padata_sequence(data))?;
            let padata = padata.unwrap_or_default();
            let (i, crealm) = TaggedParser::from_der_and_then(CS, 3, i, Realm::from_der)?;
            let (i, cname) = TaggedParser::from_der_and_then(CS, 4, i, PrincipalName::from_der)?;
            let (i, ticket) = TaggedParser::from_der_and_then(CS, 5, i, Ticket::from_der)?;
            let (i, enc_part) = TaggedParser::from_der_and_then(CS, 6, i, EncryptedData::from_der)?;
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
        })
    }
}

/// Parse a Kerberos AS Reply
///
/// <pre>
/// AS-REP          ::= [APPLICATION 11] KDC-REP
/// </pre>
pub fn parse_as_rep(i: &[u8]) -> IResult<&[u8], KdcRep<'_>, Error> {
    TaggedParser::from_der_and_then(Class::Application, 11, i, KdcRep::from_der)
}

/// Parse a Kerberos TGS Reply
///
/// <pre>
/// TGS-REP          ::= [APPLICATION 13] KDC-REP
/// </pre>
pub fn parse_tgs_rep(i: &[u8]) -> IResult<&[u8], KdcRep<'_>, Error> {
    TaggedParser::from_der_and_then(Class::Application, 13, i, KdcRep::from_der)
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
#[deprecated(
    since = "0.8.0",
    note = "Parsing functions are deprecated. Users should instead use the FromDer trait"
)]
#[inline]
pub fn parse_krb_error(i: &[u8]) -> IResult<&[u8], KrbError<'_>, Error> {
    KrbError::from_der(i)
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
impl<'a> FromDer<'a> for KrbError<'a> {
    fn from_der(bytes: &'a [u8]) -> ParseResult<'a, Self, Error> {
        TaggedParser::from_der_and_then(Class::Application, 30, bytes, |inner| {
            Sequence::from_der_and_then(inner, |i| {
                let (i, pvno) = TaggedParser::from_der_and_then(CS, 0, i, u32::from_der)?;
                let (i, msg_type) = TaggedParser::from_der_and_then(CS, 1, i, u32::from_der)?;
                let msg_type = MessageType(msg_type);
                let (i, ctime) = OptTaggedParser::new(CS, Tag(2))
                    .parse_der(i, |_, data| parse_kerberos_time(data))?;
                let (i, cusec) = OptTaggedParser::new(CS, Tag(3))
                    .parse_der(i, |_, data| parse_der_microseconds(data))?;
                let (i, stime) = TaggedParser::from_der_and_then(CS, 4, i, parse_kerberos_time)?;
                let (i, susec) = TaggedParser::from_der_and_then(CS, 5, i, parse_der_microseconds)?;
                let (i, error_code) = TaggedParser::from_der_and_then(CS, 6, i, i32::from_der)?;
                let error_code = ErrorCode(error_code);
                let (i, crealm) = OptTaggedParser::new(CS, Tag(7))
                    .parse_der(i, |_, data| Realm::from_der(data))?;
                let (i, cname) = OptTaggedParser::new(CS, Tag(8))
                    .parse_der(i, |_, data| PrincipalName::from_der(data))?;
                let (i, realm) = TaggedParser::from_der_and_then(CS, 9, i, Realm::from_der)?;
                let (i, sname) =
                    TaggedParser::from_der_and_then(CS, 10, i, PrincipalName::from_der)?;
                let (i, etext) = OptTaggedParser::new(CS, Tag(11))
                    .parse_der(i, |_, data| parse_kerberos_string(data))?;
                let (i, edata) = OptTaggedParser::new(CS, Tag(12))
                    .parse_der(i, |_, data| <&[u8]>::from_der(data))?;
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
            })
        })
    }
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
#[deprecated(
    since = "0.8.0",
    note = "Parsing functions are deprecated. Users should instead use the FromDer trait"
)]
#[inline]
pub fn parse_krb5_padata(i: &[u8]) -> IResult<&[u8], PAData<'_>, Error> {
    PAData::from_der(i)
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
impl<'a> FromDer<'a> for PAData<'a> {
    fn from_der(bytes: &'a [u8]) -> ParseResult<'a, Self, Error> {
        Sequence::from_der_and_then(bytes, |i| {
            let (i, padata_type) = TaggedParser::from_der_and_then(CS, 1, i, i32::from_der)?;
            let padata_type = PAType(padata_type);
            let (i, padata_value) = TaggedParser::from_der_and_then(CS, 2, i, <&[u8]>::from_der)?;
            let padata = PAData {
                padata_type,
                padata_value,
            };
            Ok((i, padata))
        })
    }
}

fn parse_krb5_padata_sequence(i: &[u8]) -> IResult<&[u8], Vec<PAData<'_>>, Error> {
    parse_ber_sequence_of_v(PAData::from_der)(i)
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
#[deprecated(
    since = "0.8.0",
    note = "Parsing functions are deprecated. Users should instead use the FromDer trait"
)]
#[inline]
pub fn parse_ap_req(i: &[u8]) -> IResult<&[u8], ApReq<'_>, Error> {
    ApReq::from_der(i)
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
impl<'a> FromDer<'a> for ApReq<'a> {
    fn from_der(bytes: &'a [u8]) -> ParseResult<'a, Self, Error> {
        TaggedParser::from_der_and_then(Class::Application, 14, bytes, |inner| {
            Sequence::from_der_and_then(inner, |i| {
                let (i, pvno) = TaggedParser::from_der_and_then(CS, 0, i, u32::from_der)?;
                let (i, msg_type) = TaggedParser::from_der_and_then(CS, 1, i, u32::from_der)?;
                let msg_type = MessageType(msg_type);
                let (i, ap_options) =
                    TaggedParser::from_der_and_then(CS, 2, i, parse_kerberos_flags)?;
                let (i, ticket) = TaggedParser::from_der_and_then(CS, 3, i, Ticket::from_der)?;
                let (i, authenticator) =
                    TaggedParser::from_der_and_then(CS, 4, i, EncryptedData::from_der)?;
                let req = ApReq {
                    pvno,
                    msg_type,
                    ap_options,
                    ticket,
                    authenticator,
                };
                Ok((i, req))
            })
        })
    }
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
#[deprecated(
    since = "0.8.0",
    note = "Parsing functions are deprecated. Users should instead use the FromDer trait"
)]
#[inline]
pub fn parse_ap_rep(i: &[u8]) -> IResult<&[u8], ApRep<'_>, Error> {
    ApRep::from_der(i)
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
impl<'a> FromDer<'a> for ApRep<'a> {
    fn from_der(bytes: &'a [u8]) -> ParseResult<'a, Self, Error> {
        TaggedParser::from_der_and_then(Class::Application, 15, bytes, |inner| {
            Sequence::from_der_and_then(inner, |i| {
                let (i, pvno) = TaggedExplicit::<u32, Error, 0>::from_der(i)?;
                let (i, msg_type) = map(TaggedExplicit::<u32, Error, 1>::from_der, |m| {
                    MessageType(m.into_inner())
                })(i)?;
                let (i, enc_part) =
                    TaggedParser::from_der_and_then(CS, 2, i, EncryptedData::from_der)?;
                let rep = ApRep {
                    pvno: pvno.into_inner(),
                    msg_type,
                    enc_part,
                };
                Ok((i, rep))
            })
        })
    }
}
