//! Kerberos 5 parsing functions

use der_parser::ber::*;
use der_parser::der::*;
use der_parser::error::*;
use nom::error::ErrorKind;
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
    map_res!(i, parse_der_integer, |x: DerObject| {
        match x.content {
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
        }
    })
}

//  Microseconds    ::= INTEGER (0..999999)
//                      -- microseconds
fn parse_der_microseconds(i: &[u8]) -> IResult<&[u8], u32, BerError> {
    verify!(i, parse_der_u32, |x: &u32| *x <= 999_999)
}

// helper macro to give same result as opt!(complete!(parse_der_tagged!(i,tag,fn) but with
// less complexity, and faster
macro_rules! opt_parse_der_tagged(
    ($i:expr, EXPLICIT $tag:expr, $submac:ident!( $($args:tt)*)) => ({
        use der_parser::der::der_read_element_header;
        use nom::{Err, Needed};
        match der_read_element_header($i) {
            Ok((rem,hdr)) => {
                if $tag != hdr.tag.0 {
                    Ok(($i,None))
                } else {
                    let len = hdr.len as usize;
                    if rem.len() < len { Err(Err::Incomplete(Needed::Size(len))) } // tag was correct, this really is an error
                    else {
                        match $submac!(&rem[0..len], $($args)*) {
                            Ok((_,res)) => Ok((&rem[len..],Some(res))),
                            _           => Ok(($i,None))
                        }
                    }
                }
            },
            _ => Ok(($i,None))
        }
    });
    ($i:expr, EXPLICIT $tag:expr, $f:ident) => ({
        opt_parse_der_tagged!($i, EXPLICIT $tag, call!($f))
    });
);

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
                    Err(_) => Err(Err::Error(error_position!(i, ErrorKind::IsNot))),
                }
            } else {
                Err(Err::Error(error_position!(i, ErrorKind::Tag)))
            }
        }
        Err(e) => Err(e),
    }
}

fn parse_kerberos_string_sequence(i: &[u8]) -> IResult<&[u8], Vec<String>, BerError> {
    parse_der_struct!(
        i,
        TAG DerTag::Sequence,
        v: many0!(complete!(parse_kerberos_string)) >>
        ( v )
    )
    .map(|(rem, x)| (rem, x.1))
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
    map!(i, parse_kerberos_string, Realm)
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
    map_res!(
        i,
        parse_der_struct!(
            t: parse_der_tagged!(EXPLICIT 0, parse_der_int32)
                >> s: parse_der_tagged!(EXPLICIT 1, parse_kerberos_string_sequence)
                >> (PrincipalName {
                    name_type: NameType(t),
                    name_string: s,
                })
        ),
        |(hdr, t): (BerObjectHeader, PrincipalName)| {
            if hdr.tag != BerTag::Sequence {
                return Err("not a sequence!");
            }
            Ok(t)
        }
    )
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
pub fn parse_krb5_hostaddress<'a>(i: &'a [u8]) -> IResult<&'a [u8], HostAddress<'a>, BerError> {
    parse_der_struct!(
        i,
        TAG DerTag::Sequence,
        t: parse_der_tagged!(EXPLICIT 0, parse_der_int32) >>
        a: map_res!(parse_der_tagged!(EXPLICIT 1, parse_der_octetstring),|x: DerObject<'a>| x.as_slice()) >>
        ( HostAddress{
            addr_type: AddressType(t),
            address: a,
        })
    ).map(|(rem,x)| (rem,x.1))
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
    parse_der_struct!(
        i,
        TAG DerTag::Sequence,
        v: many0!(complete!(parse_krb5_hostaddress)) >>
        ( v )
    )
    .map(|(rem, x)| (rem, x.1))
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
pub fn parse_krb5_ticket<'a>(i: &'a [u8]) -> IResult<&'a [u8], Ticket<'a>, BerError> {
    parse_der_application!(
        i,
        APPLICATION 1,
        st: parse_der_struct!(
            TAG DerTag::Sequence,
            no: parse_der_tagged!(EXPLICIT 0, parse_der_u32) >>
                error_if!(no != 5, ErrorKind::Tag) >>
            r:  parse_der_tagged!(EXPLICIT 1, parse_krb5_realm) >>
            s:  parse_der_tagged!(EXPLICIT 2, parse_krb5_principalname) >>
            e:  map_res!(parse_der,|x: DerObject<'a>| x.as_slice()) >>
            ( Ticket{
                tkt_vno: no,
                realm: r,
                sname: s,
                enc_part: e
            })
        ) >> (st)
    )
    .map(|(rem, t)| (rem, (t.1).1))
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
pub fn parse_encrypted<'a>(i: &'a [u8]) -> IResult<&'a [u8], EncryptedData<'a>, BerError> {
    parse_der_struct!(
        i,
        TAG DerTag::Sequence,
        e: parse_der_tagged!(EXPLICIT 0, parse_der_int32) >>
        k: opt_parse_der_tagged!(EXPLICIT 1, parse_der_u32) >>
        c: map_res!(parse_der_tagged!(EXPLICIT 2, parse_der_octetstring), |x: DerObject<'a>| x.as_slice()) >>
           eof!() >>
        ( EncryptedData{
            etype: EncryptionType(e),
            kvno: k,
            cipher: c
        })
    ).map(|(rem,t)| (rem,t.1))
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
    parse_der_struct!(
        i,
        TAG DerTag::Sequence,
        pvno:     parse_der_tagged!(EXPLICIT 1, parse_der_u32) >>
        t:        parse_der_tagged!(EXPLICIT 2, parse_der_u32) >>
        d:        opt_parse_der_tagged!(EXPLICIT 3, parse_krb5_padata_sequence) >>
        req_body: parse_der_tagged!(EXPLICIT 4, parse_kdc_req_body) >>
                  eof!() >>
        ( KdcReq{
            pvno,
            msg_type: MessageType(t),
            padata: d.unwrap_or_default(),
            req_body
        })
    )
    .map(|(rem, t)| (rem, t.1))
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
    parse_der_struct!(
        i,
        TAG DerTag::Sequence,
        o:     parse_der_tagged!(EXPLICIT 0,parse_kerberos_flags) >>
        cname: opt_parse_der_tagged!(EXPLICIT 1,parse_krb5_principalname) >>
        realm: parse_der_tagged!(EXPLICIT 2,parse_krb5_realm) >>
        sname: opt_parse_der_tagged!(EXPLICIT 3,parse_krb5_principalname) >>
        from:  opt_parse_der_tagged!(EXPLICIT 4,parse_kerberos_time) >>
        till:  parse_der_tagged!(EXPLICIT 5,parse_kerberos_time) >>
        rtime: opt_parse_der_tagged!(EXPLICIT 6,parse_kerberos_time) >>
        nonce: parse_der_tagged!(EXPLICIT 7, parse_der_u32) >>
        etype: parse_der_tagged!(EXPLICIT 8,
                                 parse_der_struct!(v: many1!(complete!(parse_der_int32)) >> (v.iter().map(|&x| EncryptionType(x)).collect()))
                                 ) >>
        addr:  opt_parse_der_tagged!(EXPLICIT 9,parse_krb5_hostaddresses) >>
        ead:   opt_parse_der_tagged!(EXPLICIT 10,parse_encrypted) >>
        atkts: opt_parse_der_tagged!(EXPLICIT 11,
                                 parse_der_struct!(v: many1!(complete!(parse_krb5_ticket)) >> (v))
                                 ) >>
               eof!() >>
        ( KdcReqBody{
            kdc_options: o,
            cname,
            realm,
            sname,
            from,
            till,
            rtime,
            nonce,
            etype: etype.1,
            addresses: addr.unwrap_or_default(),
            enc_authorization_data: ead,
            additional_tickets: if atkts.is_some() { atkts.unwrap().1 } else { vec![] }
        })
    ).map(|(rem,t)| (rem,t.1))
}

/// Parse a Kerberos AS Request
///
/// <pre>
/// AS-REQ          ::= [APPLICATION 10] KDC-REQ
/// </pre>
pub fn parse_as_req(i: &[u8]) -> IResult<&[u8], KdcReq, BerError> {
    parse_der_application!(
        i,
        APPLICATION 10,
        req: parse_kdc_req >> (req)
    )
    .map(|(rem, t)| (rem, t.1))
}

/// Parse a Kerberos TGS Request
///
/// <pre>
/// TGS-REQ          ::= [APPLICATION 12] KDC-REQ
/// </pre>
pub fn parse_tgs_req(i: &[u8]) -> IResult<&[u8], KdcReq, BerError> {
    parse_der_application!(
        i,
        APPLICATION 12,
        req: parse_kdc_req >> (req)
    )
    .map(|(rem, t)| (rem, t.1))
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
    parse_der_struct!(
        i,
        TAG DerTag::Sequence,
        pvno:     parse_der_tagged!(EXPLICIT 0,parse_der_u32) >>
        msgtype:  parse_der_tagged!(EXPLICIT 1,parse_der_u32) >>
        padata:   opt_parse_der_tagged!(EXPLICIT 2,parse_krb5_padata_sequence) >>
        crealm:   parse_der_tagged!(EXPLICIT 3,parse_krb5_realm) >>
        cname:    parse_der_tagged!(EXPLICIT 4,parse_krb5_principalname) >>
        ticket:   parse_der_tagged!(EXPLICIT 5,parse_krb5_ticket) >>
        enc_part: parse_der_tagged!(EXPLICIT 6,parse_encrypted) >>
                  eof!() >>
        ( KdcRep{
            pvno,
            msg_type: MessageType(msgtype),
            padata: padata.unwrap_or_default(),
            crealm,
            cname,
            ticket,
            enc_part,
        })
    )
    .map(|(rem, t)| (rem, t.1))
}

/// Parse a Kerberos AS Reply
///
/// <pre>
/// AS-REP          ::= [APPLICATION 11] KDC-REP
/// </pre>
pub fn parse_as_rep(i: &[u8]) -> IResult<&[u8], KdcRep, BerError> {
    parse_der_application!(
        i,
        APPLICATION 11,
        rep: parse_kdc_rep >> (rep)
    )
    .map(|(rem, t)| (rem, t.1))
}

/// Parse a Kerberos TGS Reply
///
/// <pre>
/// TGS-REP          ::= [APPLICATION 13] KDC-REP
/// </pre>
pub fn parse_tgs_rep(i: &[u8]) -> IResult<&[u8], KdcRep, BerError> {
    parse_der_application!(
        i,
        APPLICATION 13,
        rep: parse_kdc_rep >> (rep)
    )
    .map(|(rem, t)| (rem, t.1))
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
    parse_der_application!(
        i,
        APPLICATION 30,
        st: parse_der_struct!(
            TAG DerTag::Sequence,
            pvno:    parse_der_tagged!(EXPLICIT 0,parse_der_u32) >>
            msgtype: parse_der_tagged!(EXPLICIT 1,parse_der_u32) >>
                     error_if!(pvno != 5 || msgtype != 30, ErrorKind::Tag) >>
            ctime:   opt_parse_der_tagged!(EXPLICIT 2,parse_kerberos_time) >>
            cusec:   opt_parse_der_tagged!(EXPLICIT 3,parse_der_microseconds) >>
            stime:   parse_der_tagged!(EXPLICIT 4,parse_kerberos_time) >>
            susec:   parse_der_tagged!(EXPLICIT 5,parse_der_microseconds) >>
            errorc:  parse_der_tagged!(EXPLICIT 6,parse_der_int32) >>
            crealm:  opt_parse_der_tagged!(EXPLICIT 7,parse_krb5_realm) >>
            cname:   opt_parse_der_tagged!(EXPLICIT 8,parse_krb5_principalname) >>
            realm:   parse_der_tagged!(EXPLICIT 9,parse_krb5_realm) >>
            sname:   parse_der_tagged!(EXPLICIT 10,parse_krb5_principalname) >>
            etext:   opt_parse_der_tagged!(EXPLICIT 11,parse_kerberos_string) >>
            edata:   opt_parse_der_tagged!(EXPLICIT 12,parse_der_octetstring) >>
            (KrbError{
                pvno,
                msg_type: MessageType(msgtype),
                ctime,
                cusec,
                stime,
                susec,
                error_code: ErrorCode(errorc),
                crealm,
                cname,
                realm,
                sname,
                etext,
                edata,
            })
        )
        >> (st)
    )
    .map(|(rem, t)| (rem, (t.1).1))
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
pub fn parse_krb5_padata<'a>(i: &'a [u8]) -> IResult<&'a [u8], PAData<'a>, BerError> {
    parse_der_struct!(
        i,
        TAG DerTag::Sequence,
        t: parse_der_tagged!(EXPLICIT 1, parse_der_int32) >>
        s: map_res!(parse_der_tagged!(EXPLICIT 2, parse_der_octetstring),|x: DerObject<'a>| x.as_slice()) >>
        ( PAData{
            padata_type:  PAType(t),
            padata_value: s,
        })
    ).map(|(rem,x)| (rem,x.1))
}

fn parse_krb5_padata_sequence(i: &[u8]) -> IResult<&[u8], Vec<PAData>, BerError> {
    parse_der_struct!(
        i,
        TAG DerTag::Sequence,
        v: many0!(complete!(parse_krb5_padata)) >>
        ( v )
    )
    .map(|(rem, x)| (rem, x.1))
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
    parse_der_application!(
        i,
        APPLICATION 14,
        st: parse_der_struct!(
            TAG DerTag::Sequence,
            pvno:    parse_der_tagged!(EXPLICIT 0,parse_der_u32) >>
            msgtype: parse_der_tagged!(EXPLICIT 1,parse_der_u32) >>
                     error_if!(pvno != 5 || msgtype != 14, ErrorKind::Tag) >>
            flags:   parse_der_tagged!(EXPLICIT 2,parse_kerberos_flags) >>
            ticket:  parse_der_tagged!(EXPLICIT 3,parse_krb5_ticket) >>
            auth:    parse_der_tagged!(EXPLICIT 4,parse_encrypted) >>
            ( ApReq{
                pvno,
                msg_type: MessageType(msgtype),
                ap_options: flags,
                ticket,
                authenticator: auth,
            })
        )
        >> (st)
    )
    .map(|(rem, t)| (rem, (t.1).1))
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
    parse_der_application!(
        i,
        APPLICATION 15,
        st: parse_der_struct!(
            TAG DerTag::Sequence,
            pvno:    parse_der_tagged!(EXPLICIT 0,parse_der_u32) >>
            msgtype: parse_der_tagged!(EXPLICIT 1,parse_der_u32) >>
                     error_if!(pvno != 5 || msgtype != 15, ErrorKind::Tag) >>
            edata:   parse_der_tagged!(EXPLICIT 4,parse_encrypted) >>
            ( ApRep{
                pvno,
                msg_type: MessageType(msgtype),
                enc_part: edata,
            })
        )
        >> (st)
    )
    .map(|(rem, t)| (rem, (t.1).1))
}
