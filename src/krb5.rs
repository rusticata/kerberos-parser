//! Kerberos 5 structures
//!
//! - [RFC1510](https://tools.ietf.org/html/rfc1510) The Kerberos Network Authentication Service (V5)
//! - [RFC3961](https://tools.ietf.org/html/rfc3961) Encryption and Checksum Specifications for Kerberos 5
//! - [RFC4120](https://tools.ietf.org/html/rfc4120) The Kerberos Network Authentication Service (V5)

use der_parser::DerObject;

pub use krb5_constants::*;

/// Kerberos Realm
///
/// A Kerberos realm is a set of managed nodes that share the same Kerberos database.
#[derive(Debug, PartialEq)]
pub struct Realm(pub String);

/// Kerberos PrincipalName
///
/// A Kerberos principal is a service or user that is known to the Kerberos system. Each Kerberos
/// principal is identified by its principal name. Principal names consist of three parts: a
/// service or user name, an instance name, and a realm name in the following form:
///
/// <pre>
/// principal-name.instance-name@realm-name
/// </pre>
#[derive(Debug, PartialEq)]
pub struct PrincipalName {
    pub name_type: NameType,
    pub name_string: Vec<String>,
}

/// Kerberos Ticket
///
/// A record that helps a client authenticate itself to a server; it
/// contains the client's identity, a session key, a timestamp, and
/// other information, all sealed using the server's secret key.  It
/// only serves to authenticate a client when presented along with a
/// fresh Authenticator.
#[derive(Debug, PartialEq)]
pub struct Ticket<'a> {
    pub tkt_vno: u32,
    pub realm: Realm,
    pub sname: PrincipalName,
    pub enc_part: &'a [u8],
}

/// Kerberos EncryptedData
#[derive(Debug, PartialEq)]
pub struct EncryptedData<'a> {
    /// EncryptionType
    pub etype: EncryptionType,
    /// Version number of the key under which data is encrypted
    pub kvno: Option<u32>,
    /// Ciphertext
    pub cipher: &'a [u8],
}

/// Key Distribution Center (KDC) Request Message
#[derive(Debug, PartialEq)]
pub struct KdcReq<'a> {
    pub pvno: u32,
    pub msg_type: MessageType,
    pub padata: Vec<PAData<'a>>,
    pub req_body: KdcReqBody<'a>,
}

/// Key Distribution Center (KDC) Request Message Body
#[derive(Debug, PartialEq)]
pub struct KdcReqBody<'a> {
    pub kdc_options: DerObject<'a>,
    pub cname: Option<PrincipalName>,
    pub realm: Realm,
    pub sname: Option<PrincipalName>,
    pub from: Option<DerObject<'a>>,
    pub till: DerObject<'a>,
    pub rtime: Option<DerObject<'a>>,
    pub nonce: u32,
    pub etype: Vec<EncryptionType>,
    pub addresses: Vec<HostAddress<'a>>,
    pub enc_authorization_data: Option<EncryptedData<'a>>,
    pub additional_tickets: Vec<Ticket<'a>>,
}

/// Kerberos HostAddress
#[derive(Debug, PartialEq)]
pub struct HostAddress<'a> {
    pub addr_type: AddressType,
    pub address: &'a[u8],
}

/// Key Distribution Center (KDC) Reply Message
#[derive(Debug, PartialEq)]
pub struct KdcRep<'a> {
    pub pvno: u32,
    pub msg_type: MessageType,
    pub padata: Vec<PAData<'a>>,
    pub crealm: Realm,
    pub cname: PrincipalName,
    pub ticket: Ticket<'a>,
    pub enc_part: EncryptedData<'a>,
}

/// Kerberos Error message
#[derive(Debug, PartialEq)]
pub struct KrbError<'a> {
    pub pvno: u32,
    pub msg_type: MessageType,
    pub ctime: Option<DerObject<'a>>,
    pub cusec: Option<u32>,
    pub stime: DerObject<'a>,
    pub susec: u32,
    pub error_code: i32,
    pub crealm: Option<Realm>,
    pub cname: Option<PrincipalName>,
    pub realm: Realm,
    pub sname: PrincipalName,
    pub etext: Option<String>,
    pub edata: Option<DerObject<'a>>,
}

/// Kerberos PA-Data
#[derive(Debug, PartialEq)]
pub struct PAData<'a> {
    pub padata_type:  PAType,
    pub padata_value: &'a[u8],
}

/// Kerberos AP Request
#[derive(Debug, PartialEq)]
pub struct ApReq<'a> {
    pub pvno          : u32,
    pub msg_type      : MessageType,
    pub ap_options    : DerObject<'a>, // KerberosFlags
    pub ticket        : Ticket<'a>,
    pub authenticator : EncryptedData<'a>,
}

/// Kerberos AP Reply
#[derive(Debug, PartialEq)]
pub struct ApRep<'a> {
    pub pvno     : u32,
    pub msg_type : MessageType,
    pub enc_part : EncryptedData<'a>,
}
