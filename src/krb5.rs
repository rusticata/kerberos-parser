//! Kerberos 5 structures
//!
//! - [RFC1510](https://tools.ietf.org/html/rfc1510) The Kerberos Network Authentication Service (V5)
//! - [RFC4120](https://tools.ietf.org/html/rfc4120) The Kerberos Network Authentication Service (V5)

use der_parser::DerObject;

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
    pub name_type: u32,
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
    pub etype: u32,
    /// Version number of the key under which data is encrypted
    pub kvno: Option<u32>,
    /// Ciphertext
    pub cipher: &'a [u8],
}

/// Key Distribution Center (KDC) Request Message
#[derive(Debug, PartialEq)]
pub struct KdcReq<'a> {
    pub pvno: u32,
    pub msg_type: u32,
    pub padata: Vec<DerObject<'a>>,
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
    pub etype: Vec<u32>,
    pub addresses: Vec<HostAddress<'a>>,
    pub enc_authorization_data: Option<EncryptedData<'a>>,
    pub additional_tickets: Vec<Ticket<'a>>,
}

/// Kerberos HostAddress
#[derive(Debug, PartialEq)]
pub struct HostAddress<'a> {
    pub addr_type: u32,
    pub address: &'a[u8],
}

