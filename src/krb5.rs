//! Kerberos 5 structures
//!
//! - [RFC1510](https://tools.ietf.org/html/rfc1510) The Kerberos Network Authentication Service (V5)
//! - [RFC3961](https://tools.ietf.org/html/rfc3961) Encryption and Checksum Specifications for Kerberos 5
//! - [RFC4120](https://tools.ietf.org/html/rfc4120) The Kerberos Network Authentication Service (V5)

use der_parser::DerObject;
use std::fmt;

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

/// Key Distribution Center (KDC) Reply Message
#[derive(Debug, PartialEq)]
pub struct KdcRep<'a> {
    pub pvno: u32,
    pub msg_type: u32,
    pub padata: Vec<DerObject<'a>>,
    pub crealm: Realm,
    pub cname: PrincipalName,
    pub ticket: Ticket<'a>,
    pub enc_part: EncryptedData<'a>,
}

/// Kerberos Error message
#[derive(Debug, PartialEq)]
pub struct KrbError<'a> {
    pub pvno: u32,
    pub msg_type: u32,
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

/// Encryption type
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct EncryptionType(pub u32);

impl EncryptionType {
    pub const DES_CBC_CRC                  : EncryptionType = EncryptionType(1);
    pub const DES_CBC_MD4                  : EncryptionType = EncryptionType(2);
    pub const DES_CBC_MD5                  : EncryptionType = EncryptionType(3);
    pub const DES3_CBC_MD5                 : EncryptionType = EncryptionType(5);
    pub const DES3_CBC_SHA1                : EncryptionType = EncryptionType(7);
    pub const DSAWITHSHA1_CMSOID           : EncryptionType = EncryptionType(9);
    pub const MD5WITHRSAENCRYPTION_CMSOID  : EncryptionType = EncryptionType(10);
    pub const SHA1WITHRSAENCRYPTION_CMSOID : EncryptionType = EncryptionType(11);
    pub const RC2CBC_ENVOID                : EncryptionType = EncryptionType(12);
    pub const RSAENCRYPTION_ENVOID         : EncryptionType = EncryptionType(13);
    pub const RSAES_OAEP_ENV_OID           : EncryptionType = EncryptionType(14);
    pub const DES_EDE3_CBC_ENV_OID         : EncryptionType = EncryptionType(15);
    pub const DES3_CBC_SHA1_KD             : EncryptionType = EncryptionType(16);
    pub const AES128_CTS_HMAC_SHA1_96      : EncryptionType = EncryptionType(17);
    pub const AES256_CTS_HMAC_SHA1_96      : EncryptionType = EncryptionType(18);
    pub const RC4_HMAC                     : EncryptionType = EncryptionType(23);
    pub const RC4_HMAC_EXP                 : EncryptionType = EncryptionType(24);
    pub const SUBKEY_KEYMATERIAL           : EncryptionType = EncryptionType(65);
}

impl fmt::Debug for EncryptionType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.0 {
            1  => f.write_str("des-cbc-crc"),
            2  => f.write_str("des-cbc-md4"),
            3  => f.write_str("des-cbc-md5"),
            5  => f.write_str("des3-cbc-md5"),
            7  => f.write_str("des3-cbc-sha1"),
            9  => f.write_str("dsaWithSHA1-CmsOID"),
            10 => f.write_str("md5WithRSAEncryption-CmsOID"),
            11 => f.write_str("sha1WithRSAEncryption-CmsOID"),
            12 => f.write_str("rc2CBC-EnvOID"),
            13 => f.write_str("rsaEncryption-EnvOID"),
            14 => f.write_str("rsaES-OAEP-ENV-OID"),
            15 => f.write_str("des-ede3-cbc-Env-OID"),
            16 => f.write_str("des3-cbc-sha1-kd"),
            17 => f.write_str("aes128-cts-hmac-sha1-96"),
            18 => f.write_str("aes256-cts-hmac-sha1-96"),
            23 => f.write_str("rc4-hmac"),
            24 => f.write_str("rc4-hmac-exp"),
            65 => f.write_str("subkey-keymaterial"),
            n  => f.debug_tuple("EncryptionType").field(&n).finish(),
        }
    }
}
