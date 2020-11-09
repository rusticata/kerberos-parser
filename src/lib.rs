//! # Kerberos Parser
//!
//! A Kerberos v5 ([RFC4120]) parser, implemented with the [nom](https://github.com/Geal/nom)
//! parser combinator framework.
//!
//! The code is available on [Github](https://github.com/rusticata/kerberos-parser).
//!
//! Specific parsing functions are provided for Kerberos message types. For ex. to parse a
//! KRB_AS_REQ message, use [`parse_as_req`](krb5_parser/fn.parse_as_req.html).
//!
//! # Examples
//!
//! Parsing a KRB_AS_REQ message:
//!
//! ```rust,no_run
//! use kerberos_parser::krb5::MessageType;
//! use kerberos_parser::krb5_parser::parse_as_req;
//!
//! static AS_REQ: &'static [u8] = include_bytes!("../assets/as-req.bin");
//!
//! # fn main() {
//! let res = parse_as_req(AS_REQ);
//! match res {
//!     Ok((rem, kdc_req)) => {
//!         assert!(rem.is_empty());
//!         //
//!         assert_eq!(kdc_req.msg_type, MessageType::KRB_AS_REQ);
//!     },
//!     _ => panic!("KRB_AS_REQ parsing failed: {:?}", res),
//! }
//! # }
//! ```
//!
//! [RFC4120]: https://tools.ietf.org/html/rfc4120

#![deny(/*missing_docs,*/unsafe_code,
        unstable_features,
        unused_import_braces, unused_qualifications)]

pub mod krb5;
pub mod krb5_parser;

mod krb5_constants;
mod krb5_errors;
pub use krb5_errors::*;
