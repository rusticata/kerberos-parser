# Kerberos parser

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE-MIT)
[![Apache License 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](./LICENSE-APACHE)
[![Build Status](https://travis-ci.org/rusticata/kerberos-parser.svg?branch=master)](https://travis-ci.org/rusticata/kerberos-parser)
[![Crates.io Version](https://img.shields.io/crates/v/kerberos-parser.svg)](https://crates.io/crates/kerberos-parser)

<!-- cargo-sync-readme start -->

# Kerberos Parser

A Kerberos v5 ([RFC4120]) parser, implemented with the [nom](https://github.com/Geal/nom)
parser combinator framework.

The code is available on [Github](https://github.com/rusticata/kerberos-parser).

Specific parsing functions are provided for Kerberos message types. For ex. to parse a
KRB_AS_REQ message, use [`parse_as_req`](krb5_parser/fn.parse_as_req.html).

# Examples

Parsing a KRB_AS_REQ message:

```rust,no_run
use kerberos_parser::krb5::MessageType;
use kerberos_parser::krb5_parser::parse_as_req;

static AS_REQ: &'static [u8] = include_bytes!("../assets/as-req.bin");

let res = parse_as_req(AS_REQ);
match res {
    Ok((rem, kdc_req)) => {
        assert!(rem.is_empty());
        //
        assert_eq!(kdc_req.msg_type, MessageType::KRB_AS_REQ);
    },
    _ => panic!("KRB_AS_REQ parsing failed: {:?}", res),
}
```

[RFC4120]: https://tools.ietf.org/html/rfc4120

<!-- cargo-sync-readme end -->

## Rusticata

This parser is part of the [rusticata](https://github.com/rusticata) project.
The goal of this project is to provide **safe** parsers, that can be used in other projects.

Testing of the parser is done manually, and also using unit tests and
[cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz). Please fill a bugreport if you find any issue.

Feel free to contribute: tests, feedback, doc, suggestions (or code) of new parsers etc. are welcome.

## License

Licensed under either of

 * Apache License, Version 2.0
   ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license
   ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

