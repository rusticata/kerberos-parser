#[macro_use]
extern crate nom;

#[macro_use]
extern crate rusticata_macros;

#[macro_use]
extern crate der_parser;

pub mod krb5;
pub mod krb5_parser;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
