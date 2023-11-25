# hpke-cl
This crates offers basic functions for encryption, decryption and testing using the HPKE framework defined in the [RFC 9180](https://datatracker.ietf.org/doc/rfc9180/ "Hybrid Public Key Encryption").
    
This crate is developed upon the [hpke](https://docs.rs/hpke/0.11.0/hpke/ "docs.rs/hpke") crate to add more flexibility in the choice of algorithms used, and to integrate command line utilities.
   
The schema to use for the various files can be observed in the following [directory](/test_vectors/test/).

Detailed documentation can be extracted directly from the code, according to the [rust doc](https://doc.rust-lang.org/rustdoc/what-is-rustdoc.html) features.