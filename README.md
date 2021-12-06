# hashstorage-utils

**hashstorage-utils** provides a set of functions to work with data for
Hashstorage project that include
[backend](https://github.com/fomalhaut88/hashstorage) service and a
[frontend](https://github.com/fomalhaut88/hashstorage-cli) library.
It is a kind of bridge between common datatypes that can be used everythere
including JS (through WASM) and inner datatypes to work with ECC and multi
precision calculations provided by [bigi](https://github.com/fomalhaut88/bigi)
and [bigi-ecc](https://github.com/fomalhaut88/bigi_ecc).
This library contains two modules: *convert*
for data converting and *crypto* for working with encrypting,
decrypting, signing and so on. The library supports only 256-bit integers
for private and public keys, signatures, hashes.
