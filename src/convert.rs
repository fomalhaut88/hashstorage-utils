use std::convert::TryInto;

use bigi::Bigi;
use bigi_ecc::{point, Point};


/// Converts a string to a byte array with fixed size.
/// Extra bytes will be filled with zeros.
/// ```rust
/// use hashstorage_utils::convert::str_to_bytes_sized;
///
/// let bytes: [u8; 11] = str_to_bytes_sized("hello world");
/// ```
pub fn str_to_bytes_sized<const L: usize>(s: &str) -> [u8; L] {
    let mut v = s.as_bytes().to_vec();
    v.resize(L, 0u8);
    v.try_into().unwrap()
}


/// Converts bytes to a string. Trailing zeros will not affect on the result.
pub fn str_from_bytes(bytes: &[u8]) -> String {
    let mut bytes_truncated: Vec<u8> =
        bytes.to_vec().into_iter().rev().skip_while(|&x| x == 0u8).collect();
    bytes_truncated.reverse();
    String::from_utf8(bytes_truncated).unwrap()
}


/// Converts HEX number representation to a vector of bytes.
pub fn hex_to_bytes_vec(hex: &str) -> Vec<u8> {
    (0..hex.len()).step_by(2).rev().map(
        |i| u8::from_str_radix(&hex[i..(i + 2)], 16).unwrap()
    ).collect()
}


/// Converts HEX number representation to a bytes array with fixed size.
/// ```rust
/// use hashstorage_utils::convert::hex_to_bytes;
///
/// let bytes: [u8; 2] = hex_to_bytes("C18B");
/// assert_eq!(bytes, [139u8, 193]);
/// ```
pub fn hex_to_bytes<const L: usize>(hex: &str) -> [u8; L] {
    hex_to_bytes_vec(hex).try_into().unwrap()
}


/// Converts bytes to a HEX number as string.
pub fn hex_from_bytes(bytes: &[u8]) -> String {
    bytes.iter().rev().map(|b| format!("{:02X?}", b)).collect()
}


/// Converts a 256-bit private key given as Bigi<4> number to its byte
/// representation as an array of 32 bytes.
pub fn private_key_to_bytes(b: &Bigi<4>) -> [u8; 32] {
    b.to_bytes()[..32].try_into().unwrap()
}


/// Converts an array of 32 bytes to a Bigi<4> number that can be interpreted
/// as a private key.
pub fn private_key_from_bytes(bytes: &[u8; 32]) -> Bigi<4> {
    Bigi::<4>::from_bytes(bytes)
}


/// Converts a public key given as a point on an elliptic curve represented as
/// two 256-bit integers (type Bigi<4>) to an array of 64 bytes.
/// Note: this function will not work correctly for zero point,
/// but in practice zero public key does not make any sense.
pub fn public_key_to_bytes(p: &Point<4>) -> [u8; 64] {
    [
        &p.x.to_bytes()[..32],
        &p.y.to_bytes()[..32]
    ].concat().try_into().unwrap()
}


/// Converts an array of 64 bytes to a point on an elliptic curve that can be
/// represented as a public key.
/// Note: this function will not work correctly for zero point,
/// but in practice zero public key does not make any sense.
pub fn public_key_from_bytes(bytes: &[u8; 64]) -> Point<4> {
    point!(
        Bigi::<4>::from_bytes(&bytes[..32]),
        Bigi::<4>::from_bytes(&bytes[32..])
    )
}


/// Converts a signature given as a pair of 256-bit integers (type Bigi<4>)
/// to an array of 64 bytes.
pub fn signature_to_bytes(signature: &(Bigi<4>, Bigi<4>)) -> [u8; 64] {
    [
        &signature.0.to_bytes()[..32],
        &signature.1.to_bytes()[..32]
    ].concat().try_into().unwrap()
}


/// Converts an array of 64 bytes to a pair of 256-bit integers (type Bigi<4>)
/// that can be represented as a signature.
pub fn signature_from_bytes(bytes: &[u8; 64]) -> (Bigi<4>, Bigi<4>) {
    (
        Bigi::<4>::from_bytes(&bytes[..32]),
        Bigi::<4>::from_bytes(&bytes[32..])
    )
}
