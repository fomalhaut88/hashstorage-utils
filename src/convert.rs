use std::convert::TryInto;

use bigi::Bigi;
use bigi_ecc::{point, Point};


pub fn str_to_bytes_sized<const L: usize>(s: &str) -> [u8; L] {
    let mut v = s.as_bytes().to_vec();
    v.resize(L, 0u8);
    v.try_into().unwrap()
}


pub fn str_from_bytes(bytes: &[u8]) -> String {
    let mut bytes_truncated: Vec<u8> =
        bytes.to_vec().into_iter().rev().skip_while(|&x| x == 0u8).collect();
    bytes_truncated.reverse();
    String::from_utf8(bytes_truncated).unwrap()
}


pub fn hex_to_bytes_vec(hex: &str) -> Vec<u8> {
    (0..hex.len()).step_by(2).rev().map(
        |i| u8::from_str_radix(&hex[i..(i + 2)], 16).unwrap()
    ).collect()
}


pub fn hex_to_bytes<const L: usize>(hex: &str) -> [u8; L] {
    hex_to_bytes_vec(hex).try_into().unwrap()
}


pub fn hex_from_bytes(bytes: &[u8]) -> String {
    bytes.iter().rev().map(|b| format!("{:02X?}", b)).collect()
}


pub fn private_key_to_bytes(b: &Bigi) -> [u8; 32] {
    b.to_bytes()[..32].try_into().unwrap()
}


pub fn private_key_from_bytes(bytes: &[u8; 32]) -> Bigi {
    Bigi::from_bytes(bytes)
}


pub fn public_key_to_bytes(p: &Point) -> [u8; 64] {
    [
        &p.x.to_bytes()[..32],
        &p.y.to_bytes()[..32]
    ].concat().try_into().unwrap()
}


pub fn public_key_from_bytes(bytes: &[u8; 64]) -> Point {
    point!(
        Bigi::from_bytes(&bytes[..32]),
        Bigi::from_bytes(&bytes[32..])
    )
}


pub fn signature_to_bytes(signature: &(Bigi, Bigi)) -> [u8; 64] {
    [
        &signature.0.to_bytes()[..32],
        &signature.1.to_bytes()[..32]
    ].concat().try_into().unwrap()
}


pub fn signature_from_bytes(bytes: &[u8; 64]) -> (Bigi, Bigi) {
    (
        Bigi::from_bytes(&bytes[..32]),
        Bigi::from_bytes(&bytes[32..])
    )
}
