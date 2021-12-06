//! A standard usecase:
//!
//! ```rust
//! use bigi_ecc::schemas::load_secp256k1;
//! use hashstorage_utils::convert::{str_to_bytes_sized};
//! use hashstorage_utils::crypto::{generate_pair, build_signature, check_signature};
//!
//! let mut rng = rand::thread_rng();
//!
//! // Load a schema
//! let schema = load_secp256k1();
//!
//! // Generate a key pair
//! let (private_key, public_key) = generate_pair(&mut rng, &schema);
//!
//! // Define a hashstorage block data
//! let group: [u8; 32] = str_to_bytes_sized("my group");
//! let key: [u8; 32] = str_to_bytes_sized("my key");
//! let version: u64 = 1;
//! let data = b"my test data";
//!
//! // Build signature
//! let signature = build_signature(
//!     &mut rng, &schema, &private_key, &group, &key, version, data
//! );
//!
//! // Check signature
//! let result = check_signature(
//!     &schema, &signature, &public_key, &group, &key, version, data
//! );
//! assert_eq!(result, true);
//! ```

use std::convert::TryInto;

use rand::Rng;
use sha2::{Sha256, Digest};
use bigi_ecc::CurveTrait;
use bigi_ecc::schemas::Schema;
use bigi_ecc::ecdsa::{check_signature as ecdsa_check_signature,
                      build_signature as ecdsa_build_signature};

use crate::convert::*;


/// Creates a signature of a hashstorage block by given: group, key, version
/// and data.
pub fn build_signature<T: CurveTrait<4>, R: Rng + ?Sized>(
            rng: &mut R, schema: &Schema<T, 4>,
            private_key: &[u8; 32], group: &[u8; 32], key: &[u8; 32],
            version: u64, data: &[u8]
        ) -> [u8; 64] {
    let private_bigi = private_key_from_bytes(private_key);
    let hash = sha256_pack(group, key, version, data);
    let signature_pair = ecdsa_build_signature(
        rng, schema, &private_bigi, &hash.to_vec()
    );
    signature_to_bytes(&signature_pair)
}


/// Checks the signature for a hashstorage block by given: group, key, version
/// and data.
pub fn check_signature<T: CurveTrait<4>>(
            schema: &Schema<T, 4>, signature: &[u8; 64],
            public_key: &[u8; 64], group: &[u8; 32], key: &[u8; 32],
            version: u64, data: &[u8]
        ) -> bool {
    let signature_pair = signature_from_bytes(&signature);
    let public_point = public_key_from_bytes(public_key);
    let hash = sha256_pack(group, key, version, data);
    ecdsa_check_signature(
        schema, &public_point, &hash.to_vec(), &signature_pair
    )
}


/// Calculates a 256-bit hash of byte array using SHA256.
pub fn sha256_hash(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.reset();
    hasher.update(bytes);
    hasher.finalize().try_into().unwrap()
}


/// Calculates SHA256 hash for hashstorage block data: group, key, version and
/// data.
pub fn sha256_pack(
            group: &[u8; 32], key: &[u8; 32],
            version: u64, data: &[u8]
        ) -> [u8; 32] {
    let bytes = [group, key, &version.to_le_bytes()[..], data].concat();
    sha256_hash(&bytes)
}


/// Generates a random pair of private and public keys by given `schema`.
pub fn generate_pair<T: CurveTrait<4>, R: Rng + ?Sized>(
            rng: &mut R, schema: &Schema<T, 4>
        ) -> ([u8; 32], [u8; 64]) {
    let (private_key, public_key) = schema.generate_pair(rng);
    let private_bytes = private_key_to_bytes(&private_key);
    let public_bytes = public_key_to_bytes(&public_key);
    (private_bytes, public_bytes)
}


/// Chechs whether the key pair is valid.
pub fn check_pair<T: CurveTrait<4>>(
            schema: &Schema<T, 4>,
            private_key: &[u8; 32], public_key: &[u8; 64]
        ) -> bool {
    let private_bigi = private_key_from_bytes(private_key);
    let public_point = public_key_from_bytes(public_key);
    let public_point_calculated = schema.get_point(&private_bigi);
    public_point == public_point_calculated
}


#[cfg(test)]
mod tests {
    use bigi_ecc::schemas::load_secp256k1;

    use super::*;

    #[test]
    fn test_pair() {
        let mut rng = rand::thread_rng();
        let schema = load_secp256k1();
        let (private_key, public_key) = generate_pair(&mut rng, &schema);
        assert_eq!(check_pair(&schema, &private_key, &public_key), true);
    }

    #[test]
    fn test_signature() {
        let mut rng = rand::thread_rng();
        let schema = load_secp256k1();
        let (private_key, public_key) = generate_pair(&mut rng, &schema);

        let group: [u8; 32] = str_to_bytes_sized("my group");
        let key: [u8; 32] = str_to_bytes_sized("my key");
        let version: u64 = 1;
        let data = b"my test data";

        let signature = build_signature(
            &mut rng, &schema, &private_key, &group, &key, version, data
        );

        let result = check_signature(
            &schema, &signature, &public_key, &group, &key, version, data
        );
        assert_eq!(result, true);
    }
}
