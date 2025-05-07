use crate::bytes::combine_bytes;
use dep::bignum::{BigNum, fields::U256::U256};
use dep::noir_bigcurve::{
    BigCurveTrait,
    curves::secp256k1::{Secp256k1, Secp256k1Scalar},
    ScalarFieldTrait,
};
use std::hash::blake2s;

/// Converts a 32-byte big-endian array to a Secp256k1 scalar field element.
///
/// # Arguments
///
/// * `bytes` - The big-endian byte array.
///
/// # Returns
///
/// The corresponding scalar field element.
pub fn bytes_to_scalar(bytes: [u8; 32]) -> Secp256k1Scalar {
    // Safety: Expand the scalar to 33 bytes
    let bn_bytes = unsafe { __expand_scalar(bytes) };
    assert(bn_bytes[0] == 0);
    for i in 1..33 {
        assert(bn_bytes[i] == bytes[i - 1]);
    }

    let bn = U256::from_be_bytes(bn_bytes);
    Secp256k1Scalar::from_bignum(bn)
}

unconstrained fn __expand_scalar(bytes: [u8; 32]) -> [u8; 33] {
    let mut bn_bytes: [u8; 33] = [0; 33];
    for i in 0..32 {
        bn_bytes[i + 1] = bytes[i];
    }
    bn_bytes
}

/// Multiplies a Secp256k1 scalar by a Secp256k1 curve point.
///
/// # Arguments
///
/// * `scalar` - The scalar multiplier.
/// * `point` - The curve point.
///
/// # Returns
///
/// The result of the scalar multiplication.
fn scalar_mul_point(scalar: Secp256k1Scalar, point: Secp256k1) -> Secp256k1 {
    point.mul(scalar)
}

/// Derives the public key from a secret key scalar.
/// This computes `secret_key * G`, where G is the generator point.
///
/// # Arguments
///
/// * `secret_key` - The secret key as a scalar field element.
///
/// # Returns
///
/// The corresponding public key (a curve point).
pub fn derive_public_key(secret_key: Secp256k1Scalar) -> Secp256k1 {
    scalar_mul_point(secret_key, Secp256k1::one()) // Secp256k1::one() is the conventional generator G
}

/// Derives the key image from the secret key and block parameters.
/// Computes `H(secret_key_bytes || block_params) * G`, where H is blake2s and G is the generator point.
///
/// # Arguments
///
/// * `secret_key_bytes` - The secret key as a 32-byte big-endian array.
/// * `block_params` - The block parameters as a 32-byte big-endian array.
///
/// # Returns
///
/// The key image (a curve point).
pub fn derive_key_image(secret_key_bytes: [u8; 32], block_params: [u8; 32]) -> Secp256k1 {
    let combined_bytes = combine_bytes(secret_key_bytes, block_params);
    let hash = blake2s::<64>(combined_bytes);
    let hash_scalar: Secp256k1Scalar = bytes_to_scalar(hash);
    scalar_mul_point(hash_scalar, Secp256k1::one())
}

/// Serializes a Secp256k1 point (public key) into a byte array.
/// Concatenates the little-endian byte representations of the x and y coordinates.
/// Each coordinate (Fq element) is 32 bytes. Total output is 64 bytes.
///
/// # Arguments
///
/// * `pk` - The Secp256k1 point (public key).
///
/// # Returns
///
/// A 64-byte array representing the serialized public key (x_bytes_le || y_bytes_le).
fn serialize_public_key_le(pk: Secp256k1) -> [u8; 64] {
    // BLS12_381 coordinates are Fq elements, which are 48 bytes each.
    let x_bytes: [u8; 32] = pk.x.to_le_bytes();
    let y_bytes: [u8; 32] = pk.y.to_le_bytes();

    // Safety: The result is a valid combination of the input byte arrays
    let combined = unsafe { __combine_coordinates(x_bytes, y_bytes) };
    for i in 0..32 {
        assert(combined[i] == x_bytes[i]);
        assert(combined[i + 32] == y_bytes[i]);
    }
    combined
}

unconstrained fn __combine_coordinates(x_bytes: [u8; 32], y_bytes: [u8; 32]) -> [u8; 64] {
    let mut combined: [u8; 64] = [0; 64];
    for i in 0..32 {
        combined[i] = x_bytes[i];
        combined[i + 32] = y_bytes[i];
    }
    combined
}

/// Hashes a Secp256k1 public key using Blake2s.
/// Serializes the point coordinates (x, y) in little-endian format, concatenates them,
/// and then computes the Blake2s hash of the resulting 64 bytes.
///
/// # Arguments
///
/// * `public_key` - The Secp256k1 point representing the public key.
///
/// # Returns
///
/// The 32-byte Blake2s hash of the serialized public key (little-endian).
pub fn hash_public_key(public_key: Secp256k1) -> [u8; 32] {
    // Serialize the public key (x || y, both LE)
    let serialized_pk = serialize_public_key_le(public_key); // [u8; 64]

    // Hash the serialized bytes
    // Need to specify the input length for blake2s
    // TODO: Compressed public key can be used to reduce computation
    let hash_result = blake2s::<64>(serialized_pk); // Returns [u8; 32] LE

    hash_result
}
