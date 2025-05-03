use crate::bytes::{combine_bytes, le_to_be};
use dep::bignum::{BigNum, fields::U256::U256};
use dep::noir_bigcurve::{
    BigCurveTrait,
    curves::bls12_381::{BLS12_381, BLS12_381Scalar},
    ScalarFieldTrait,
};
use std::hash::blake2s;

/// Converts a 32-byte big-endian array to a BLS12_381 scalar field element.
///
/// # Arguments
///
/// * `bytes` - The big-endian byte array.
///
/// # Returns
///
/// The corresponding scalar field element.
pub fn bytes_to_scalar(bytes: [u8; 32]) -> BLS12_381Scalar {
    // Safety: Expand the scalar to 33 bytes
    let bn_bytes = unsafe { __expand_scalar(bytes) };
    assert(bn_bytes[0] == 0);
    for i in 1..33 {
        assert(bn_bytes[i] == bytes[i - 1]);
    }

    let bn = U256::from_be_bytes(bn_bytes);
    BLS12_381Scalar::from_bignum(bn)
}

unconstrained fn __expand_scalar(bytes: [u8; 32]) -> [u8; 33] {
    let mut bn_bytes: [u8; 33] = [0; 33];
    for i in 0..32 {
        bn_bytes[i + 1] = bytes[i];
    }
    bn_bytes
}

/// Multiplies a BLS12_381 scalar by a BLS12_381 curve point.
///
/// # Arguments
///
/// * `scalar` - The scalar multiplier.
/// * `point` - The curve point.
///
/// # Returns
///
/// The result of the scalar multiplication.
fn scalar_mul_point(scalar: BLS12_381Scalar, point: BLS12_381) -> BLS12_381 {
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
pub fn derive_public_key(secret_key: BLS12_381Scalar) -> BLS12_381 {
    scalar_mul_point(secret_key, BLS12_381::one()) // BLS12_381::one() is the conventional generator G
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
pub fn derive_key_image(secret_key_bytes: [u8; 32], block_params: [u8; 32]) -> BLS12_381 {
    let combined_bytes = combine_bytes(secret_key_bytes, block_params);
    // blake2s returns LE bytes
    let hash_le = blake2s::<64>(combined_bytes);
    // Convert hash to BE for scalar conversion
    let hash_be = le_to_be(hash_le);

    let hash_scalar: BLS12_381Scalar = bytes_to_scalar(hash_be);
    // Multiply the hash scalar by the generator point
    scalar_mul_point(hash_scalar, BLS12_381::one())
}

/// Serializes a BLS12_381 point (public key) into a byte array.
/// Concatenates the little-endian byte representations of the x and y coordinates.
/// Each coordinate (Fq element) is 48 bytes. Total output is 96 bytes.
///
/// # Arguments
///
/// * `pk` - The BLS12_381 point (public key).
///
/// # Returns
///
/// A 96-byte array representing the serialized public key (x_bytes_le || y_bytes_le).
fn serialize_public_key_le(pk: BLS12_381) -> [u8; 96] {
    // BLS12_381 coordinates are Fq elements, which are 48 bytes each.
    let x_bytes: [u8; 48] = pk.x.to_le_bytes();
    let y_bytes: [u8; 48] = pk.y.to_le_bytes();

    // Safety: The result is a valid combination of the input byte arrays
    let combined = unsafe { __combine_coordinates(x_bytes, y_bytes) };
    for i in 0..48 {
        assert(combined[i] == x_bytes[i]);
        assert(combined[i + 48] == y_bytes[i]);
    }
    combined
}

unconstrained fn __combine_coordinates(x_bytes: [u8; 48], y_bytes: [u8; 48]) -> [u8; 96] {
    let mut combined: [u8; 96] = [0; 96];
    for i in 0..48 {
        combined[i] = x_bytes[i];
        combined[i + 48] = y_bytes[i];
    }
    combined
}

/// Hashes a BLS12_381 public key using Blake2s.
/// Serializes the point coordinates (x, y) in little-endian format, concatenates them,
/// and then computes the Blake2s hash of the resulting 96 bytes.
///
/// # Arguments
///
/// * `public_key` - The BLS12_381 point representing the public key.
///
/// # Returns
///
/// The 32-byte Blake2s hash of the serialized public key (little-endian).
pub fn hash_public_key(public_key: BLS12_381) -> [u8; 32] {
    // Serialize the public key (x || y, both LE)
    let serialized_pk = serialize_public_key_le(public_key); // [u8; 96]

    // Hash the serialized bytes
    // Need to specify the input length for blake2s
    // TODO: Compressed public key can be used to reduce computation
    let hash_result = blake2s::<96>(serialized_pk); // Returns [u8; 32] LE

    hash_result
}
