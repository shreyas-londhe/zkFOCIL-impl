/// Converts a 32-byte little-endian array to big-endian.
///
/// # Arguments
///
/// * `bytes` - The little-endian byte array.
///
/// # Returns
///
/// The big-endian representation of the input byte array.
pub fn le_to_be(bytes: [u8; 32]) -> [u8; 32] {
    // Safety: The result is a valid big-endian representation of the input
    let result = unsafe { __le_to_be(bytes) };
    for i in 0..32 {
        assert(result[i] == bytes[31 - i]);
    }
    result
}

unconstrained fn __le_to_be(bytes: [u8; 32]) -> [u8; 32] {
    let mut result: [u8; 32] = [0; 32];
    for i in 0..32 {
        result[i] = bytes[31 - i];
    }
    result
}

/// Combines two 32-byte arrays into a single 64-byte array.
///
/// # Arguments
///
/// * `a` - The first byte array.
/// * `b` - The second byte array.
///
/// # Returns
///
/// A 64-byte array containing the bytes of `a` followed by the bytes of `b`.
pub fn combine_bytes(a: [u8; 32], b: [u8; 32]) -> [u8; 64] {
    // Safety: The result is a valid combination of the input byte arrays
    let result = unsafe { __combine_bytes(a, b) };
    for i in 0..32 {
        assert(result[i] == a[i]);
        assert(result[i + 32] == b[i]);
    }
    result
}

unconstrained fn __combine_bytes(a: [u8; 32], b: [u8; 32]) -> [u8; 64] {
    let mut result: [u8; 64] = [0; 64];
    for i in 0..32 {
        result[i] = a[i];
        result[i + 32] = b[i];
    }
    result
}
