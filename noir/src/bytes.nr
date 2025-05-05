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
