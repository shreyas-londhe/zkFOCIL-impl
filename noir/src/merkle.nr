use crate::bytes::combine_bytes;
use std::hash::blake2s;

/// Hashes two sibling nodes in the Merkle tree using Blake2s.
/// Assumes the input hashes are 32 bytes each. Concatenates left || right.
///
/// # Arguments
///
/// * `left_sibling` - The 32-byte hash of the left sibling node.
/// * `right_sibling` - The 32-byte hash of the right sibling node.
///
/// # Returns
///
/// The 32-byte Blake2s hash of the combined siblings (parent node hash).
/// The result is returned in little-endian format as per blake2s standard output.
fn hash_siblings(left_sibling: [u8; 32], right_sibling: [u8; 32]) -> [u8; 32] {
    // Combine bytes: left || right
    let combined = combine_bytes(left_sibling, right_sibling);
    // Hash the combined bytes
    let parent_hash_le = blake2s::<64>(combined);
    // blake2s returns LE, which is often used directly as node hashes.
    // If BE is needed internally or for comparison, use le_to_be.
    parent_hash_le
}

/// Verifies a Merkle proof for a given leaf against a known root.
/// The proof consists of sibling hashes along the path from the leaf to the root.
///
/// # Type Parameters
///
/// * `N` - The depth of the Merkle tree (number of levels in the proof path).
///
/// # Arguments
///
/// * `root` - The expected Merkle root hash (LE bytes).
/// * `leaf_hash` - The hash of the leaf data (LE bytes).
/// * `path` - An array of sibling hashes constituting the Merkle proof path (LE bytes).
/// * `indices` - An array of bits indicating the position of the node at each level
///               (0 for left, 1 for right). `indices[i]` corresponds to the sibling `path[i]`.
///
/// # Constraints
///
/// * `root`, `leaf_hash`, and elements of `path` must all be 32-byte arrays.
/// * The length of `path` must equal `N`.
/// * The length of `indices` must equal `N`.
///
/// # Returns
///
/// * `bool` - `true` if the proof is valid (computed root matches `root`), `false` otherwise.
pub fn verify_merkle_proof<let N: u32>(
    root: [u8; 32],
    leaf_hash: [u8; 32],
    path: [[u8; 32]; N],
    indices: [bool; N],
) -> bool {
    // Start with the leaf hash
    let mut current_hash = leaf_hash;

    // Iterate up the tree levels
    for i in 0..N {
        let sibling_hash = path[i];
        let index = indices[i]; // 0 if current_hash is left, 1 if current_hash is right

        // Compute the parent hash based on the index
        if index as u8 == 0 {
            // Current node is the left sibling, hash(current | sibling)
            current_hash = hash_siblings(current_hash, sibling_hash);
        } else {
            // Current node is the right sibling, hash(sibling | current)
            current_hash = hash_siblings(sibling_hash, current_hash);
        }
    }

    // Check if the computed root matches the expected root
    current_hash == root
}

#[test]
fn test_merkle_verification() {
    // Example data (replace with actual hashes and path from a known tree)
    // Assume hashes are LE

    // Leaf: H(data)
    let leaf = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20,
    ];
    // Sibling at level 0
    let sibling0 = [
        0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
        0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe,
        0xbf, 0xc0,
    ];
    // Sibling at level 1
    let sibling1 = [
        0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
        0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde,
        0xdf, 0xe0,
    ];

    // Path: [sibling0, sibling1]
    let path = [sibling0, sibling1];
    // Indices: Leaf is left child (0), Parent is right child (1)
    let indices = [false, true]; // bool representation

    // Calculate intermediate and root hashes manually for expected result
    // Parent0 = H(leaf || sibling0)
    let parent0 = hash_siblings(leaf, sibling0);
    // Root = H(sibling1 || parent0) -> because index[1] is 1, parent0 is the right node
    let expected_root = hash_siblings(sibling1, parent0);

    // Verify the proof
    let is_valid = verify_merkle_proof(expected_root, leaf, path, indices);

    // Assert validity
    assert(is_valid);

    // Test invalid case (wrong root)
    let wrong_root = [0; 32];
    let is_invalid = verify_merkle_proof(wrong_root, leaf, path, indices);
    assert(!is_invalid);

    // Test invalid case (wrong path element)
    let wrong_path = [[0; 32], sibling1];
    let is_invalid_path = verify_merkle_proof(expected_root, leaf, wrong_path, indices);
    assert(!is_invalid_path);

    // Test invalid case (wrong index)
    let wrong_indices = [true, false]; // Swapped indices
    let is_invalid_indices = verify_merkle_proof(expected_root, leaf, path, wrong_indices);
    assert(!is_invalid_indices); // This should fail if the root calculation differs
}
