#include "zkfocil.hpp"
#include "barretenberg/crypto/pedersen_commitment/pedersen.hpp"
#include "barretenberg/ecc/curves/grumpkin/grumpkin.hpp"
#include "barretenberg/stdlib/hash/blake2s/blake2s.hpp"
#include "barretenberg/stdlib/hash/pedersen/pedersen.hpp"
#include "barretenberg/stdlib/primitives/circuit_builders/circuit_builders_fwd.hpp"
#include "barretenberg/stdlib/primitives/group/cycle_group.hpp"
#include <array>

namespace bb::stdlib::zkfocil {

void zkfocil_circuit(const zkfocil_inputs& inputs)
{
    // using namespace bb::crypto;
    // using namespace bb::stdlib;

    // Check that the public key is valid
    inputs.public_key.assert_is_valid_point("public key is not valid");

    // Check that the key image is valid
    inputs.key_image.assert_is_valid_point("key image is not valid");

    // Check that the secret key is a valid scalar
    inputs.secret_key.assert_is_valid_scalar("secret key is not valid");

    // Check that the index in the merkle tree is less than the size of the tree
    inputs.index_in_merkle_tree.assert_less_than(crypto::merkle_tree::MAX_TREE_DEPTH, "index out of bounds");

    // Check that the merkle path is valid
    inputs.merkle_path.assert_is_valid_path(inputs.merkle_root, inputs.index_in_merkle_tree);
}

} // namespace bb::stdlib::zkfocil
