#pragma once

#include "barretenberg/crypto/merkle_tree/membership.hpp"
#include "barretenberg/crypto/pedersen_commitment/pedersen.hpp"
#include "barretenberg/ecc/curves/grumpkin/grumpkin.hpp"
#include "barretenberg/stdlib/hash/blake2s/blake2s.hpp"
#include "barretenberg/stdlib/hash/pedersen/pedersen.hpp"
#include "barretenberg/stdlib/primitives/circuit_builders/circuit_builders_fwd.hpp"
#include "barretenberg/stdlib/primitives/group/cycle_group.hpp"
#include "zkfocil.hpp"
#include <array>

namespace bb::stdlib::zkfocil {

constexpr size_t VALIDATOR_TREE_DEPTH = 20; // 2^20 = 1M leaves

template <typename Builder, typename Curve, typename Fq, typename Fr, typename G1>
bool_t<Builder> zkfocil_circuit(const zkfocil_inputs<Builder, Curve, Fq, Fr, G1>& inputs)
{
    using field_ct = stdlib::field_t<Builder>;
    using byte_array_ct = stdlib::byte_array<Builder>;
    using bool_ct = stdlib::bool_t<Builder>;

    // Get the builder context from the inputs
    Builder* builder = nullptr;
    auto try_get_context = [&](auto&& field) {
        if (builder == nullptr) {
            builder = field.get_context();
        }
    };
    try_get_context(inputs.slot_identifier);
    try_get_context(inputs.secret_key);
    try_get_context(inputs.public_key);
    try_get_context(inputs.key_image);
    try_get_context(inputs.merkle_root);
    try_get_context(inputs.index_in_merkle_tree);
    if (builder == nullptr) {
        throw std::runtime_error("no context found for zkfocil circuit");
    }

    // Check if the public key is valid
    auto computed_public_key = G1::batch_mul({ G1::one(builder) }, { inputs.secret_key });
    inputs.public_key.x.assert_equal(computed_public_key.x);
    inputs.public_key.y.assert_equal(computed_public_key.y);

    // Compute the input to the hash function
    // The input is the concatenation of the secret key and the slot identifier
    // The input is a byte array, so we need to convert the secret key and slot identifier to byte arrays
    // and then concatenate them
    byte_array_ct secret_key_array = inputs.secret_key.to_byte_array();
    byte_array_ct slot_identifier_array = byte_array_ct(inputs.slot_identifier);
    byte_array_ct hash_input_array(builder);
    hash_input_array.write(secret_key_array);
    hash_input_array.write(slot_identifier_array);

    // Compute Blake2s hash of the input, and cast it to a field element
    // Note that output of Blake2s is 32 bytes, and we convert it to a bigfield element
    byte_array_ct hash_output = blake2s(hash_input_array);
    Fr hash_output_field(hash_output.slice(0, 32));

    // Check if key image is valid
    auto computed_key_image = G1::batch_mul({ G1::one(builder) }, { hash_output_field });
    inputs.key_image.x.assert_equal(computed_key_image.x);
    inputs.key_image.y.assert_equal(computed_key_image.y);

    // Now check if the merkle path is valid
    byte_array_ct public_key_array = inputs.public_key.to_byte_array();
    byte_array_ct public_key_hash = blake2s(public_key_array);
    field_ct leaf_value(public_key_hash.slice(0, 32));

    const bool_ct exists = bb::crypto::merkle_tree::check_membership(
        inputs.merkle_root,
        inputs.merkle_path,
        leaf_value,
        inputs.index_in_merkle_tree.value.decompose_into_bits(VALIDATOR_TREE_DEPTH));
    exists.assert_equal(true, "public key is not an active validator");

    return bool_t<Builder>(builder, true);
}

} // namespace bb::stdlib::zkfocil
