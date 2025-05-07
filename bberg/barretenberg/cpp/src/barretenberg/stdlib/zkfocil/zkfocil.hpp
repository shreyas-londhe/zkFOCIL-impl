#pragma once

#include "../primitives/bool/bool.hpp"
#include "../primitives/byte_array/byte_array.hpp"
#include "../primitives/field/field.hpp"
#include "../primitives/group/cycle_group.hpp"
#include "../primitives/witness/witness.hpp"
#include "barretenberg/crypto/merkle_tree/hash_path.hpp"
#include "barretenberg/crypto/schnorr/schnorr.hpp"
#include "barretenberg/stdlib/primitives/curves/bn254.hpp"

namespace bb::stdlib::zkfocil {

// Inputs to the circuit that implements zkFOCIL
template <typename Builder, typename Curve, typename Fq, typename Fr, typename G1> struct zkfocil_inputs {
    using field_ct = stdlib::field_t<Builder>;
    using hash_path_ct = crypto::merkle_tree::hash_path<Builder>;
    using suint_ct = stdlib::safe_uint_t<Builder>;

    // The slot identifier is a 32-byte field element (circuit-native field element, i.e., bn254::fr)
    field_ct slot_identifier;

    // Validator secret key (bigfield element)
    Fr secret_key;

    // Validator public key (biggroup element)
    G1 public_key;

    // Key image generated from the secret key (biggroup element)
    G1 key_image;

    // Root of the Merkle tree (circuit-native field element)
    field_ct merkle_root;

    // Index of the leaf in the Merkle tree (circuit-native safe uint)
    suint_ct index_in_merkle_tree;

    // The Merkle path to the leaf (array of hash_path_ct)
    hash_path_ct merkle_path;
};

template <typename Builder, typename Curve, typename Fq, typename Fr, typename G1>
bool_t<Builder> zkfocil_circuit(const zkfocil_inputs<Builder, Curve, Fq, Fr, G1>& inputs);

template <typename Builder, typename Curve, typename Fq, typename Fr, typename G1>
zkfocil_inputs<Builder, Curve, Fq, Fr, G1> construct_zkfocil_inputs(Builder& builder, size_t num_iterations);

template <typename Builder, typename Curve> void generate_zkfocil_test_circuit(Builder& builder, size_t num_iterations);

} // namespace bb::stdlib::zkfocil

#include "./zkfocil_impl.hpp"
