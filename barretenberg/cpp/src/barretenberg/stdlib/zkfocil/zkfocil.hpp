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

// Define builder type (which determines the arithmetisation)
using Builder = UltraCircuitBuilder;

// Define types
using witness_ct = stdlib::witness_t<Builder>;
using public_witness_ct = stdlib::public_witness_t<Builder>;
using bool_ct = stdlib::bool_t<Builder>;
using byte_array_ct = stdlib::byte_array<Builder>;
using field_ct = stdlib::field_t<Builder>;
using suint_ct = stdlib::safe_uint_t<Builder>;
using uint32_ct = stdlib::uint32<Builder>;
using group_ct = stdlib::cycle_group<Builder>;
using bn254 = stdlib::bn254<Builder>;
using hash_path_ct = crypto::merkle_tree::hash_path<Builder>;

// Inputs to the circuit that implements zkFOCIL
struct zkfocil_inputs {
    field_ct slot_identifier;
    field_ct secret_key;
    group_ct public_key;
    group_ct key_image;
    field_ct merkle_root;
    suint_ct index_in_merkle_tree;
    hash_path_ct merkle_path;
};

void zkfocil_circuit(const zkfocil_inputs& inputs);

template <typename C> struct schnorr_signature_bits {
    typename cycle_group<C>::cycle_scalar s;
    typename cycle_group<C>::cycle_scalar e;
};

template <typename C>
schnorr_signature_bits<C> schnorr_convert_signature(C* context, const crypto::schnorr_signature& sig);

template <typename C>
std::array<field_t<C>, 2> schnorr_verify_signature_internal(const byte_array<C>& message,
                                                            const cycle_group<C>& pub_key,
                                                            const schnorr_signature_bits<C>& sig);

template <typename C>
void schnorr_verify_signature(const byte_array<C>& message,
                              const cycle_group<C>& pub_key,
                              const schnorr_signature_bits<C>& sig);

template <typename C>
bool_t<C> schnorr_signature_verification_result(const byte_array<C>& message,
                                                const cycle_group<C>& pub_key,
                                                const schnorr_signature_bits<C>& sig);

} // namespace bb::stdlib::zkfocil
