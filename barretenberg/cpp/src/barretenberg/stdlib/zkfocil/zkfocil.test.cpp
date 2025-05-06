#include <gtest/gtest.h>

#include "barretenberg/circuit_checker/circuit_checker.hpp"
#include "barretenberg/crypto/merkle_tree/index.hpp"
#include "barretenberg/crypto/pedersen_commitment/pedersen.hpp"
#include "barretenberg/ecc/curves/grumpkin/grumpkin.hpp"
#include "barretenberg/stdlib/primitives/curves/secp256k1.hpp"
#include "barretenberg/stdlib/primitives/curves/secp256r1.hpp"
#include "barretenberg/stdlib_circuit_builders/ultra_circuit_builder.hpp"
#include "barretenberg/stdlib_circuit_builders/ultra_flavor.hpp"
#include "barretenberg/ultra_honk/decider_proving_key.hpp"
#include "barretenberg/ultra_honk/ultra_prover.hpp"
#include "barretenberg/ultra_honk/ultra_verifier.hpp"
#include "zkfocil.hpp"

using namespace bb;
using namespace bb::crypto;

using Builder = UltraCircuitBuilder;
using curve_ = stdlib::secp256k1<Builder>;
using curveR1 = stdlib::secp256r1<Builder>;

using bb_fr = bb::fr;
using MemoryTree = bb::crypto::merkle_tree::MemoryStore;
using PedersenHashPolicy = bb::crypto::merkle_tree::PedersenHashPolicy;
using MerkleTree = bb::crypto::merkle_tree::MerkleTree<MemoryTree, PedersenHashPolicy>;

using bool_ct = stdlib::bool_t<Builder>;
using byte_array_ct = stdlib::byte_array<Builder>;
using field_ct = stdlib::field_t<Builder>;
using suint_ct = stdlib::safe_uint_t<Builder>;
using witness_ct = stdlib::witness_t<Builder>;

namespace {
auto& engine = numeric::get_debug_randomness();
}

TEST(stdlibZkfocil, zkfocilBasic)
{
    using Fr = curve_::fr;
    using G1 = curve_::g1;
    using fq_ct = curve_::fq_ct;
    using bigfr_ct = curve_::bigfr_ct;
    using g1_bigfr_ct = curve_::g1_bigfr_ct;

    Builder builder = Builder();

    // Generate a key pair
    Fr native_private_key = Fr::random_element();
    G1::affine_element native_public_key = G1::one * native_private_key;

    // Generate a key image
    // K = H(s || t) * G
    bb_fr slot_identifier = bb_fr::random_element();
    std::vector<uint8_t> slot_identifier_bytes = slot_identifier.to_buffer();
    std::vector<uint8_t> sk_bytes = native_private_key.to_buffer();
    std::vector<uint8_t> key_image_secret_bytes = sk_bytes;
    key_image_secret_bytes.insert(
        key_image_secret_bytes.end(), slot_identifier_bytes.begin(), slot_identifier_bytes.end());
    auto hash_input_bytes = blake2s(key_image_secret_bytes);
    Fr key_image_secret = Fr::serialize_from_buffer(&hash_input_bytes[0]);
    G1::affine_element native_key_image = G1::one * key_image_secret;

    // Generate a Merkle tree
    // The Merkle tree is a binary tree with 2^20 leaves
    // The leaves are the (hash of) public keys of the validators
    size_t tree_depth = 20;
    auto store = std::make_unique<MemoryTree>();
    auto tree = std::make_unique<MerkleTree>(*store, tree_depth);

    // Fill a few leaves with (random) public keys
    for (size_t i = 0; i < 100; ++i) {
        uint256_t index = engine.get_random_uint256() % (uint256_t(1) << tree_depth);
        tree->update_element(index, bb_fr::random_element());
    }

    // Now fill at (random) index the hash of the public key
    uint256_t native_validator_index = engine.get_random_uint256() % (uint256_t(1) << tree_depth);
    auto native_validator_hash_bytes = blake2s(native_public_key.to_buffer());
    bb_fr native_validator_leaf = bb_fr::serialize_from_buffer(&native_validator_hash_bytes[0]);
    tree->update_element(native_validator_index, native_validator_leaf);
    auto native_tree_root = tree->root();

    // Generate a Merkle path to the leaf
    merkle_tree::fr_hash_path native_path = tree->get_hash_path(native_validator_index);

    // Convert the native path to circuit-native and construct zkfocil inputs
    stdlib::zkfocil::zkfocil_inputs<Builder, curve_, fq_ct, bigfr_ct, g1_bigfr_ct> ckt_inputs = {
        .slot_identifier = witness_ct(&builder, slot_identifier),
        .secret_key = bigfr_ct::from_witness(&builder, native_private_key),
        .public_key = g1_bigfr_ct::from_witness(&builder, native_public_key),
        .key_image = g1_bigfr_ct::from_witness(&builder, native_key_image),
        .merkle_root = field_ct::from_witness(&builder, native_tree_root),
        .index_in_merkle_tree = suint_ct(witness_ct(&builder, native_validator_index), tree_depth, "val_index"),
        .merkle_path = merkle_tree::create_witness_hash_path(builder, native_path),
    };

    // Call the zkfocil circuit
    bool_ct zkfocil_result =
        stdlib::zkfocil::zkfocil_circuit<Builder, curve_, fq_ct, bigfr_ct, g1_bigfr_ct>(ckt_inputs);
    zkfocil_result.assert_equal(true, "zkfocil circuit failed");
    bool proof_result = CircuitChecker::check(builder);
    EXPECT_EQ(proof_result, true);

    std::cerr << "num gates = " << builder.get_estimated_num_finalized_gates() << "\n";

    benchmark_info(
        Builder::NAME_STRING, "zkfocil", "Circuit", "Gate Count", builder.get_estimated_num_finalized_gates());
}

TEST(stdlibZkfocil, verifyProof)
{
    using Fr = curve_::fr;
    using G1 = curve_::g1;
    using fq_ct = curve_::fq_ct;
    using bigfr_ct = curve_::bigfr_ct;
    using g1_bigfr_ct = curve_::g1_bigfr_ct;

    Builder builder = Builder();

    // Generate a key pair
    Fr native_private_key = Fr::random_element();
    G1::affine_element native_public_key = G1::one * native_private_key;

    // Generate a key image
    // K = H(s || t) * G
    bb_fr slot_identifier = bb_fr::random_element();
    std::vector<uint8_t> slot_identifier_bytes = slot_identifier.to_buffer();
    std::vector<uint8_t> sk_bytes = native_private_key.to_buffer();
    std::vector<uint8_t> key_image_secret_bytes = sk_bytes;
    key_image_secret_bytes.insert(
        key_image_secret_bytes.end(), slot_identifier_bytes.begin(), slot_identifier_bytes.end());
    auto hash_input_bytes = blake2s(key_image_secret_bytes);
    Fr key_image_secret = Fr::serialize_from_buffer(&hash_input_bytes[0]);
    G1::affine_element native_key_image = G1::one * key_image_secret;

    // Generate a Merkle tree
    // The Merkle tree is a binary tree with 2^20 leaves
    // The leaves are the (hash of) public keys of the validators
    size_t tree_depth = 20;
    auto store = std::make_unique<MemoryTree>();
    auto tree = std::make_unique<MerkleTree>(*store, tree_depth);

    // Fill a few leaves with (random) public keys
    for (size_t i = 0; i < 100; ++i) {
        uint256_t index = engine.get_random_uint256() % (uint256_t(1) << tree_depth);
        tree->update_element(index, bb_fr::random_element());
    }

    // Now fill at (random) index the hash of the public key
    uint256_t native_validator_index = engine.get_random_uint256() % (uint256_t(1) << tree_depth);
    auto native_validator_hash_bytes = blake2s(native_public_key.to_buffer());
    bb_fr native_validator_leaf = bb_fr::serialize_from_buffer(&native_validator_hash_bytes[0]);
    tree->update_element(native_validator_index, native_validator_leaf);
    auto native_tree_root = tree->root();

    // Generate a Merkle path to the leaf
    merkle_tree::fr_hash_path native_path = tree->get_hash_path(native_validator_index);

    // Convert the native path to circuit-native and construct zkfocil inputs
    stdlib::zkfocil::zkfocil_inputs<Builder, curve_, fq_ct, bigfr_ct, g1_bigfr_ct> ckt_inputs = {
        .slot_identifier = witness_ct(&builder, slot_identifier),
        .secret_key = bigfr_ct::from_witness(&builder, native_private_key),
        .public_key = g1_bigfr_ct::from_witness(&builder, native_public_key),
        .key_image = g1_bigfr_ct::from_witness(&builder, native_key_image),
        .merkle_root = field_ct::from_witness(&builder, native_tree_root),
        .index_in_merkle_tree = suint_ct(witness_ct(&builder, native_validator_index), tree_depth, "val_index"),
        .merkle_path = merkle_tree::create_witness_hash_path(builder, native_path),
    };

    // Call the zkfocil circuit
    bool_ct zkfocil_result =
        stdlib::zkfocil::zkfocil_circuit<Builder, curve_, fq_ct, bigfr_ct, g1_bigfr_ct>(ckt_inputs);
    zkfocil_result.assert_equal(true, "zkfocil circuit failed");
    bool proof_result = CircuitChecker::check(builder);
    EXPECT_EQ(proof_result, true);

    // Declare more types
    using DeciderProvingKey = DeciderProvingKey_<UltraFlavor>;
    using VerificationKey = typename UltraFlavor::VerificationKey;
    using Prover = UltraProver_<UltraFlavor>;
    using Verifier = UltraVerifier_<UltraFlavor>;

    // Generate the proof and verify it
    bb::srs::init_crs_factory(bb::srs::get_ignition_crs_path());
    auto proving_key = std::make_shared<DeciderProvingKey>(builder);
    Prover prover(proving_key);
    auto verification_key = std::make_shared<VerificationKey>(proving_key->proving_key);
    Verifier verifier(verification_key);
    auto proof = prover.construct_proof();
    bool verified = verifier.verify_proof(proof);
    EXPECT_EQ(verified, true);
}
