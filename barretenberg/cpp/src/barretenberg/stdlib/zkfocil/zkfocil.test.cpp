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

using curveR1 = stdlib::secp256r1<Builder>;

namespace {
auto& engine = numeric::get_debug_randomness();
}

TEST(stdlibZkfocil, zkfocilBasic)
{
    using curve_ = stdlib::secp256k1<Builder>;
    using fr = typename curve_::fr;
    using g1 = typename curve_::g1;
    using bool_ct = stdlib::bool_t<Builder>;
    using fq_ct = curve_::fq_ct;
    using bigfr_ct = curve_::bigfr_ct;
    using g1_bigfr_ct = curve_::g1_bigfr_ct;

    Builder builder = Builder();

    auto zkfocil_inputs =
        stdlib::zkfocil::construct_zkfocil_inputs<Builder, curve_, fr, g1, fq_ct, bigfr_ct, g1_bigfr_ct>(builder, 0);

    // Call the zkfocil circuit
    bool_ct zkfocil_result =
        stdlib::zkfocil::zkfocil_circuit<Builder, curve_, fq_ct, bigfr_ct, g1_bigfr_ct>(zkfocil_inputs);
    zkfocil_result.assert_equal(true, "zkfocil circuit failed");
    bool proof_result = CircuitChecker::check(builder);
    EXPECT_EQ(proof_result, true);

    std::cerr << "num gates = " << builder.get_estimated_num_finalized_gates() << "\n";

    benchmark_info(
        Builder::NAME_STRING, "zkfocil", "Circuit", "Gate Count", builder.get_estimated_num_finalized_gates());
}

TEST(stdlibZkfocil, zkfocilBn254Basic)
{
    using curve_ = stdlib::bn254<Builder>;
    using fr = typename curve_::ScalarFieldNative;
    using g1 = typename curve_::GroupNative;
    using bool_ct = stdlib::bool_t<Builder>;
    using fq_ct = stdlib::bigfield<Builder, Bn254FqParams>;
    using fr_ct = stdlib::field_t<Builder>;
    using g1_ct = curve_::Group;

    Builder builder = Builder();

    auto zkfocil_inputs =
        stdlib::zkfocil::construct_zkfocil_inputs<Builder, curve_, fr, g1, fq_ct, fr_ct, g1_ct>(builder, 0);

    // Call the zkfocil circuit
    bool_ct zkfocil_result = stdlib::zkfocil::zkfocil_circuit<Builder, curve_, fq_ct, fr_ct, g1_ct>(zkfocil_inputs);
    zkfocil_result.assert_equal(true, "zkfocil circuit failed");
    bool proof_result = CircuitChecker::check(builder);
    EXPECT_EQ(proof_result, true);

    std::cerr << "num gates = " << builder.get_estimated_num_finalized_gates() << "\n";

    // Log plookup table usage
    std::cerr << "\n=== PLOOKUP TABLE USAGE ===" << "\n";
    std::cerr << "Total basic lookup tables: " << builder.lookup_tables.size() << "\n";

    // Helper function to get table name
    auto get_table_name = [](plookup::BasicTableId id) -> std::string {
        switch (id) {
            case plookup::BasicTableId::BN254_X_14BIT_BASIC: return "BN254_X_14BIT";
            case plookup::BasicTableId::BN254_Y_14BIT_BASIC: return "BN254_Y_14BIT";
            case plookup::BasicTableId::BN254_X_14BIT_ENDO_BASIC: return "BN254_X_ENDO_14BIT";
            case plookup::BasicTableId::BLAKE_XOR_ROTATE0: return "BLAKE_XOR_ROTATE0";
            case plookup::BasicTableId::BLAKE_XOR_ROTATE1: return "BLAKE_XOR_ROTATE1";
            case plookup::BasicTableId::BLAKE_XOR_ROTATE2: return "BLAKE_XOR_ROTATE2";
            case plookup::BasicTableId::BLAKE_XOR_ROTATE4: return "BLAKE_XOR_ROTATE4";
            case plookup::BasicTableId::BLAKE_XOR_ROTATE0_SLICE5_MOD4: return "BLAKE_XOR_ROTATE0_SLICE5_MOD4";
            default: return "Unknown(" + std::to_string(static_cast<int>(id)) + ")";
        }
    };

    // Count table entries by type
    std::map<plookup::BasicTableId, size_t> table_sizes;
    for (const auto& table : builder.lookup_tables) {
        size_t entries = table.column_1.size();
        table_sizes[table.id] = entries;
        std::cerr << get_table_name(table.id) << " (ID " << static_cast<int>(table.id) << "): "
                  << entries << " entries" << "\n";
    }

    // Calculate total size
    size_t total_table_entries = 0;
    for (const auto& [id, size] : table_sizes) {
        total_table_entries += size;
    }
    std::cerr << "\nTotal cumulative table entries: " << total_table_entries << "\n";
    std::cerr << "========================\n" << "\n";

    benchmark_info(
        Builder::NAME_STRING, "zkfocil", "Circuit", "Gate Count", builder.get_estimated_num_finalized_gates());
}

TEST(stdlibZkfocil, verifyProof)
{
    using curve_ = stdlib::secp256k1<Builder>;
    using fr = typename curve_::fr;
    using g1 = typename curve_::g1;
    using bool_ct = stdlib::bool_t<Builder>;
    using fq_ct = curve_::fq_ct;
    using bigfr_ct = curve_::bigfr_ct;
    using g1_bigfr_ct = curve_::g1_bigfr_ct;

    Builder builder = Builder();

    auto zkfocil_inputs =
        stdlib::zkfocil::construct_zkfocil_inputs<Builder, curve_, fr, g1, fq_ct, bigfr_ct, g1_bigfr_ct>(builder, 0);

    // Call the zkfocil circuit
    bool_ct zkfocil_result =
        stdlib::zkfocil::zkfocil_circuit<Builder, curve_, fq_ct, bigfr_ct, g1_bigfr_ct>(zkfocil_inputs);
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

    std::cout << "Proof size: " << proof.size() << " bytes"
              << "\n";

    auto start = std::chrono::high_resolution_clock::now();
    bool verified = verifier.verify_proof(proof);
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    std::cout << "Verification time: " << duration.count() << " microseconds"
              << "\n";

    EXPECT_EQ(verified, true);
}

TEST(stdlibZkfocil, verifyBn254Proof)
{
    using curve_ = stdlib::bn254<Builder>;
    using fr = typename curve_::ScalarFieldNative;
    using g1 = typename curve_::GroupNative;
    using bool_ct = stdlib::bool_t<Builder>;
    using fq_ct = stdlib::bigfield<Builder, Bn254FqParams>;
    using fr_ct = stdlib::field_t<Builder>;
    using g1_ct = curve_::Group;

    Builder builder = Builder();

    auto zkfocil_inputs =
        stdlib::zkfocil::construct_zkfocil_inputs<Builder, curve_, fr, g1, fq_ct, fr_ct, g1_ct>(builder, 0);

    // Call the zkfocil circuit
    bool_ct zkfocil_result = stdlib::zkfocil::zkfocil_circuit<Builder, curve_, fq_ct, fr_ct, g1_ct>(zkfocil_inputs);
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

    std::cout << "Proof size: " << proof.size() << " bytes"
              << "\n";

    auto start = std::chrono::high_resolution_clock::now();
    bool verified = verifier.verify_proof(proof);
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    std::cout << "Verification time: " << duration.count() << " microseconds"
              << "\n";

    EXPECT_EQ(verified, true);
}
