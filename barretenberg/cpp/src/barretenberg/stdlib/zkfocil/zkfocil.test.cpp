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
