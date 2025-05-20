#include <benchmark/benchmark.h>

#include "barretenberg/benchmark/ultra_bench/mock_circuits.hpp"
#include "barretenberg/stdlib_circuit_builders/ultra_circuit_builder.hpp"
#include "barretenberg/ultra_honk/ultra_verifier.hpp"

using namespace benchmark;
using namespace bb;

/**
 * @brief Benchmark: Construction of a Ultra Honk proof for a circuit determined by the provided circuit function
 */
static void construct_proof_ultrahonk(State& state,
                                      void (*test_circuit_function)(UltraCircuitBuilder&, size_t)) noexcept
{
    size_t num_iterations = 10; // 10x the circuit
    bb::mock_circuits::construct_proof_with_specified_num_iterations<UltraProver>(
        state, test_circuit_function, num_iterations);
}

static void verify_proof_ultrahonk(State& state, void (*test_circuit_function)(UltraCircuitBuilder&, size_t)) noexcept
{
    size_t num_iterations = 10; // 10x the circuit
    bb::mock_circuits::verify_proof_with_specified_num_iterations<UltraProver, UltraVerifier>(
        state, test_circuit_function, num_iterations);
}

/**
 * @brief Benchmark: Witness generation of a Ultra Honk proof for a circuit determined by the provided circuit function
 */
static void generate_witness_ultrahonk(State& state,
                                       void (*test_circuit_function)(UltraCircuitBuilder&, size_t)) noexcept
{
    size_t num_iterations = 10; // 10x the circuit
    bb::mock_circuits::generate_prover_with_specified_num_iterations<UltraProver>(
        state, test_circuit_function, num_iterations);
}

/**
 * @brief Benchmark: Construction of a Ultra Plonk proof with 2**n gates
 */
static void construct_proof_ultrahonk_power_of_2(State& state) noexcept
{
    auto log2_of_gates = static_cast<size_t>(state.range(0));
    bb::mock_circuits::construct_proof_with_specified_num_iterations<UltraProver>(
        state, &bb::mock_circuits::generate_basic_arithmetic_circuit<UltraCircuitBuilder>, log2_of_gates);
}

// Define benchmarks
BENCHMARK_CAPTURE(construct_proof_ultrahonk, sha256, &stdlib::generate_sha256_test_circuit<UltraCircuitBuilder>)
    ->Unit(kMillisecond);
BENCHMARK_CAPTURE(construct_proof_ultrahonk, keccak, &stdlib::generate_keccak_test_circuit<UltraCircuitBuilder>)
    ->Unit(kMillisecond);
BENCHMARK_CAPTURE(construct_proof_ultrahonk,
                  ecdsa_verification,
                  &stdlib::generate_ecdsa_verification_test_circuit<UltraCircuitBuilder>)
    ->Unit(kMillisecond);
BENCHMARK_CAPTURE(construct_proof_ultrahonk,
                  merkle_membership,
                  &stdlib::generate_merkle_membership_test_circuit<UltraCircuitBuilder>)
    ->Unit(kMillisecond);

BENCHMARK_CAPTURE(generate_witness_ultrahonk,
                  zkfocil_secp256k1,
                  &stdlib::zkfocil::generate_zkfocil_test_circuit<UltraCircuitBuilder,
                                                                  stdlib::secp256k1<UltraCircuitBuilder>,
                                                                  stdlib::secp256k1<UltraCircuitBuilder>::fr,
                                                                  stdlib::secp256k1<UltraCircuitBuilder>::g1,
                                                                  stdlib::secp256k1<UltraCircuitBuilder>::fq_ct,
                                                                  stdlib::secp256k1<UltraCircuitBuilder>::bigfr_ct,
                                                                  stdlib::secp256k1<UltraCircuitBuilder>::g1_bigfr_ct>)
    ->Unit(kMillisecond)
    ->Iterations(10);

BENCHMARK_CAPTURE(generate_witness_ultrahonk,
                  zkfocil_bn254,
                  &stdlib::zkfocil::generate_zkfocil_test_circuit<UltraCircuitBuilder,
                                                                  stdlib::bn254<UltraCircuitBuilder>,
                                                                  stdlib::bn254<UltraCircuitBuilder>::ScalarFieldNative,
                                                                  stdlib::bn254<UltraCircuitBuilder>::GroupNative,
                                                                  stdlib::bn254<UltraCircuitBuilder>::fq_ct,
                                                                  stdlib::bn254<UltraCircuitBuilder>::ScalarField,
                                                                  stdlib::bn254<UltraCircuitBuilder>::Group>)
    ->Unit(kMillisecond)
    ->Iterations(10);

BENCHMARK_CAPTURE(construct_proof_ultrahonk,
                  zkfocil_secp256k1,
                  &stdlib::zkfocil::generate_zkfocil_test_circuit<UltraCircuitBuilder,
                                                                  stdlib::secp256k1<UltraCircuitBuilder>,
                                                                  stdlib::secp256k1<UltraCircuitBuilder>::fr,
                                                                  stdlib::secp256k1<UltraCircuitBuilder>::g1,
                                                                  stdlib::secp256k1<UltraCircuitBuilder>::fq_ct,
                                                                  stdlib::secp256k1<UltraCircuitBuilder>::bigfr_ct,
                                                                  stdlib::secp256k1<UltraCircuitBuilder>::g1_bigfr_ct>)
    ->Unit(kMillisecond)
    ->Iterations(10);

BENCHMARK_CAPTURE(construct_proof_ultrahonk,
                  zkfocil_bn254,
                  &stdlib::zkfocil::generate_zkfocil_test_circuit<UltraCircuitBuilder,
                                                                  stdlib::bn254<UltraCircuitBuilder>,
                                                                  stdlib::bn254<UltraCircuitBuilder>::ScalarFieldNative,
                                                                  stdlib::bn254<UltraCircuitBuilder>::GroupNative,
                                                                  stdlib::bn254<UltraCircuitBuilder>::fq_ct,
                                                                  stdlib::bn254<UltraCircuitBuilder>::ScalarField,
                                                                  stdlib::bn254<UltraCircuitBuilder>::Group>)
    ->Unit(kMillisecond)
    ->Iterations(10);

BENCHMARK_CAPTURE(verify_proof_ultrahonk,
                  zkfocil_secp256k1,
                  &stdlib::zkfocil::generate_zkfocil_test_circuit<UltraCircuitBuilder,
                                                                  stdlib::secp256k1<UltraCircuitBuilder>,
                                                                  stdlib::secp256k1<UltraCircuitBuilder>::fr,
                                                                  stdlib::secp256k1<UltraCircuitBuilder>::g1,
                                                                  stdlib::secp256k1<UltraCircuitBuilder>::fq_ct,
                                                                  stdlib::secp256k1<UltraCircuitBuilder>::bigfr_ct,
                                                                  stdlib::secp256k1<UltraCircuitBuilder>::g1_bigfr_ct>)
    ->Unit(kMillisecond)
    ->Iterations(10);

BENCHMARK_CAPTURE(verify_proof_ultrahonk,
                  zkfocil_bn254,
                  &stdlib::zkfocil::generate_zkfocil_test_circuit<UltraCircuitBuilder,
                                                                  stdlib::bn254<UltraCircuitBuilder>,
                                                                  stdlib::bn254<UltraCircuitBuilder>::ScalarFieldNative,
                                                                  stdlib::bn254<UltraCircuitBuilder>::GroupNative,
                                                                  stdlib::bn254<UltraCircuitBuilder>::fq_ct,
                                                                  stdlib::bn254<UltraCircuitBuilder>::ScalarField,
                                                                  stdlib::bn254<UltraCircuitBuilder>::Group>)
    ->Unit(kMillisecond)
    ->Iterations(10);

BENCHMARK(construct_proof_ultrahonk_power_of_2)
    // 2**15 gates to 2**20 gates
    ->DenseRange(15, 20)
    ->Unit(kMillisecond);

BENCHMARK_MAIN();
