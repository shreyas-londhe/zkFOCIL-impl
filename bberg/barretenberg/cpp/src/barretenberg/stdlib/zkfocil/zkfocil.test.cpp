#include <gtest/gtest.h>

#include "barretenberg/circuit_checker/circuit_checker.hpp"
#include "barretenberg/crypto/pedersen_commitment/pedersen.hpp"
#include "barretenberg/ecc/curves/grumpkin/grumpkin.hpp"
#include "barretenberg/stdlib_circuit_builders/ultra_circuit_builder.hpp"
#include "zkfocil.hpp"

using namespace bb;
using namespace bb::crypto;

using Builder = UltraCircuitBuilder;
using bool_ct = stdlib::bool_t<Builder>;
using byte_array_ct = stdlib::byte_array<Builder>;
using field_ct = stdlib::field_t<Builder>;
using witness_ct = stdlib::witness_t<Builder>;

TEST(stdlib_zkfocil, zkfocil_basic)
{
    Builder builder = Builder();
}
