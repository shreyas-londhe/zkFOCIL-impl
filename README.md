# ZKFocil with Barretenberg

ZKFocil circuit is written with the standard library in barretenberg. The circuit specification is described [here](https://hackmd.io/qRtuRAD3Q4KeXZr8TxvUng?view#SNARK-Design-for-zkFOCIL). In this implementation, we test and benchmark the circuit with BN254 and SECP256K1 keys. Ethereum validator keys are on BLS381-12 but BLS is not supported in barretenberg's stdlib. Note that we use BN254 as the base curve of the ZKFocil circuit.

#### Installing Barretenberg

```bash
# Install system dependencies
sudo apt-get update
sudo apt-get install -y cmake clang clang-format ninja-build libstdc++-12-dev

# Clone the repository
git clone https://github.com/shreyas-londhe/zkFOCIL-impl

# Change to the project directory
cd zkFOCIL-impl

# Bootstrap at the top-level (inside bberg/)
# This step sets up dependencies and build configurations
cd bberg
./bootstrap.sh

# Bootstrap at the cpp-level (inside bberg/barretenberg/cpp/)
# This step builds the core Barretenberg library
cd barretenberg/cpp
./bootstrap.sh
```

#### Generate CRS for IPA with BN254

You must generate a BN254 CRS to be used with IPA commitment scheme (with BN254). This is a one-time step and should generate a `transcript00.dat` file in `bberg/barretenberg/cpp/srs_db/bn254/monomial`.

```bash
# We will run the script to generate 2^22 points on the BN254 curve using the "nothing up my sleeves" principle.
# The source code can be found at:
# bberg/barretenberg/cpp/src/barretenberg/bn254_transparent_srs_gen/bn254_transparent_srs_gen.cpp

# Step 1: Compile the script (from within bberg/barretenberg/cpp)
# This step is optional if the bootstrap completed successfully during installation.
cmake --build --preset default --target bn254_transparent_srs_gen

# Step 2: Run the script to generate 2^22 = 4194304 points.
# The parentheses allow running from a sub-shell without changing your current directory.
# The CRS file is stored at bberg/barretenberg/cpp/srs_db/bn254/monomial/transcript00.dat (size 256 MB)
(cd build && ./bin/bn254_transparent_srs_gen 4194304)
```

#### Run benchmarks for ZKFocil with KZG

```bash
# Run tests of the ZKFocil circuit with BN254 and SECP256K1 keys.
cmake --build --preset default --target stdlib_zkfocil_tests && (cd build && ./bin/stdlib_zkfocil_tests)

# Run prover benchmark for the ZKFocil circuit with BN254 and SECP256K1 keys.
cmake --preset bench
cmake --build --preset bench --target ultra_honk_bench && (cd build-bench && ./bin/ultra_honk_bench --benchmark_filter=zkfocil)
```

#### Run benchmarks for ZKFocil with IPA (no trusted setup)

Note: Getting the IPA to work with BN254 required a quite a bit of work (to decouple IPA from Grumpkin), so bootstrapping will throw lot of errors in other parts of the repository. We only care about getting tests and benchmarks working for the ZKFocil circuit.

```bash
# Before you run the IPA benchmarks, it is necessary to have generated the CRS for IPA, see [above](#generate-crs-for-ipa-with-bn254).
# First, we switch to the ipa branch:
git checkout sb/ipa

# Run tests of the ZKFocil circuit with BN254 and SECP256K1 keys.
cmake --build --preset default --target stdlib_zkfocil_tests && (cd build && ./bin/stdlib_zkfocil_tests)

# Run prover benchmark for the ZKFocil circuit with BN254 and SECP256K1 keys.
cmake --preset bench
cmake --build --preset bench --target ultra_honk_bench && (cd build-bench && ./bin/ultra_honk_bench --benchmark_filter=zkfocil)
```

#### Benchmarking Results

##### 2x AMD EPYC 7R13 (48C/96T each, 192 logical CPUs total)

| Stage                   | bn254-kzg | secp256k1-kzg | bn254-ipa | secp256k1-ipa |
| ----------------------- | --------- | ------------- | --------- | ------------- |
| Num of gates            | 136261    | 137583        | 136261    | 137583        |
| Witness Generation (ms) | 888       | 905           | 965       | 975           |
| Proof Generation (ms)   | 484       | 491           | 2237      | 2401          |
| Verification (ms)       | 8.522     | 8.794         | 93.5      | 86.9          |
| Proof size (bytes)      | 440       | 440           | 586       | 586           |

##### GCP `e2-standard-16 (16vCPU (8 core), 64 GB memory)`

| Stage                   | bn254-kzg | secp256k1-kzg | bn254-ipa | secp256k1-ipa |
| ----------------------- | --------- | ------------- | --------- | ------------- |
| Num of gates            | 136261    | 137583        | 136261    | 137583        |
| Witness Generation (ms) | 846       | 853           | 855       | 850           |
| Proof Generation (ms)   | 605       | 597           | 1679      | 1700          |
| Verification (ms)       | 8.522     | 8.794         | 93.5      | 86.9          |
| Proof size (bytes)      | 440       | 440           | 586       | 586           |
