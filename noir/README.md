# zkFOCIL-impl: Zero-Knowledge FOCIL Implementation in Noir

This project implements core components of the [zkFOCIL](https://ethresear.ch/t/zkfocil-inclusion-list-privacy-using-linkable-ring-signatures/21688) protocol using the Noir DSL. Specifically, it provides a Noir circuit that:

1.  Derives a public key (PK) from a secret key (SK).
2.  Derives a key image (KI) from the secret key and block parameters.
3.  Verifies that the derived public key exists within a validator set represented by a Merkle tree.

This allows proving knowledge of a secret key corresponding to a validator in the set and deriving a unique key image for a specific block, without revealing the secret key itself.

## Project Structure

```bash
├── Nargo.toml # Noir project configuration
├── noir/
│ ├── src/
│ │ ├── main.nr # Main circuit logic
│ │ ├── crypto.nr # Cryptographic helpers (hashing, EC ops)
│ │ ├── bytes.nr # Byte manipulation utilities
│ │ └── merkle.nr # Merkle proof verification logic
│ ├── noir_test_values.json # Example/Generated test input/output values
│ └── test.py # Python script to generate test inputs/expected values
├── proofs/ # Default directory for generated proofs
└── target/ # Default directory for build artifacts (ACIR, etc.)
```

## Prerequisites

-   **Noir Language Toolchain (Nargo)**: Follow the installation instructions from the [official Noir documentation](https://noir-lang.org/docs/getting_started/installation/).

## Building the Circuit

To compile the Noir circuit into its Arithmetic Circuit Intermediate Representation (ACIR):

```bash
nargo compile
```

This will create the ACIR file in the `target/` directory.

## Testing

The project includes unit tests written directly in Noir within the `src/main.nr` file. These tests use pre-defined inputs and assert expected outputs.

To run the tests:

```bash
nargo test
```

This command will compile the circuit and execute the `#[test]` functions.

## Generating Test Inputs and Prover Inputs

The Python script `noir/test.py` is provided to generate consistent input data for both testing and proving. It performs the necessary cryptographic operations (BLS12-381 point multiplication, Blake2s hashing) outside the circuit to create inputs and expected outputs.

**Dependencies:**

```bash
pip install py_ecc merkletools
```

**Usage:**

The script can output data in two formats:

1.  **`test` format**: Generates Noir code snippets (like `let variable = [...]`) that can be directly pasted into the `#[test]` function in `src/main.nr`. This is useful for creating new test cases.
2.  **`toml` format**: Generates key-value pairs suitable for a `Prover.toml` file, which is used by `nargo prove` to provide inputs to the circuit during proof generation.

**Commands:**

-   **Generate Noir test function inputs:**

    ```bash
    python noir/test.py --format test
    ```

    This will print the necessary `let` statements to the console. Copy these into the `test_main` function in `src/main.nr`, replacing the existing test data if needed.

-   **Generate `Prover.toml` inputs:**

    ```bash
    python noir/test.py --format toml > Prover.toml
    ```

    This will create or overwrite `Prover.toml` in the project root with the required inputs for proving.

-   **Use specific inputs:** You can provide fixed secret keys or block parameters using the `--sk` and `--bp` flags (provide hex strings):
    ```bash
    python noir/test.py --format toml --sk 0x... --bp 0x... > Prover.toml
    ```

**Output File:**

Regardless of the format chosen, the script will _always_ save the generated inputs, expected outputs (public key, key image), and metadata (like the tree depth and target public key hash) to `noir/noir_test_values.json`. This serves as a persistent record of the generated data.

**Important Notes:**

-   The script uses `blake2s` for hashing, matching the `pedersen_hash` implementation used in the Noir standard library for Blake2s.
-   All hashes (root, path elements, public key hash) are handled as **Little-Endian (LE)** byte arrays, consistent with the circuit's expectations.
-   Secret keys and block parameters are treated as **Big-Endian (BE)** when converting to scalars or performing cryptographic operations outside the circuit, but are passed _as byte arrays_ to the circuit.
-   Elliptic curve point coordinates (PK, KI) are represented as **Little-Endian (LE)** byte arrays in the `noir_test_values.json` and required for assertions in `test_main`.

## Proving and Verifying (with Native Barretenberg - UltraHonk)

This project uses a custom script to interact directly with the Barretenberg backend for more control over the proving process, specifically using the UltraHonk proving system.

**Prerequisites:**

-   Ensure you have the Barretenberg binary (`bb`) installed and available in your PATH. Refer to the [Barretenberg](https://github.com/AztecProtocol/barretenberg) repository for installation instructions.
-   Compile the circuit first: `nargo compile`
-   Generate the `Prover.toml` file with inputs using the Python script: `python noir/test.py --format toml > Prover.toml`

**Execution:**

The `noir/native_honk.sh` script handles witness generation, proving, verification key writing, and proof verification in sequence.

```bash
cd noir/ # Make sure you are in the noir directory
./native_honk.sh
```

This script will:

1.  **Generate Witness:** Run `nargo execute witness` to create the witness file (`target/witness.gz`).
2.  **Generate Proof:** Use `bb prove` with the UltraHonk scheme, the compiled circuit (`target/noir.json`), and the witness to create a proof (`target/proof`).
3.  **Write Verification Key:** Use `bb write_vk` to generate the verification key (`target/vk`).
4.  **Verify Proof:** Use `bb verify` with the verification key and proof to confirm its validity.

The script automatically times each major step and prints the durations.

## Benchmarking

The `noir/native_honk.sh` script provides timing information for the core cryptographic operations. You don't need a separate benchmark command; simply run the script as described above.

Here are example benchmark results from a run (on a 2024 MacBook Pro M3 Pro):

| Operation                 | Time (seconds) |
| :------------------------ | -------------: |
| Witness Generation        |         3.5831 |
| Proof Generation          |         2.5701 |
| **Total Proving Time**    |     **6.1591** |
| Proof Verification        |         0.0323 |

_Note: Circuit size (UltraHonk) reported during this run was 411,166 constraints. Performance may vary based on hardware and circuit complexity._
