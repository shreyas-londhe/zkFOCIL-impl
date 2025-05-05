import hashlib
from py_ecc.optimized_bls12_381 import FQ, G1, multiply, normalize, Z1
import random
import json
from merkletools import MerkleTools  # Import merkletools
import argparse


class MerkleToolsBlake2s(MerkleTools):
    def __init__(self):
        super().__init__(hash_type="sha256")  # dummy, will override
        self.hash_function = lambda x: hashlib.blake2s(x).digest()
        self.leaves = []
        self.levels = None

    def add_leaf(self, values, do_hash=False):
        if isinstance(values, list):
            for v in values:
                self.add_leaf(v, do_hash)
            return
        v = values
        if isinstance(v, str):
            v = bytearray.fromhex(v)
        if do_hash:
            v = self.hash_function(v)
        self.leaves.append(v)

    def _calculate_next_level(self):
        nodes = []
        for i in range(0, len(self.leaves), 2):
            left = self.leaves[i]
            right = self.leaves[i + 1] if i + 1 < len(self.leaves) else self.leaves[i]
            nodes.append(self.hash_function(left + right))
        self.leaves = nodes

    def make_tree(self):
        if not self.leaves:
            return False
        self.levels = []
        self.levels.append(self.leaves)
        while len(self.leaves) > 1:
            self._calculate_next_level()
            self.levels.append(self.leaves)
        return True

    def get_merkle_root(self):
        if not self.levels:
            return None
        return self.levels[-1][0]

    def get_proof(self, index):
        if not self.levels:
            return None
        proof = []
        for level in self.levels[:-1]:
            if index % 2 == 0:
                sibling = level[index + 1] if index + 1 < len(level) else level[index]
            else:
                sibling = level[index - 1]
            proof.append(sibling)
            index = index // 2
        return proof


mt = MerkleTools()
mt.hash_function = lambda x: hashlib.blake2s(x).digest()

# --- Constants (Match Noir side if necessary for testing) ---
# For generating test data, we might use a smaller tree than the actual circuit
# Ensure VALIDATOR_TREE_DEPTH here matches the N generic in the Noir test or main fn called by test
TEST_TREE_DEPTH = 20  # Example depth for generating test data (16 leaves)
NUM_LEAVES = 1 << TEST_TREE_DEPTH


def int_to_bytes_be(value, length=32):
    # Allow length override for Fq elements (48 bytes)
    return value.to_bytes(length, byteorder="big")


def int_to_bytes_le(value, length=32):
    # Allow length override for Fq elements (48 bytes)
    return value.to_bytes(length, byteorder="little")


def bytes_to_int(bytes_val):
    # Default to big-endian unless specified? Let's stick to BE for scalars as before.
    return int.from_bytes(bytes_val, byteorder="big")


def hex_to_bytes(hex_str):
    if hex_str.startswith("0x"):
        hex_str = hex_str[2:]
    return bytes.fromhex(hex_str)


# --- Helper to hash public key consistent with Noir's hash_public_key ---
def hash_public_key_uncompressed(point):
    """
    Hashes a BLS12-381 G1 point by serializing uncompressed LE coordinates
    (x_le || y_le) and using blake2s. Matches Noir's `hash_public_key`.
    Returns 32-byte LE hash.
    """
    if point is None or point == Z1:
        # Define hash for point at infinity if needed, e.g., hash of 96 zero bytes
        serialized = bytes(96)
    else:
        normalized = normalize(point)
        x, y = normalized[0], normalized[1]
        x_val = x.n if isinstance(x, FQ) else x
        y_val = y.n if isinstance(y, FQ) else y

        x_bytes_le = int_to_bytes_le(x_val, 48)
        y_bytes_le = int_to_bytes_le(y_val, 48)
        serialized = x_bytes_le + y_bytes_le  # 96 bytes total

    # Hash using blake2s
    # Note: hashlib.blake2s default digest size is 32 bytes
    hash_le = hashlib.blake2s(serialized).digest()
    return hash_le


# --- Helper to build Merkle tree and get proof ---
def generate_merkle_data(
    target_leaf_hash_le, num_leaves=NUM_LEAVES, depth=TEST_TREE_DEPTH
):
    """
    Generates a Merkle tree, root, and proof for a target leaf.
    Uses blake2s for hashing, consistent with Noir's hash_siblings (left || right).
    Hashes are LE.
    """

    mt = MerkleToolsBlake2s()

    # Generate random leaf hashes (LE)
    leaf_hashes_le = [random.randbytes(32) for _ in range(num_leaves)]

    # Place the target hash at a random index
    target_index = random.randint(0, num_leaves - 1)
    leaf_hashes_le[target_index] = target_leaf_hash_le

    # Add leaves to the tree (raw bytes, do_hash=False)
    for leaf in leaf_hashes_le:
        mt.add_leaf(leaf, do_hash=False)

    # Build the tree
    mt.make_tree()

    # Get root (bytes)
    merkle_root_le = mt.get_merkle_root()

    # Get proof (list of sibling hashes as bytes)
    proof_le = mt.get_proof(target_index)

    # Pad proof if necessary to match expected depth/length
    while len(proof_le) < depth:
        proof_le.append(bytes(32))

    # Calculate indices (0 for left, 1 for right) based on target_index
    indices = []
    current_index = target_index
    for _ in range(depth):
        indices.append(current_index % 2)
        current_index //= 2

    while len(indices) < depth:
        indices.append(0)

    return {
        "root_le": merkle_root_le,
        "path_le": proof_le,
        "indices": indices,
    }


def generate_test_inputs(
    secret_key_hex=None, block_params_hex=None, output_format="test"
):
    # --- Generate Secret Key and Block Params ---
    if secret_key_hex:
        secret_key_bytes = hex_to_bytes(secret_key_hex)
    else:
        secret_key_bytes = random.randbytes(32)

    if block_params_hex:
        block_params_bytes = hex_to_bytes(block_params_hex)
    else:
        block_params_bytes = random.randbytes(32)

    # --- Calculate Expected PK and KI ---
    CURVE_ORDER = (
        52435875175126190479447740508185965837690552500527637822603658699938581184513
    )
    secret_key_int = bytes_to_int(secret_key_bytes) % CURVE_ORDER
    secret_key_bytes = int_to_bytes_be(
        secret_key_int
    )  # Ensure canonical BE representation

    public_key = multiply(G1, secret_key_int)

    combined_ki = secret_key_bytes + block_params_bytes
    hash_le_ki = hashlib.blake2s(combined_ki).digest()
    hash_be_ki = bytes(hash_le_ki)
    hash_int_ki = bytes_to_int(hash_be_ki) % CURVE_ORDER
    key_image = multiply(G1, hash_int_ki)

    # --- Hash the target public key (consistent with Noir) ---
    target_pk_hash_le = hash_public_key_uncompressed(public_key)

    # --- Generate Merkle Data ---
    merkle_data = generate_merkle_data(
        target_pk_hash_le, num_leaves=NUM_LEAVES, depth=TEST_TREE_DEPTH
    )
    validator_root_le = merkle_data["root_le"]
    validator_path_le = merkle_data["path_le"]  # List of 32-byte hashes
    validator_indices = merkle_data["indices"]  # List of 0s/1s

    # --- Format G1 Point Coordinates (LE bytes) ---
    def format_g1_point_bytes(point):
        if point is None or point == Z1:
            return {"x_le_bytes": bytes(48), "y_le_bytes": bytes(48)}
        normalized = normalize(point)
        x, y = normalized[0], normalized[1]
        x_val = x.n if isinstance(x, FQ) else x
        y_val = y.n if isinstance(y, FQ) else y
        x_bytes = int_to_bytes_le(x_val, 48)
        y_bytes = int_to_bytes_le(y_val, 48)
        return {"x_le_bytes": x_bytes, "y_le_bytes": y_bytes}

    public_key_coords = format_g1_point_bytes(public_key)
    key_image_coords = format_g1_point_bytes(key_image)

    # --- Format inputs for Noir test or TOML ---
    def format_byte_array_noir(byte_list):
        return ", ".join([f"0x{b:02x}" for b in byte_list])

    def format_byte_array_toml(byte_list):
        return ", ".join([f'"0x{b:02x}"' for b in byte_list])

    sk_noir = format_byte_array_noir(secret_key_bytes)
    bp_noir = format_byte_array_noir(block_params_bytes)
    root_noir = format_byte_array_noir(validator_root_le)
    path_elements_noir = [f"[{format_byte_array_noir(p)}]" for p in validator_path_le]
    path_noir = ",\n        ".join(path_elements_noir)
    indices_noir = ", ".join(["true" if i == 1 else "false" for i in validator_indices])

    sk_toml = format_byte_array_toml(secret_key_bytes)
    bp_toml = format_byte_array_toml(block_params_bytes)
    root_toml = format_byte_array_toml(validator_root_le)
    path_elements_toml = [f"[{format_byte_array_toml(p)}]" for p in validator_path_le]
    path_toml = ",\n    ".join(path_elements_toml)
    # TOML usually expects strings for bools/ints in this context
    indices_toml = ", ".join([f'"{i}"' for i in validator_indices])

    # --- Print Output ---
    if output_format == "test":
        print("// Test Input Values")
        print(f"// Tree Depth used for this test: {TEST_TREE_DEPTH}")
        print(f"let secret_key_bytes = [{sk_noir}];")
        print(f"let block_params = [{bp_noir}];")
        print(f"let validator_root = [{root_noir}]; // LE hash")
        print(
            f"let validator_merkle_path: [[u8; 32]; {TEST_TREE_DEPTH}] = [\n        {path_noir}\n    ]; // Array of LE hashes"
        )
        print(f"let validator_merkle_indices = [{indices_noir}];")  # bool in Noir

        # --- Print Expected Results (Optional for test format) ---
        ki_x_array = format_byte_array_noir(key_image_coords["x_le_bytes"])
        ki_y_array = format_byte_array_noir(key_image_coords["y_le_bytes"])
        print("\n// Expected Results (Coords LE)")
        print(f"let expected_key_image_x_bytes = [{ki_x_array}];")
        print(f"let expected_key_image_y_bytes = [{ki_y_array}];")

    elif output_format == "toml":
        print("# Prover.toml Input Values")
        print(f"# Tree Depth used for this test: {TEST_TREE_DEPTH}")
        print(f"secret_key_bytes = [{sk_toml}]")
        print(f"block_params = [{bp_toml}]")
        print(f"validator_root = [{root_toml}]")
        print(f"validator_merkle_path = [\n    {path_toml}\n]")
        print(f"validator_merkle_indices = [{indices_toml}]")

    # --- Keep JSON generation ---
    result = {
        "inputs": {
            "secret_key_bytes": "0x" + secret_key_bytes.hex(),
            "block_params": "0x" + block_params_bytes.hex(),
            "validator_root": "0x" + validator_root_le.hex(),  # LE
            "validator_merkle_path": ["0x" + p.hex() for p in validator_path_le],  # LE
            "validator_merkle_indices": validator_indices,  # Keep as 0/1 ints here
        },
        "expected": {
            "public_key": {
                "x": "0x" + public_key_coords["x_le_bytes"].hex(),
                "y": "0x" + public_key_coords["y_le_bytes"].hex(),
            },
            "key_image": {
                "x": "0x" + key_image_coords["x_le_bytes"].hex(),
                "y": "0x" + key_image_coords["y_le_bytes"].hex(),
            },
        },
        "metadata": {
            "tree_depth": TEST_TREE_DEPTH,
            "target_pk_hash": "0x" + target_pk_hash_le.hex(),  # LE hash used as leaf
        },
    }
    return result


# --- Main Execution ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate test data for Noir circuit.")
    parser.add_argument(
        "-f",
        "--format",
        choices=["test", "toml"],
        default="test",
        help="Output format ('test' for Noir test func, 'toml' for Prover.toml)",
    )
    parser.add_argument("--sk", help="Fixed secret key (hex string)")
    parser.add_argument("--bp", help="Fixed block params (hex string)")
    args = parser.parse_args()

    # Generate test case with specified format and optional fixed inputs
    test_case = generate_test_inputs(
        secret_key_hex=args.sk, block_params_hex=args.bp, output_format=args.format
    )

    # Save to JSON file for reference (always happens)
    with open("noir_test_values.json", "w") as f:
        json.dump(test_case, f, indent=4)
    print("\nTest values saved to noir_test_values.json")

    # Example of using fixed inputs:
    # print("\n--- Generating with Fixed Inputs ---")
    # fixed_sk = "0x2fbaa868139e0d5bccc5e1a92148827c24637e711820bdb31723825c2590fd9a"
    # fixed_bp = "0x6399f43c845ebbb4286c64fe3af11768747fa6ea43f9f2af934ba5bda3c13e35"
    # generate_test_inputs(secret_key_hex=fixed_sk, block_params_hex=fixed_bp)
