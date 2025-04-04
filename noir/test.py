import hashlib
from py_ecc.optimized_bls12_381 import FQ, G1, multiply, normalize, Z1
import random
import json


def int_to_bytes_be(value, length=32):
    return value.to_bytes(length, byteorder="big")


def int_to_bytes_le(value, length=32):
    return value.to_bytes(length, byteorder="little")


def bytes_to_int(bytes_val):
    return int.from_bytes(bytes_val, byteorder="big")


def hex_to_bytes(hex_str):
    if hex_str.startswith("0x"):
        hex_str = hex_str[2:]
    return bytes.fromhex(hex_str)


def generate_test_inputs(secret_key_hex=None, block_params_hex=None):
    # Use provided values or generate random ones
    if secret_key_hex:
        secret_key_bytes = hex_to_bytes(secret_key_hex)
    else:
        # Generate random bytes for secret key
        secret_key_bytes = bytes(random.randint(0, 255) for _ in range(32))

    if block_params_hex:
        block_params_bytes = hex_to_bytes(block_params_hex)
    else:
        # Generate random bytes for block params
        block_params_bytes = bytes(random.randint(0, 255) for _ in range(32))

    # Calculate expected results
    # 1. Convert secret key to scalar
    CURVE_ORDER = (
        52435875175126190479447740508185965837690552500527637822603658699938581184513
    )
    secret_key_int = bytes_to_int(secret_key_bytes) % CURVE_ORDER
    secret_key_bytes = int_to_bytes_be(secret_key_int)

    # 2. Compute public key
    public_key = multiply(G1, secret_key_int)

    # 3. Compute key image
    # Combine secret key and block params
    combined = secret_key_bytes + block_params_bytes
    # Hash with blake2s
    hash_le = hashlib.blake2s(combined).digest()
    # Convert to big-endian
    hash_be = bytes(reversed(hash_le))
    # Convert to scalar
    hash_int = bytes_to_int(hash_be) % CURVE_ORDER
    # Multiply by generator
    key_image = multiply(G1, hash_int)

    # Format point coordinates as little-endian bytes
    def format_g1_point_bytes(point):
        if point is None or point == Z1:
            return {
                "x_le_bytes": bytes(48),  # 48 zero bytes
                "y_le_bytes": bytes(48),  # 48 zero bytes
            }

        normalized = normalize(point)
        x, y = normalized[0], normalized[1]

        # Handle FQ type from py_ecc
        if isinstance(x, FQ):
            x = x.n
        if isinstance(y, FQ):
            y = y.n

        # Format as little-endian bytes (48 bytes for BLS12-381 Fq)
        x_bytes = int_to_bytes_le(x, 48)
        y_bytes = int_to_bytes_le(y, 48)

        return {"x_le_bytes": x_bytes, "y_le_bytes": y_bytes}

    # Get point coordinates as bytes
    public_key_bytes = format_g1_point_bytes(public_key)
    key_image_bytes = format_g1_point_bytes(key_image)

    # Format secret key and block params as u8 arrays for Noir
    sk_array = ", ".join([f"0x{b:02x}" for b in secret_key_bytes])
    bp_array = ", ".join([f"0x{b:02x}" for b in block_params_bytes])

    # Format point coordinates as byte arrays for Noir
    pk_x_array = ", ".join([f"0x{b:02x}" for b in public_key_bytes["x_le_bytes"]])
    pk_y_array = ", ".join([f"0x{b:02x}" for b in public_key_bytes["y_le_bytes"]])
    ki_x_array = ", ".join([f"0x{b:02x}" for b in key_image_bytes["x_le_bytes"]])
    ki_y_array = ", ".join([f"0x{b:02x}" for b in key_image_bytes["y_le_bytes"]])

    # Print values in Noir-friendly format
    print("// Test Input Values")
    print(f"let secret_key_bytes = [{sk_array}];")
    print(f"let block_params = [{bp_array}];")

    print("\n// Expected Results")
    print("// Public Key")
    print(f"let expected_public_key_x_bytes = [{pk_x_array}];")
    print(f"let expected_public_key_y_bytes = [{pk_y_array}];")
    print("// Key Image")
    print(f"let expected_key_image_x_bytes = [{ki_x_array}];")
    print(f"let expected_key_image_y_bytes = [{ki_y_array}];")

    print("\n// You can use these in your test like:")
    print("assert_eq!(public_key.x.to_le_bytes(), expected_public_key_x_bytes);")
    print("assert_eq!(public_key.y.to_le_bytes(), expected_public_key_y_bytes);")
    print("assert_eq!(key_image.x.to_le_bytes(), expected_key_image_x_bytes);")
    print("assert_eq!(key_image.y.to_le_bytes(), expected_key_image_y_bytes);")

    # Create a compact result for JSON serialization
    result = {
        "inputs": {
            "secret_key_bytes": "0x" + secret_key_bytes.hex(),
            "block_params": "0x" + block_params_bytes.hex(),
        },
        "expected": {
            "public_key": {
                "x": "0x" + public_key_bytes["x_le_bytes"].hex(),
                "y": "0x" + public_key_bytes["y_le_bytes"].hex(),
            },
            "key_image": {
                "x": "0x" + key_image_bytes["x_le_bytes"].hex(),
                "y": "0x" + key_image_bytes["y_le_bytes"].hex(),
            },
        },
    }

    return result


# Generate test case with random values
test_case = generate_test_inputs()

# Save to file for reference
with open("noir_test_values.json", "w") as f:
    json.dump(test_case, f, indent=2)
print("\nTest values saved to noir_test_values.json")
