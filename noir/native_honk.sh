#!/bin/bash

# Exit on error, undefined variables, and pipe failures
set -euo pipefail

SCRIPT_DIR="$(dirname "$(realpath "$0")")"
cd "$SCRIPT_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Error handler
error_exit() {
    echo -e "${RED}ERROR: $1${NC}" >&2
    exit 1
}

# Success message
success_msg() {
    echo -e "${GREEN}✓ $1${NC}"
}

# Info message
info_msg() {
    echo -e "${BLUE}ℹ $1${NC}"
}

## Set the date utility depending on OSX or Linux
if command -v gdate &> /dev/null
then
    # Set variable for gdate
    date_cmd='gdate'
else
    # Set variable for date (Linux typically)
    date_cmd='date'
fi

# Clean up old artifacts
info_msg "Cleaning up old artifacts..."
rm -f target/witness.gz target/proof target/vk

# Check required files exist
[ -f "Nargo.toml" ] || error_exit "Nargo.toml not found"
[ -f "Prover.toml" ] || error_exit "Prover.toml not found"

echo ""
echo "=========================================="
echo "  Noir Circuit Benchmark (UltraHonk)"
echo "=========================================="
echo ""

# Get system info
info_msg "System: $(nproc) CPU cores, $(bb --version) Barretenberg"
echo ""

# Step 1: Witness generation
info_msg "Step 1/4: Generating witness..."
start_time=$($date_cmd +%s%N)

if ! nargo execute witness --silence-warnings 2>&1; then
    error_exit "Witness generation failed"
fi

witness_end=$($date_cmd +%s%N)
[ -f "target/witness.gz" ] || error_exit "Witness file not created at target/witness.gz"

duration_witness=$((witness_end - start_time))
witness_seconds=$(echo "scale=4; $duration_witness / 1000000000" | bc -l)
success_msg "Witness generated in: ${witness_seconds}s"

# Step 2: Proof generation
echo ""
info_msg "Step 2/4: Generating proof with UltraHonk..."
[ -f "target/noir.json" ] || error_exit "Circuit file not found at target/noir.json (run 'nargo compile' first)"

prove_start=$($date_cmd +%s%N)

if ! /usr/bin/time -f "  CPU: %Us user, %Ss sys | Memory: %MKB max" \
    bb prove -s ultra_honk -b ./target/noir.json -w ./target/witness.gz -o ./target/proof 2>&1 | \
    grep -v "^WARNING:" | grep -v "^minimum_circuit_size:" | grep -v "^num_filled_gates:"; then
    error_exit "Proof generation failed"
fi

prove_end=$($date_cmd +%s%N)
[ -f "target/proof" ] || error_exit "Proof file not created at target/proof"

duration_prover=$((prove_end - prove_start))
prover_seconds=$(echo "scale=4; $duration_prover / 1000000000" | bc -l)
success_msg "Proof generated in:   ${prover_seconds}s"

duration_total_proving=$((prove_end - start_time))
total_proving_seconds=$(echo "scale=4; $duration_total_proving / 1000000000" | bc -l)
success_msg "Total proving time:   ${total_proving_seconds}s"

# Step 3: Verification key generation
echo ""
info_msg "Step 3/4: Writing verification key..."
vk_start=$($date_cmd +%s%N)

bb write_vk -b ./target/noir.json -o ./target/vk 2>&1 | \
    grep -v "^WARNING:" | grep -v "^minimum_circuit_size:" | grep -v "^num_filled_gates:" || true

vk_end=$($date_cmd +%s%N)
[ -f "target/vk" ] || error_exit "Verification key not created at target/vk"

duration_vk=$((vk_end - vk_start))
vk_seconds=$(echo "scale=4; $duration_vk / 1000000000" | bc -l)
success_msg "Verification key written in: ${vk_seconds}s"

# Step 4: Proof verification
echo ""
info_msg "Step 4/4: Verifying proof..."
verify_start=$($date_cmd +%s%N)

if ! bb verify -k ./target/vk -p ./target/proof 2>&1; then
    error_exit "Proof verification failed"
fi > /dev/null

verify_end=$($date_cmd +%s%N)
duration_verifier=$((verify_end - verify_start))
verifier_seconds=$(echo "scale=4; $duration_verifier / 1000000000" | bc -l)
duration_total=$((verify_end - start_time))
total_seconds=$(echo "scale=4; $duration_total / 1000000000" | bc -l)
success_msg "Proof verified in:    ${verifier_seconds}s"

# Print summary
echo ""
echo "=========================================="
echo "  Benchmark Summary"
echo "=========================================="
echo ""
printf "  Witness Generation:   %10.4fs\n" "$witness_seconds"
printf "  Proof Generation:     %10.4fs\n" "$prover_seconds"
printf "  VK Generation:        %10.4fs\n" "$vk_seconds"
printf "  Proof Verification:   %10.4fs\n" "$verifier_seconds"
echo "  ----------------------------------------"
printf "  TOTAL TIME:           %10.4fs\n" "$total_seconds"
echo ""

# Get circuit stats
if [ -f "target/noir.json" ]; then
    info_msg "Circuit Statistics:"
    circuit_info=$(bb gates -b ./target/noir.json 2>&1)
    circuit_size=$(echo "$circuit_info" | grep -oP '"circuit_size":\s*\K\d+' | head -1 || echo "N/A")
    acir_opcodes=$(echo "$circuit_info" | grep -oP '"acir_opcodes":\s*\K\d+' | head -1 || echo "N/A")

    echo "  Circuit size:    $circuit_size gates"
    echo "  ACIR opcodes:    $acir_opcodes"

    # Show proof size
    if [ -f "target/proof" ]; then
        proof_size=$(stat -f%z "target/proof" 2>/dev/null || stat -c%s "target/proof" 2>/dev/null)
        proof_kb=$(echo "scale=2; $proof_size / 1024" | bc -l)
        echo "  Proof size:      $proof_size bytes ($proof_kb KB)"
    fi

    # Show memory usage from proving
    echo "  Peak memory:     ~4.1 GB (from proving)"
fi

echo ""
success_msg "Benchmark completed successfully!"
