#!/bin/bash

SCRIPT_DIR="$(dirname "$(realpath "$0")")"
cd $SCRIPT_DIR

## Set the date utility depending on OSX or Linix
if command -v gdate &> /dev/null
then
    # Set variable for gdate
    date_cmd='gdate'
else
    # Set variable for date (Linux typically)
    date_cmd='date'
fi

echo "Calculating witness..."
start_time=$($date_cmd +%s%N)

## Calculate the witness of the circuit
nargo execute witness --silence-warnings
witness_end=$($date_cmd +%s%N)
duration_witness=$((witness_end - start_time))
witness_seconds=$(echo "scale=4; $duration_witness / 1000000000" | bc -l)
printf "Witness generated in: %.4f seconds\n" $witness_seconds

## Generate the proof
echo "Generating proof..."
prove_start=$($date_cmd +%s%N)
bb prove -s ultra_honk -b ./target/noir.json -w ./target/noir.gz -o ./target
prove_end=$($date_cmd +%s%N)
duration_prover=$((prove_end - prove_start))
prover_seconds=$(echo "scale=4; $duration_prover / 1000000000" | bc -l)
printf "Proof generated in:   %.4f seconds\n" $prover_seconds

duration_total_proving=$((prove_end - start_time))
total_proving_seconds=$(echo "scale=4; $duration_total_proving / 1000000000" | bc -l)
printf "Total proving time: %.4f seconds\n" $total_proving_seconds

echo "Writing verification key..."
bb write_vk -b ./target/noir.json -o ./target

echo "Verifying proof..."
verify_start=$($date_cmd +%s%N)
bb verify -k ./target/vk -p ./target/proof
verify_end=$($date_cmd +%s%N)
duration_verifier=$((verify_end - verify_start))
verifier_seconds=$(echo "scale=4; $duration_verifier / 1000000000" | bc -l)
duration_total=$((verify_end - start_time))
total_seconds=$(echo "scale=4; $duration_total / 1000000000" | bc -l)
printf "Proof verified in:    %.4f seconds\n" $verifier_seconds
printf "Total time (inc ver): %.4f seconds\n" $total_seconds
