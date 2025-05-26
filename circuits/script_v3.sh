#!/bin/bash -e
POWERS_OF_TAU=19 # circuit will support max 2^POWERS_OF_TAU constraints
mkdir -p artifacts/circuits
if [ ! -f artifacts/circuits/ptau$POWERS_OF_TAU ]; then
  echo "Downloading powers of tau file"
  curl -L https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_$POWERS_OF_TAU.ptau --create-dirs -o artifacts/circuits/ptau$POWERS_OF_TAU
fi

# npx circom -v -r artifacts/circuits/non_membership.r1cs -w artifacts/circuits/non_membership.wasm -s artifacts/circuits/non_membership.sym v3_flag_propagation/non_membership.circom

# circom v3_flag_propagation/non_membership.circom --r1cs --wasm --sym -o artifacts/circuits -l v3_flag_propagation -l node_modules/circomlib/circuits
# npx snarkjs groth16 setup artifacts/circuits/non_membership.r1cs artifacts/circuits/ptau$POWERS_OF_TAU artifacts/circuits/non_membership_0.zkey

# npx snarkjs zkey contribute artifacts/circuits/non_membership_0.zkey artifacts/circuits/non_membership_1.zkey
# npx snarkjs zkey beacon artifacts/circuits/non_membership_1.zkey artifacts/circuits/non_membership.zkey e586fccaf245c9a1d7e78294d4802018f3001149a71b8f10cd997ef8235aa372 10
# npx snarkjs zkey export solidityverifier artifacts/circuits/non_membership.zkey artifacts/circuits/VerifierMaskCommitment.sol
# npx snarkjs info -r artifacts/circuits/non_membership.r1cs
# npx snarkjs zkey export verificationkey artifacts/circuits/non_membership.zkey artifacts/circuits/verification_key.json