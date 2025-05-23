### Setup
`snarkjs groth16 setup circuits/artifacts/circuits/non_membership.r1cs circuits/artifacts/circuits/ptau18 circuits/artifacts/circuits/non_membership_0000.zkey`

### Contribute
`snarkjs zkey contribute circuits/artifacts/circuits/non_membership_0000.zkey circuits/artifacts/circuits/non_membership.zkey --name="Contributor" -v -e="some random text"`

### Export verifier
`snarkjs zkey export verificationkey circuits/artifacts/circuits/non_membership.zkey circuits/artifacts/circuits/verification_key.json`