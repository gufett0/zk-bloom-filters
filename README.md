### 1 - Setup
Bloom non-membership:
`snarkjs groth16 setup circuits/artifacts/circuits/non_membership.r1cs circuits/artifacts/circuits/ptau18 circuits/artifacts/circuits/non_membership_0000.zkey`
Bloom union:
`snarkjs groth16 setup circuits/artifacts/circuits2/union_set.r1cs circuits/artifacts/circuits2/ptau20 circuits/artifacts/circuits2/union_set_0000.zkey`

### 2 - Contribute
Bloom non-membership:
`snarkjs zkey contribute circuits/artifacts/circuits/non_membership_0000.zkey circuits/artifacts/circuits/non_membership.zkey --name="Contributor" -v -e="some random text"`
Bloom union:
`snarkjs zkey contribute circuits/artifacts/circuits2/union_set_0000.zkey circuits/artifacts/circuits2/union_set.zkey --name="Contributor" -v -e="some random text2"`

### 3 - Export verifier
Bloom non-membership:
`snarkjs zkey export verificationkey circuits/artifacts/circuits/non_membership.zkey circuits/artifacts/circuits/verification_key.json`
Bloom union:
`snarkjs zkey export verificationkey circuits/artifacts/circuits2/union_set.zkey circuits/artifacts/circuits2/verification_key.json`



