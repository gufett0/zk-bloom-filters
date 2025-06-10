### 1 - Setup
Bloom non-membership:
`snarkjs groth16 setup circuits/artifacts/circuits/non_membership.r1cs circuits/artifacts/circuits/ptau18 circuits/artifacts/circuits/non_membership_0000.zkey`
Full ACC:
`snarkjs groth16 setup circuits/artifacts/circuits2/acc.r1cs circuits/artifacts/circuits2/ptau21 circuits/artifacts/circuits2/acc_0000.zkey`

### 2 - Contribute
Bloom non-membership:
`snarkjs zkey contribute circuits/artifacts/circuits/non_membership_0000.zkey circuits/artifacts/circuits/non_membership.zkey --name="Contributor" -v -e="some random text"`
Full ACC:
`snarkjs zkey contribute circuits/artifacts/circuits2/acc_0000.zkey circuits/artifacts/circuits2/acc.zkey --name="Contributor" -v -e="some random text2"`

### 3 - Export verifier
Bloom non-membership:
`snarkjs zkey export verificationkey circuits/artifacts/circuits/non_membership.zkey circuits/artifacts/circuits/verification_key.json`
Full ACC:
`snarkjs zkey export verificationkey circuits/artifacts/circuits2/acc.zkey circuits/artifacts/circuits2/acc_verification_key.json`



