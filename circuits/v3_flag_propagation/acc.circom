pragma circom 2.1.9;

include "../../node_modules/circomlib/circuits/comparators.circom";
include "./bloom.circom";

/**
 * AncestralCommitmentComplianceFieldChunked
 * ----------------------------------------
 * Validates that a set of `parentStates` (Bloom-filter field elements) has been
 * merged correctly into `unionState`, proves that the corresponding hash is
 * the one included in the external data, and enforces that the masked
 * commitment (`flaggedStateChunks`) **is not** already present in the Bloom
 * filter.
 *
 * Template parameters
 *  - numChunks   : number of 254-bit field elements that encode the Bloom filter
 *  - k           : number of Bloom-filter hash functions (normally 2)
 *  - depth       : depth of the SMT that authenticates the Bloom filter root
 *  - maxInputs   : maximum number of direct parents/inputs that can be merged
 *  - mBits       : exact Bloom-filter size (in bits). Needed so that the last
 *                  chunk may be < 254 bits when mBits % 254 ≠ 0.
 */

template AncestralCommitmentComplianceFieldChunked(
        numChunks,
        k,
        depth,
        maxInputs,
        mBits
) {
    // ──────────────────────────────────────────────────────────────────────
    // INPUTS
    // --------------------------------------------------------------------
    // Number of actually-provided inputs (2 … maxInputs)
    signal input numActiveInputs;

    // Parent states (each split in `numChunks` field-element chunks)
    signal input parentStates[maxInputs][numChunks];

    // Claimed union state (same chunking)
    signal input unionState[numChunks];

    // Hash of the parent states (included in extDataHash on-chain)
    signal input chainStatesHash;

    // The masked commitment we are trying to spend, chunked already
    signal input flaggedStateChunks[numChunks];

    // SMT inputs authenticating the Bloom filter leaf
    signal input root;
    signal input siblings[depth];
    signal input key;
    signal input value;      // this should correspond to Poseidon(bloom(C_hat))
    signal input auxKey;
    signal input auxValue;
    signal input auxIsEmpty;
    signal input isExclusion; // 1 → non-membership proof

    // ──────────────────────────────────────────────────────────────────────
    // OUTPUTS
    // --------------------------------------------------------------------
    signal output notInSet;        // 1 ⇔ flagged commitment not in Bloom filter
    signal output chainStateValid; // 1 ⇔ parentStates hash == chainStatesHash

    // ──────────────────────────────────────────────────────────────────────
    // (1) Check that numActiveInputs ∈ [2,maxInputs]
    // --------------------------------------------------------------------
    component gte = GreaterEqThan(5); // 5-bit comparator (max 31)
    gte.in[0] <== numActiveInputs;
    gte.in[1] <== 2;

    component lte = LessEqThan(5);
    lte.in[0] <== numActiveInputs;
    lte.in[1] <== maxInputs;

    signal rangeOk;
    rangeOk <== gte.out * lte.out;
    rangeOk === 1;

    // ──────────────────────────────────────────────────────────────────────
    // (2) Parent states hash must equal the public `chainStatesHash`
    // --------------------------------------------------------------------
    component parentHasher = ParentStatesHasherFieldChunked(numChunks, maxInputs);
    parentHasher.numActiveInputs <== numActiveInputs;
    for (var i = 0; i < maxInputs; i++) {
        for (var c = 0; c < numChunks; c++) {
            parentHasher.parentStates[i][c] <== parentStates[i][c];
        }
    }

    parentHasher.hash === chainStatesHash;
    chainStateValid <== 1; // will remain 1 as long as the equality holds

    // ──────────────────────────────────────────────────────────────────────
    // (3) Check that `unionState` is indeed the bitwise-OR of the active parents
    // --------------------------------------------------------------------
    component bloomUnion = BloomFilterUnionFieldChunked(numChunks, maxInputs, mBits);
    bloomUnion.numActiveInputs <== numActiveInputs;

    for (var i = 0; i < maxInputs; i++) {
        for (var c = 0; c < numChunks; c++) {
            bloomUnion.parentStates[i][c] <== parentStates[i][c];
        }
    }
    for (var c = 0; c < numChunks; c++) {
        bloomUnion.unionState[c] <== unionState[c];
    }

    // ──────────────────────────────────────────────────────────────────────
    // (4) Prove that the flagged masked commitment is **not** in the Bloom filter
    // --------------------------------------------------------------------
    // Calculate chunk parameters
    var bitsPerChunk = 253;
    var lastChunkBits = mBits - (numChunks - 1) * bitsPerChunk;
    
    component bloomFilter = BloomFilterFieldChunked(numChunks, k, depth, bitsPerChunk, lastChunkBits);
    for (var c = 0; c < numChunks; c++) {
        bloomFilter.chainStateChunks[c] <== unionState[c];
        bloomFilter.flaggedStateChunks[c] <== flaggedStateChunks[c];
    }

    bloomFilter.root <== root;
    for (var d = 0; d < depth; d++) {
        bloomFilter.siblings[d] <== siblings[d];
    }
    bloomFilter.key       <== key;
    bloomFilter.value     <== value;
    bloomFilter.auxKey    <== auxKey;
    bloomFilter.auxValue  <== auxValue;
    bloomFilter.auxIsEmpty <== auxIsEmpty;
    bloomFilter.isExclusion <== isExclusion;

    notInSet <== bloomFilter.notInSet;
}

// ────────────────────────────────────────────────────────────────────────────
//  Main component instantiation with concrete parameters
//  * numChunks = 65  (-> Bloom filter of 16,384 bits)
//  * k         = 2
//  * depth     = 20  (SMT depth)
//  * maxInputs = 16
//  * mBits     = 16384 (exact Bloom length)
//
component main {public [root, key, isExclusion, chainStatesHash, numActiveInputs]} =
    AncestralCommitmentComplianceFieldChunked(65, 2, 20, 16, 16384);