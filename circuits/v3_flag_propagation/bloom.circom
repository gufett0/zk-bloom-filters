pragma circom 2.1.9;

include "../../node_modules/circomlib/circuits/poseidon.circom";
include "../../node_modules/circomlib/circuits/comparators.circom";
include "../../node_modules/circomlib/circuits/bitify.circom";
include "./smtverifier.circom";

// -----------------------------------------------------------------------------
// Aux - Rolling Poseidon hash for an arbitrary-length vector using width-5
// permutation. It avoids the N_ROUNDS_P table overflow for t ≥ 6.
// -----------------------------------------------------------------------------
template PoseidonHashVec(l) {
    assert(l > 0);
    signal input in[l]; // array di field elements da hashare (ie. i nostri 65 chunks)
    signal output out; // il singolo field element risultante dall'hash

    var RATE  = 4;   // quanti nuovi elementi possiamo assorbire per chiamata poseidon
    var WIDTH = 5;   // dimensione totale dello stato poseidon (1 capacity + 4 rate)
    // Circomlib ha tabelle precompilate solo per WIDTH ≤ 5 
    // Capacity = WIDTH - RATE = 5 - 4 = 1 slot
    // La capacity è la convenzione che slot[0] non contiene mai input diretti dell'utente - solo stato interno/chaining.


    var numFullCalls = (l + (RATE-1)) \ RATE;  // per arrotondare per eccesso
    component sponge[numFullCalls]; // dichiara array di componenti poseidon (uno per ogni chiamata necessaria)

    if (l <= RATE) {
        // una sola chiamata poseido è sufficiente per assorbire tutti gli elementi
        sponge[0] = Poseidon(WIDTH);
        sponge[0].inputs[0] <== 0;  // stato iniziale
        
        for (var i = 0; i < RATE; i++) {
            if (i < l) {
                sponge[0].inputs[i+1] <== in[i];
            } else {
                sponge[0].inputs[i+1] <== 0;  // padding
            }
        }
        
        out <== sponge[0].out;
    } else {
        
        // la prima chiamata assorbe elementi 0,1,2,3
        sponge[0] = Poseidon(WIDTH);
        sponge[0].inputs[0] <== 0;  
        sponge[0].inputs[1] <== in[0];
        sponge[0].inputs[2] <== in[1];
        sponge[0].inputs[3] <== in[2];
        sponge[0].inputs[4] <== in[3];

        // loop per le chiamate successive (dalla seconda in poi)
        for (var call = 1; call < numFullCalls; call++) {

            // nuova istanza Poseidon + chaining dello stato:
            sponge[call] = Poseidon(WIDTH); 
            sponge[call].inputs[0] <== sponge[call-1].out;  // slot 0 = output della chiamata precedente (tiene in memoria i dati già processati)
            
            
            for (var slot = 1; slot < WIDTH; slot++) {
                var inputIndex = (call-1) * RATE + RATE + (slot-1); // calcola quale elemento dell'input originale usare
                
                // se l'indice è valido: usa il dato reale sennò zero padding
                if (inputIndex < l) {
                    sponge[call].inputs[slot] <== in[inputIndex];
                } else {
                    sponge[call].inputs[slot] <== 0; 
                }
            }
        }
        
        out <== sponge[numFullCalls-1].out; // output dell'ultima chiamata Poseidon
    }
}


// -----------------------------------------------------------------------------
// Aux - Popcount of an array of bits (or small field elements).
// -----------------------------------------------------------------------------
template SumBits(n) {
    assert(n > 0);
    signal input in[n];
    signal output out;

    if (n == 1) {
        out <== in[0];
    } else {
        signal acc[n];
        acc[0] <== in[0];
        for (var i = 1; i < n; i++) {
            acc[i] <== acc[i-1] + in[i];
        }
        out <== acc[n-1];
    }
}

// -----------------------------------------------------------------------------
// Helper template to compute bitwise OR of multiple inputs
// -----------------------------------------------------------------------------
template BitwiseOR(numInputs, numBits) {
    signal input bits[numInputs][numBits];
    signal input isActive[numInputs];
    signal output out[numBits];

    signal activeBits[numInputs][numBits];
    signal accumOR[numBits][numInputs + 1];
    
    // first compute all active bits
    for (var i = 0; i < numInputs; i++) {
        for (var b = 0; b < numBits; b++) {
            activeBits[i][b] <== bits[i][b] * isActive[i];
        }
    }
    
    // then compute the OR accumulation
    for (var b = 0; b < numBits; b++) {
        accumOR[b][0] <== 0;
        
        for (var i = 0; i < numInputs; i++) {
            accumOR[b][i + 1] <== accumOR[b][i] + activeBits[i][b] - accumOR[b][i] * activeBits[i][b];
        }
        
        out[b] <== accumOR[b][numInputs];
    }
}

// -----------------------------------------------------------------------------
// BloomFilterFieldChunked
//   numChunks  – number of chunks
//   k          – number of hash functions / bits that must be set.
//   depth      – SMT depth for verification
//   bitsPerChunk – bits per chunk (usually 254, but parameterized)
//   lastChunkBits – bits in the last chunk
//
// Public inputs
//   chainStateChunks[numChunks]   – OR of all parent states
//   flaggedStateChunks[numChunks] – vector with exactly k bits set to 1
// Output
//   notInSet (boolean)      – 0 if intersection == k and flagged has k bits, 1 otherwise
// -----------------------------------------------------------------------------
template BloomFilterFieldChunked(numChunks, k, depth, bitsPerChunk, lastChunkBits) {
    signal input chainStateChunks[numChunks];
    signal input flaggedStateChunks[numChunks];
    
    signal input root;
    signal input siblings[depth];
    signal input key;
    signal input value;
    signal input auxKey;
    signal input auxValue;
    signal input auxIsEmpty;
    signal input isExclusion;
    
    signal output notInSet;

    // first verify that flaggedStateChunks belong to the authorized smt 
    component hasher = PoseidonHashVec(numChunks);
    for (var i = 0; i < numChunks; i++) {
        hasher.in[i] <== flaggedStateChunks[i];
    }
    
    component smtVerifier = SMTVerifier(depth);
    smtVerifier.root <== root;
    for (var i = 0; i < depth; i++) {
        smtVerifier.siblings[i] <== siblings[i];
    }
    smtVerifier.key <== key;
    smtVerifier.value <== value;
    smtVerifier.auxKey <== auxKey;
    smtVerifier.auxValue <== auxValue;
    smtVerifier.auxIsEmpty <== auxIsEmpty;
    smtVerifier.isExclusion <== isExclusion;
    
    hasher.out === value;

    signal intersectionCounts[numChunks];
    signal flaggedCounts[numChunks];

    // for bit decomposition
    component uBits[numChunks];
    component fBits[numChunks];
    
    // for counting
    component sumInter[numChunks];
    component sumFlag[numChunks];

    signal interBitsRegular[numChunks-1][bitsPerChunk];
    signal interBitsLast[lastChunkBits];
    
    // initialize components for each chunk
    for (var c = 0; c < numChunks-1; c++) {
        uBits[c] = Num2Bits(bitsPerChunk);
        fBits[c] = Num2Bits(bitsPerChunk);
        uBits[c].in <== chainStateChunks[c];
        fBits[c].in <== flaggedStateChunks[c];
        
        // get intersection
        for (var i = 0; i < bitsPerChunk; i++) {
            interBitsRegular[c][i] <== uBits[c].out[i] * fBits[c].out[i];
        }
        
        // count bits
        sumInter[c] = SumBits(bitsPerChunk);
        sumFlag[c] = SumBits(bitsPerChunk);
        for (var i = 0; i < bitsPerChunk; i++) {
            sumInter[c].in[i] <== interBitsRegular[c][i];
            sumFlag[c].in[i] <== fBits[c].out[i];
        }
        intersectionCounts[c] <== sumInter[c].out;
        flaggedCounts[c] <== sumFlag[c].out;
    }
    
    // process last chunk
    uBits[numChunks-1] = Num2Bits(lastChunkBits);
    fBits[numChunks-1] = Num2Bits(lastChunkBits);
    uBits[numChunks-1].in <== chainStateChunks[numChunks-1];
    fBits[numChunks-1].in <== flaggedStateChunks[numChunks-1];
    
    // compute intersection for last chunk
    for (var i = 0; i < lastChunkBits; i++) {
        interBitsLast[i] <== uBits[numChunks-1].out[i] * fBits[numChunks-1].out[i];
    }
    
    // count bits for last chunk
    sumInter[numChunks-1] = SumBits(lastChunkBits);
    sumFlag[numChunks-1] = SumBits(lastChunkBits);
    for (var i = 0; i < lastChunkBits; i++) {
        sumInter[numChunks-1].in[i] <== interBitsLast[i];
        sumFlag[numChunks-1].in[i] <== fBits[numChunks-1].out[i];
    }
    intersectionCounts[numChunks-1] <== sumInter[numChunks-1].out;
    flaggedCounts[numChunks-1] <== sumFlag[numChunks-1].out;

    // global totals
    component totalInter = SumBits(numChunks);
    component totalFlag = SumBits(numChunks);
    for (var c = 0; c < numChunks; c++) {
        totalInter.in[c] <== intersectionCounts[c];
        totalFlag.in[c] <== flaggedCounts[c];
    }

    // verify equalities with k
    component eqInter = IsEqual();
    eqInter.in[0] <== totalInter.out;
    eqInter.in[1] <== k;

    component eqFlag = IsEqual();
    eqFlag.in[0] <== totalFlag.out;
    eqFlag.in[1] <== k;

    signal allOK;
    allOK <== eqInter.out * eqFlag.out;

    notInSet <== 1 - allOK;
}

// -----------------------------------------------------------------------------
// BloomFilterUnionFieldChunked
// Verifies that unionState is the correct bitwise OR of active parent states
// -----------------------------------------------------------------------------
template BloomFilterUnionFieldChunked(numChunks, maxInputs, mBits) {
    signal input numActiveInputs;
    signal input parentStates[maxInputs][numChunks];
    signal input unionState[numChunks];

    var bitsPerChunk = 254;
    var lastChunkBits = mBits - (numChunks - 1) * bitsPerChunk;
    
    // verify numActiveInputs is in valid range [2, maxInputs]
    component gte = GreaterEqThan(5);
    gte.in[0] <== numActiveInputs;
    gte.in[1] <== 2;
    
    component lte = LessEqThan(5);
    lte.in[0] <== numActiveInputs;
    lte.in[1] <== maxInputs;
    
    signal validRange <== gte.out * lte.out;
    validRange === 1;

    // activity flags for each input
    component isActive[maxInputs];
    for (var i = 0; i < maxInputs; i++) {
        isActive[i] = LessEqThan(5);
        isActive[i].in[0] <== i;
        isActive[i].in[1] <== numActiveInputs - 1;
    }

    // bit decomposition 
    component unionBits[numChunks];
    component parentBits[maxInputs][numChunks];
    
    // OR computation
    component orComputer[numChunks];
    
    // process regular chunks
    for (var c = 0; c < numChunks-1; c++) {
        unionBits[c] = Num2Bits(bitsPerChunk);
        unionBits[c].in <== unionState[c];
        
        for (var i = 0; i < maxInputs; i++) {
            parentBits[i][c] = Num2Bits(bitsPerChunk);
            parentBits[i][c].in <== parentStates[i][c];
        }
        
        // use BitwiseOR template for this chunk
        orComputer[c] = BitwiseOR(maxInputs, bitsPerChunk);
        for (var i = 0; i < maxInputs; i++) {
            orComputer[c].isActive[i] <== isActive[i].out;
            for (var b = 0; b < bitsPerChunk; b++) {
                orComputer[c].bits[i][b] <== parentBits[i][c].out[b];
            }
        }
        
        // verify the OR result matches unionState
        for (var b = 0; b < bitsPerChunk; b++) {
            orComputer[c].out[b] === unionBits[c].out[b];
        }
    }
    
    // process last chunk
    unionBits[numChunks-1] = Num2Bits(lastChunkBits);
    unionBits[numChunks-1].in <== unionState[numChunks-1];
    
    for (var i = 0; i < maxInputs; i++) {
        parentBits[i][numChunks-1] = Num2Bits(lastChunkBits);
        parentBits[i][numChunks-1].in <== parentStates[i][numChunks-1];
    }
    
    // use BitwiseOR template for last chunk
    orComputer[numChunks-1] = BitwiseOR(maxInputs, lastChunkBits);
    for (var i = 0; i < maxInputs; i++) {
        orComputer[numChunks-1].isActive[i] <== isActive[i].out;
        for (var b = 0; b < lastChunkBits; b++) {
            orComputer[numChunks-1].bits[i][b] <== parentBits[i][numChunks-1].out[b];
        }
    }
    
    // verify the OR result matches unionState for last chunk
    for (var b = 0; b < lastChunkBits; b++) {
        orComputer[numChunks-1].out[b] === unionBits[numChunks-1].out[b];
    }
}

// -----------------------------------------------------------------------------
// ParentStatesHasherFieldChunked
// Computes hash of active parent states
// -----------------------------------------------------------------------------
template ParentStatesHasherFieldChunked(numChunks, maxInputs) {
    signal input numActiveInputs;
    signal input parentStates[maxInputs][numChunks];
    signal output hash;

    // activity flags
    component lte[maxInputs];
    signal isActive[maxInputs];
    for (var i = 0; i < maxInputs; i++) {
        lte[i] = LessEqThan(5); // 5-bit comparator -> allows up to 31 inputs
        lte[i].in[0] <== i;
        lte[i].in[1] <== numActiveInputs - 1;
        isActive[i] <== lte[i].out;
    }

    // hash each individual parent state
    component stateHashers[maxInputs];
    for (var i = 0; i < maxInputs; i++) {
        stateHashers[i] = PoseidonHashVec(numChunks);
        for (var c = 0; c < numChunks; c++) {
            stateHashers[i].in[c] <== parentStates[i][c];
        }
    }

    // hash all active parents together
    component finalHasher = PoseidonHashVec(maxInputs);
    for (var i = 0; i < maxInputs; i++) {
        finalHasher.in[i] <== stateHashers[i].out * isActive[i];
    }
    hash <== finalHasher.out;
}