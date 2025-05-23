pragma circom 2.1.9;

include "./bloom.circom"; 


component main {public [root, key, isExclusion]} = BloomFilter(16384, 2, 20); //(2^14);