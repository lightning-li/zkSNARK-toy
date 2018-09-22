# zkSNARK-toy

This is a toy exmaple about how to use [libsnark](https://github.com/scipr-lab/libsnark). libsnark implements zkSNARK algorithm. This toy example do the following:

- The prover know a merkle tree root `rt`, a leaf `leaf`, a valid merkle branch `path` from `leaf` to `rt`, and `prev_leaf`, the relation between `prev_leaf` and `leaf` is : `prev_leaf = sha256(leaf)`.

- The verifier is given `rt` and `prev_leaf`, can verify that prover know a valid preimage of `prev_leaf`, and a valid merkle brach `path` from `leaf` to `root` using zkSNARK algorithm.  

### howto

`./get-libsnark && make && ./main`

### details

see [here](https://blockchain.iethpay.com/libsnark-example.html) for details.

### performance

- proof generation time : 10.297805s

- proof verification time : 0.041092s

- proof size : 2294 bits == 7 G1 and 1 G2 element. sizeof(G1 element) = sizeof(x,y) = 512 can be compressed into x coordinate and flag(8 bits) which represent y coordinate even or odd，so sizeof(compressed G1) = 264;
Similarly, sizeof(compressed G2 element) = sizeof (x coordinate of G2) + 8 bits = 520 bits, so proof size is 2368 bits. the output of libsnark is different, see https://github.com/zcash/zips/issues/43


