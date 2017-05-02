# zkSNARK-toy

This is a toy exmaple about how to use [libsnark](https://github.com/scipr-lab/libsnark). libsnark implements zkSNARK algorithm. This toy example do the following:

- The prover know a merkle tree root `rt`, a leaf `leaf`, a valid merkle branch `path` from `leaf` to `rt`, and `prev_leaf`, the preimage of `leaf`(`leaf = sha256(prev_leaf)`).

- The verifier is given `rt` and `prev_leaf`, can verify that prover know a valid preimage of `leaf`, and a valid merkle brach `path` from `leaf` to `root` using zkSNARK algorithm.  

### howto

`./get-libsnark && make && ./main`

### details

see [here](https://blockchain.iethpay.com/libsnark-example.html) for details.
