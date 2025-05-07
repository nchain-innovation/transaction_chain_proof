# Transaction Chain Proof

This crate provides an implementation of the Proof-Carrying-Data predicate `TransactionChainProof`, which was first described in the paper [NFT Trade in Bitcoin with Off-chain Receipts](https://eprint.iacr.org/2023/697), Kiraz, M, Larraia, E., Vaughan, O., _Application Intelligence and Blockchain Security Workshop (AIBlock) in conjunction with ACNS 2023_.

A _transaction chain_ at indices `(input_index, output_index)` is a sequence `(Tx0, .., Txn)` of Bitcoin transactions such that for every `0 <= i <= n-1`

```
Tx(i+1).inputs[input_index] = (Txi.txid(), output_index)
```

Namely, the input of `Tx(i+1)` at position `input_index` is the output of `Txi` at position `output_index`.

The crate implements two PCD predicates using the Arkworks PCD crate:<sup><a href="#footnote1">1</a></sup>
- [`TransactionChainProofPredicate`](./src/predicates/tcp.rs#L57)
- [`UniversalTransactionChainProofPredicate`](./src/predicates/universal_tcp.rs#L57)

Both predicates are used to prove the following statement: 

> _"The UTXO `(Txn, input_index)` is part of a transaction chain at indices `(input_index, output_index)` starting at the transaction with TxID `genesis_txid`"_ 

the difference is that in [`TransactionChainProofPredicate`](./src/predicates/tcp.rs#L57) the prover only shows to the verifier `(Txn, input_index)` (the `genesis_txid` is assumed to have been agreed upon), while in [`UniversalTransactionChainProofPredicate`](./src/predicates/universal_tcp.rs#L57) the prover shows the verifier `(Txn, input_index)` _and_ `genesis_txid`.

In a nutshell, this difference means that when using [`TransactionChainProofPredicate`](./src/predicates/tcp.rs#L57) in a SNARK `genesis_txid` is hard-coded in the verifying key, while when using [`UniversalTransactionChainProofPredicate`](./src/predicates/universal_tcp.rs#L57) `genesis_txid` is passed as a public input.

## Getting started

The library compiles on the nightly toolchain of the Rust compiler.
To install the latest version of Rust, first install rustup by following the instructions here, or via your platform's package manager. Once rustup is installed, install the Rust toolchain by invoking:

```bash
rustup install nightly
```

After that, you can clone and test the library by using `cargo`

```bash
git clone https://github.com/nchain-innovation/transaction_chain_proof
cd transaction_chain_proof
cargo test
```

## Further documentation

For further documentation on the structures and function implemented in the library, use `cargo`

```bash
cargo doc --open
```

## Disclaimer

The code and resources within this repository are intended for research and educational purposes only.

Please note:

- No guarantees are provided regarding the security or the performance of the code.
- Users are responsible for validating the code and understanding its implications before using it in any capacity.
- There may be edge cases causing bugs or unexpected behaviours. Please contact us if you find any bug.

## License

The code is released under the attached [LICENSE](./LICENSE.txt).

## Footnotes

[<a name="footnote1">1</a>]: We forked the original [ark_pcd](https://github.com/arkworks-rs/pcd) crate and modified it so that it works with elliptic curves in Short Weierstrass form. You can find the fork [here](https://github.com/BarbacoviF/pcd/tree/barbacovif/use-short-weierstrass-curve).


