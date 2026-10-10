# Phoenix Circuits

Phoenix is one of the transaction models used by Dusk, an open-source public blockchain. Phoenix has a UTXO-based architecture and allows for the execution of obfuscated transactions and confidential smart contracts.

This library contains the implementation of the Phoenix-circuits, to prove, in zero-knowledge, that the following conditions hold true:

1. Membership: every note that is about to be spent is included in the Merkle tree of notes.
2. Ownership: the sender holds the note secret key for every note that is about to be spent.
3. Nullification: the nullifier is calculated correctly.
4. Minting: the value commitment for the newly minted notes are computed correctly.
5. Balance integrity: the sum of the values of all spent notes is equal to the sum of the values of all minted notes + the gas fee + a deposit, where a deposit refers to funds being transfered to a contract.

## Tests

The circuit tests compile the 1- and 2-input circuits with the production CRS, which they download to `~/.dusk/rusk/devnet-piecrust.crs` once. The 3- and 4-input circuits need the CRS extended to `2^17 + 9` powers, three more than the production CRS has. Until that file is hosted next to the production CRS, their tests skip with a notice unless `PHOENIX_EXTENDED_CRS` names a local copy, which is checked against its SHA-256:

```sh
PHOENIX_EXTENDED_CRS=/path/to/devnet-piecrust-plus9.crs make test
```
