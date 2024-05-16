# Phoenix Circuits

Phoenix is the transaction model used by Dusk, an open-source public blockchain with a UTXO-based architecture that allows for the execution of obfuscated transactions and confidential smart contracts.

This library contains the implementation of the Phoenix-circuits, to prove, in zero-knowledge, that the following conditions hold true:

1. Membership: every note that is about to be spent is included in the Merkle tree of notes.
2. Ownership: the sender holds the note secret key for every note that is about to be spent.
3. Nullification: the nullifier is calculated correctly.
4. Minting: the value commitment for the newly minted notes are computed correctly.
5. Balance integrity: the sum of the value of all spent notes is equal to the value of the sum of all minted notes + the gas fee + a crossover, where a crossover refers to funds being transfered to a contract.
