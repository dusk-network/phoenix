# Phoenix

Phoenix is the transaction model used by Dusk, an open-source public blockchain with a UTXO-based architecture that allows for the execution of obfuscated transactions and confidential smart contracts.

In privacy-preserving blockchains, there are no accounts or wallets at the protocol layer. Instead, coins are stored as a list of UTXOs with a quantity and some criteria for spending it. In this approach, transactions are created by consuming existing UTXOs and producing new ones in their place. Dusk follows this system, and UTXOs are called notes.

Unlike transparent transaction models, where it is easy to monitor which notes were spent, this task is much harder in a privacy-preserving network, since the details of the notes must be kept hidden. In this case, the network must keep track of all notes ever created by storing their hashes in the leaves of a Merkle tree (called Merkle tree of notes). That is, when a transaction is validated, the network includes the hashes of the new notes to the leaves of this tree.
To prevent double spending, transactions include a list of deterministic values called nullifiers, one for each note being spent, which invalidates these notes.
The idea here is that the nullifier is computed in such a way that an external observer cannot link it to any specific note. This way, when a transaction is accepted, the network knows that some notes are nullified and can no longer be spent, but does not know which ones.

Please refer to the [docs](https://github.com/dusk-network/phoenix/blob/master/docs/v2/protocol.pdf) for more detail.
