# Phoenix Core

Phoenix is an anonymity-preserving zero-knowledge proof-powered transaction model formalized and developed by Dusk Network.

# General

Although somewhat based on the UTXO model utilized in the [Zcash protocol](https://github.com/zcash/zips/blob/master/protocol/protocol.pdf), Phoenix is uniquely capable to enable privacy-preserving smart contract by allowing confidential spending of public output (gas and coinbase transactions).

Unlike Zcash, in which transactions can be potentially linked [\[1\]](https://arxiv.org/pdf/1712.01210)[\[2\]](https://orbilu.uni.lu/bitstream/10993/39996/1/Zcash_Miner_Linking%20%282%29.pdf), Phoenix guarantees transaction unlinkability through combining the so-called "obfuscated notes" (i.e. outputs containing encrypted values) with "transparent notes" (i.e. outputs containing plain values) into a single Merkle Tree.

All the transactions utilize one-time keys. It is totally up to the user how he wants to manage his secret key: he could have one or many secret keys for many unspent outputs. The inner Diffie-Hellman key exchange randomness mechanism guarantees the note public key will not repeat for the same spender public key, which causes the identification of the spender to be unfeasible.

For further details, check out the technical paper to be published soon.

# Concepts

## Zero-knowledge

Phoenix uses zero-knowledge proofs to guarantee:

- Transaction balance consistency
- Prevent double-spending attacks
- Prove the ownership of unspent outputs

The set of unspent outputs is a union of obfuscated and transparent note sets. Both notes share a similar structure aside from the obfuscated containing encrypted values and transparent notes containing plain values.

The owner of a note can share his/her `View Key`, allowing a third-party (e.g. a wallet provider) to detect the outputs belonging to the owner as well as the value of the encrypted in the note, in case of an obfuscated note.

The spending of a note can be done only via a `Secret Key`, known only to the owner of the note.
