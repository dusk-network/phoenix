# Phoenix

Phoenix is the privacy-preserving transaction model used by Dusk. It implements a UTXO-based architecture with obfuscated transactions using zero-knowledge proofs.

In Phoenix, coins are stored as encrypted notes in a Merkle tree. Transactions consume existing notes and produce new ones, using nullifiers to prevent double spending without revealing which notes were spent.

## Repository Map

```
phoenix/
├── core/          # phoenix-core — core types: keys, notes, stealth addresses, transactions
├── circuits/      # phoenix-circuits — ZKP circuit definitions (PLONK-based)
├── docs/          # Protocol specifications (v1, v2)
└── Makefile       # Root Makefile delegating to member crates
```

### `core/` (`phoenix-core`)

Core library providing the fundamental Phoenix types:

- **Keys**: `SecretKey`, `PublicKey`, `ViewKey` — key derivation and management
- **Notes**: `Note`, `NoteType`, `Sender` — the UTXO type with encryption
- **Stealth addresses**: `StealthAddress` — one-time addresses for recipient privacy
- **Transactions**: `TxSkeleton` — transaction structure (requires `alloc` feature)
- **Encryption**: AES-GCM encryption for note data
- **Value commitments**: Pedersen commitment scheme for hiding transaction values

### `circuits/` (`phoenix-circuits`)

Zero-knowledge circuit definitions for proving transaction validity:

- `TxCircuit` — main transaction circuit with configurable tree height (`H`) and input count (`I`)
- `InputNoteInfo` / `OutputNoteInfo` — circuit witness data for notes
- Sender encryption gadget
- Built on `dusk-plonk` (gated behind the `plonk` feature)

## Commands

```bash
make test          # Run all tests (core + circuits, --release)
make test-no-std   # Verify no_std compilation (rkyv, wasm targets)
make no-std        # Verify bare-metal target compatibility (thumbv6m-none-eabi)
make clippy        # Run clippy on all crates
make fmt           # Format code (requires nightly toolchain)
make doc           # Generate documentation
make clean         # Clean build artifacts
```

Tests **must** use `--release` because phoenix depends on `dusk-plonk` — debug builds take extremely long for PLONK proofs.

## Feature Flags

### `phoenix-core`

| Feature    | Description                                             | Default |
|------------|---------------------------------------------------------|---------|
| `alloc`    | Enables `TxSkeleton` and heap-allocated types           | Yes     |
| `rkyv-impl`| rkyv serialization (enables rkyv on jubjub, bls12_381) | No      |
| `serde`    | serde + JSON support (implies `alloc`)                  | No      |

### `phoenix-circuits`

| Feature    | Description                                             | Default |
|------------|---------------------------------------------------------|---------|
| `plonk`   | Enables circuit implementations via `dusk-plonk`         | Yes     |
| `rkyv-impl`| rkyv serialization for circuit types                    | No      |

## Architecture

### Privacy Model

Phoenix uses a **UTXO model** where:

1. Notes are hashed and stored in a **Merkle tree of notes**
2. Spending a note requires proving ownership via zero-knowledge proof without revealing which note is spent
3. **Nullifiers** are deterministic values that invalidate spent notes — they cannot be linked to specific notes by external observers
4. **Stealth addresses** provide recipient privacy via one-time addresses
5. **Value commitments** (Pedersen scheme) hide transaction amounts

### Transaction Flow

1. Sender selects input notes and generates Merkle openings
2. `TxCircuit` proves: ownership of inputs, correct nullifier computation, balance (inputs = outputs + fee + deposit), and sender encryption
3. Output notes are encrypted for recipients
4. The network verifies the proof and adds nullifiers to the spent set

### Key Dependencies

- `dusk-plonk` — PLONK proving system (private repo, requires auth token)
- `dusk-jubjub` — JubJub elliptic curve (key derivation, stealth addresses)
- `dusk-bls12_381` — BLS12-381 curve (scalars used in Merkle tree, circuit)
- `dusk-poseidon` — Poseidon hash (note hashing, Merkle tree)
- `poseidon-merkle` — Merkle tree implementation
- `jubjub-schnorr` — Schnorr signatures (transaction authorization)
- `jubjub-elgamal` — ElGamal encryption (sender encryption in circuits)

## Conventions

- **`no_std`**: Both crates are `no_std`. Do not add `std` dependencies.
- **Serialization**: Use `dusk-bytes` for canonical byte encoding, `rkyv` for zero-copy deserialization (feature-gated), `serde` for JSON (feature-gated).
- **Field ordering**: Do not reorder fields in `rkyv`-serializable structs — it breaks archive compatibility.
- **Constant-time**: Operations on secret data (keys, blinding factors) must remain constant-time. Do not introduce branches or early returns on secrets.
- **Edition 2024**: The workspace uses Rust edition 2024 with MSRV 1.85.

## Change Propagation

`phoenix-core` and `phoenix-circuits` are used by downstream crates in the Dusk ecosystem:

| Changed crate     | Also verify                                |
|--------------------|--------------------------------------------|
| `phoenix-core`     | `phoenix-circuits`, `rusk/contracts`, `rusk/wallet-core`, `rusk/vm` |
| `phoenix-circuits` | `rusk-prover`, `rusk`                      |

## Git Conventions

- Default branch: `master`
- Commit messages: concise, imperative mood (e.g. "add Makefile targets for CI parity")
- License: MPL-2.0
