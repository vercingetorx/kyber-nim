# kyber-nim — Pure Nim CRYSTALS-Kyber (KEM)

A **pure Nim** port of the CRYSTALS-Kyber key encapsulation mechanism (post-quantum KEM).
No C glue required. Uses SHA3/SHAKE (Keccak) and constant-time helpers implemented in Nim.

Kyber lets two parties agree on a **shared 32-byte session key** using only a public key and a one-shot ciphertext (“envelope”). It’s IND-CCA2 secure and NIST-standardized.

## Status

* Implements the full KEM (keygen, encaps, decaps) for **Kyber512/768/1024**.
* Passes the official **NIST KAT (.rsp)** vectors.
* Deterministic and OS-random entry points provided.

## Sizes (by parameter set)

| Set       | Public Key | Secret Key | Ciphertext | Session Key |
| --------- | ---------- | ---------- | ---------- | ----------- |
| Kyber512  | 800 B      | 1632 B     | 768 B      | 32 B        |
| Kyber768  | 1184 B     | 2400 B     | 1088 B     | 32 B        |
| Kyber1024 | 1568 B     | 3168 B     | 1568 B     | 32 B        |

> The **session key is always 32 bytes**; only pk/sk/ct sizes change with security level.

## Quick API

Simple, human-readable API (see `api.nim`). “Envelope” = ciphertext you send.

```nim
import api

# 1) Alice creates an identity (public/private keys).
let alice = generateKeys()  # uses OS randomness

# 2) Bob creates an envelope for Alice using her PUBLIC key,
#    and immediately gets his copy of the session key.
let (envelope, bobsSessionKey) = createEnvelope(alice.publicKey)

# 3) Alice opens the received envelope with her PRIVATE key
#    to obtain the same session key.
let alicesSessionKey = openEnvelope(alice.privateKey, envelope)

# 4) Both keys must match; use this 32-byte secret for AEAD, etc.
doAssert bobsSessionKey == alicesSessionKey
```

### Deterministic variants (testing / reproducibility)

You can supply **coins** (randomness) explicitly:

```nim
import kyber, std/random

var keypairCoins = newSeq[byte](KeypairCoinBytes)  # 64 bytes
var encCoins     = newSeq[byte](EncCoinBytes)      # 32 bytes
discard rand(keypairCoins)                         # fill however you like
discard rand(encCoins)

let me = generateKeys(keypairCoins)
let (env, sk1) = createEnvelope(me.publicKey, encCoins)
let sk2 = openEnvelope(me.privateKey, env)
```

## Selecting the parameter set

Current default is **Kyber768**. The parameter set is controlled by compiler flag:

```bash
-d:kyber512 # KYBER_K == 2
-d:kyber768 # KYBER_K == 3 (default, can be omitted during compilation)
-d:kyber1024 # KYBER_K == 4
```

(If you prefer build-time switches, you can wrap this in `when defined(kyber512|kyber768|kyber1024)` guards and pass `-d:kyber768`, etc.)

## Testing (KAT)

A lightweight KAT harness is included (parses NIST `.rsp` files and checks pk/sk/ct/ss).

  ```
  KAT_RSP=/nistkat/PQCkemKAT_2400.rsp
  ```
* Run the test (see `nistkat/test_kat_runner.nim` in the repo).
* Compile with flag `-d:kat`

The API also has deterministic hooks (coins) to mirror the reference flow.

## RNG

* **API** functions use OS randomness (`/dev/urandom` / platform equivalent).
* The **KAT** code uses a deterministic SHAKE-based DRBG to match the reference vectors.

## Security notes

* Constant-time techniques are used where required (e.g., `verify`, `cmov`), but the code has **not been audited**.
* Nim is GC’d; **secret zeroization isn’t guaranteed**. Use with care for long-lived secrets.

## Layout

```
src/
  cbd.nim            # Centered binomial samplers (eta1/eta2) used for noise
  indcpa.nim         # CPA PKE core (gen_matrix, rej_uniform, keygen/enc/dec)
  kem.nim            # CCA KEM wrapper (keypair, encapsulate, decapsulate)
  ntt.nim            # Forward/inverse NTT and base multiplication; zetas table
  params.nim         # Parameter set & sizes; selects variant via KYBER_K (512/768/1024)
  poly.nim           # Polynomial ops: (de)serialize, (de)compress, noise, NTT wrappers
  polyvec.nim        # Vector-of-polys ops: (de)serialize, (de)compress, NTT wrappers
  randombytes.nim    # OS RNG for public API (e.g., /dev/urandom)
  reduce.nim         # Montgomery & Barrett reductions (mod q)
  symmetric.nim      # SHA3-256/512, SHAKE128/256 wrappers (XOF, PRF, rkprf)
  types.nim          # Small structs/aliases used across the code (Poly, PolyVec, etc.)
  verify.nim         # Constant-time compare and conditional moves
kyber.nim        # high-level friendly API (Envelope-based)
test/            # basic tests
nistkat/         # KAT tests
private/         # crypto backends
```

### Note: This code is for reference. It has not been audited and should not be used in production.
