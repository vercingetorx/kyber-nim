# tests/test_kem.nim
import std/[unittest, strformat]
import ../src/kem
import ../src/randombytes

const NTESTS = 1000

proc memeq(a, b: openArray[byte]): bool =
  if a.len != b.len: return false
  for i in 0..<a.len:
    if a[i] != b[i]: return false
  return true

proc randomNonZeroByte(): byte =
  var b: array[1, byte]
  while true:
    randombytes(b)
    if b[0] != 0'u8: return b[0]

proc randomUint64(): uint64 =
  var bytes: array[8, byte]
  randombytes(bytes)
  var x: uint64
  for i in 0..7:
    x = (x shl 8) or uint64(bytes[i])
  return x

suite "CRYSTALS-Kyber KEM tests":

  test "Parameter sizes are sane":
    check CRYPTO_SECRETKEYBYTES > 0
    check CRYPTO_PUBLICKEYBYTES > 0
    check CRYPTO_CIPHERTEXTBYTES > 0
    check CRYPTO_BYTES > 0
    checkpoint fmt"SK={CRYPTO_SECRETKEYBYTES}, PK={CRYPTO_PUBLICKEYBYTES}, CT={CRYPTO_CIPHERTEXTBYTES}, KEY={CRYPTO_BYTES}"

  test "Key agreement: encaps then decaps yields same shared key":
    for _ in 0..<NTESTS:
      var
        pk  = newSeq[byte](CRYPTO_PUBLICKEYBYTES)
        sk  = newSeq[byte](CRYPTO_SECRETKEYBYTES)
        ct  = newSeq[byte](CRYPTO_CIPHERTEXTBYTES)
        keyA= newSeq[byte](CRYPTO_BYTES)
        keyB= newSeq[byte](CRYPTO_BYTES)

      crypto_kem_keypair(pk, sk)   # Alice
      crypto_kem_enc(ct, keyB, pk) # Bob
      crypto_kem_dec(keyA, ct, sk) # Alice

      check memeq(keyA, keyB)

  test "Decapsulation with invalid secret key should NOT match":
    for _ in 0..<NTESTS:
      var
        pk  = newSeq[byte](CRYPTO_PUBLICKEYBYTES)
        sk  = newSeq[byte](CRYPTO_SECRETKEYBYTES)
        ct  = newSeq[byte](CRYPTO_CIPHERTEXTBYTES)
        keyA= newSeq[byte](CRYPTO_BYTES)
        keyB= newSeq[byte](CRYPTO_BYTES)

      crypto_kem_keypair(pk, sk)
      crypto_kem_enc(ct, keyB, pk)

      randombytes(sk)              # sabotage SK
      crypto_kem_dec(keyA, ct, sk)

      check not memeq(keyA, keyB)

  test "Tampered ciphertext should NOT yield the same key":
    for _ in 0..<NTESTS:
      var
        pk  = newSeq[byte](CRYPTO_PUBLICKEYBYTES)
        sk  = newSeq[byte](CRYPTO_SECRETKEYBYTES)
        ct  = newSeq[byte](CRYPTO_CIPHERTEXTBYTES)
        keyA= newSeq[byte](CRYPTO_BYTES)
        keyB= newSeq[byte](CRYPTO_BYTES)

      crypto_kem_keypair(pk, sk)
      crypto_kem_enc(ct, keyB, pk)

      # flip one random, nonzero byte
      let idx = int(randomUint64() mod uint64(ct.len))
      ct[idx] = ct[idx] xor randomNonZeroByte()

      crypto_kem_dec(keyA, ct, sk)
      check not memeq(keyA, keyB)
