import unittest, os, strutils
import ../src/params
import ../src/kem
import rng

# NOTE: compile with -d:kat

# --- helpers ---------------------------------------------------------------

proc unhex(s: string): seq[byte] =
  ## Parse hex with optional spaces/newlines.
  var i = 0
  while i < s.len:
    while i < s.len and s[i].isSpaceAscii: inc i
    if i+1 >= s.len: break
    result.add(parseHexInt(s[i..i+1]).byte)
    inc i, 2

type Kat = tuple[seed, pk, sk, ct, ss: seq[byte]]

proc parseRsp(path: string): seq[Kat] =
  var f = open(path)
  defer: f.close()
  var line: string
  var seed, pk, sk, ct, ss: seq[byte]
  while f.readLine(line):
    if line.len == 0: continue
    if   line.startsWith("seed = "): seed = unhex(line[7..^1])
    elif line.startsWith("pk = "):   pk   = unhex(line[5..^1])
    elif line.startsWith("sk = "):   sk   = unhex(line[5..^1])
    elif line.startsWith("ct = "):   ct   = unhex(line[5..^1])
    elif line.startsWith("ss = "):
      ss = unhex(line[5..^1])
      # One complete record ends at ss
      result.add( (seed, pk, sk, ct, ss) )

# --- config ---------------------------------------------------------------

# Point this to generated kat file, e.g. PQCkemKAT_2400.rsp for Kyber768
const DefaultRsp = "PQCkemKAT_2400.rsp"
let katPath = getEnv("KAT_RSP", DefaultRsp)

# Limit how many vectors to run (env KAT_LIMIT=N); default: all
let katLimit = try: parseInt(getEnv("KAT_LIMIT", "0")) except: 0

# --- tests ----------------------------------------------------------------

suite "Kyber KEM — official NIST KAT (.rsp)":
  test "match .rsp vectors":
    let vecs = parseRsp(katPath)
    check vecs.len > 0

    var ran = 0
    for v in vecs:
      if katLimit > 0 and ran >= katLimit: break
      inc ran

      # Seed DRBG exactly like the C KAT harness
      randombytes_init(v.seed)

      # keypair
      var pk = newSeq[byte](KYBER_PUBLICKEYBYTES)
      var sk = newSeq[byte](KYBER_SECRETKEYBYTES)
      crypto_kem_keypair(pk, sk)
      check pk == v.pk
      check sk == v.sk

      # encaps
      var ct = newSeq[byte](KYBER_CIPHERTEXTBYTES)
      var ssB = newSeq[byte](KYBER_SSBYTES)
      crypto_kem_enc(ct, ssB, pk)
      check ct == v.ct
      check ssB == v.ss

      # decaps
      var ssA = newSeq[byte](KYBER_SSBYTES)
      crypto_kem_dec(ssA, ct, sk)
      check ssA == v.ss
