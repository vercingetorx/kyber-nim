# rng.nim — NIST KAT AES-256-CTR DRBG + AES seed expander

import std/math
import ../private/aes/aes

# ---- Return codes ------------------------------------------------
const
  RNG_SUCCESS*     = 0
  RNG_BAD_MAXLEN*  = 1
  RNG_BAD_OUTBUF*  = 2
  RNG_BAD_REQ_LEN* = 3

# ---- AES-256 ECB (single block) -----------------------------------------------
proc AES256_ECB(key: openArray[byte], ctr: openArray[byte], buffer: var array[16, byte]) =
  doAssert key.len == 32
  doAssert ctr.len == 16
  var k: array[32,byte]
  var inb: array[16,byte]
  for i in 0..<32: k[i] = key[i]
  for i in 0..<16: inb[i] = ctr[i]
  aes256EcbBlock(k, inb, buffer)

# ---- AES seed expander (used by some NIST KAT harnesses) ----------------------
type
  AES_XOF_struct* = object
    key*: array[32, byte]
    ctr*: array[16, byte]
    buffer*: array[16, byte]
    buffer_pos*: int
    length_remaining*: uint32

proc seedexpander_init*(ctx: var AES_XOF_struct,
                        seed: openArray[byte],
                        diversifier: openArray[byte],
                        maxlen: uint32): int =
  ## seed = 32 bytes, diversifier = 8 bytes, maxlen < 2^32
  if maxlen >= 0x1_0000_0000'u64: return RNG_BAD_MAXLEN
  doAssert seed.len == 32
  doAssert diversifier.len == 8

  # key
  for i in 0..<32: ctx.key[i] = seed[i]
  # ctr[0..7] = diversifier, ctr[8..11] = maxlen (big-endian), ctr[12..15] = 0
  for i in 0..<8: ctx.ctr[i] = diversifier[i]
  var m = maxlen
  ctx.ctr[11] = (m and 0xFF).byte; m = m shr 8
  ctx.ctr[10] = (m and 0xFF).byte; m = m shr 8
  ctx.ctr[ 9] = (m and 0xFF).byte; m = m shr 8
  ctx.ctr[ 8] = (m and 0xFF).byte
  for i in 12..15: ctx.ctr[i] = 0

  ctx.buffer_pos = 16
  for i in 0..15: ctx.buffer[i] = 0
  ctx.length_remaining = maxlen
  RNG_SUCCESS

proc seedexpander*(ctx: var AES_XOF_struct, x: var openArray[byte], xlen: uint32): int =
  if x.len == 0: return RNG_BAD_OUTBUF
  if xlen.uint64 >= ctx.length_remaining.uint64: return RNG_BAD_REQ_LEN
  doAssert x.len >= int(xlen), "x must be at least xlen bytes"

  ctx.length_remaining = ctx.length_remaining - xlen

  var offset = 0'u32
  while offset < xlen:
    let avail = 16 - ctx.buffer_pos
    let need  = int(xlen - offset)

    if need <= avail:
      for i in 0..<need:
        x[int(offset) + i] = ctx.buffer[ctx.buffer_pos + i]
      ctx.buffer_pos += need
      return RNG_SUCCESS

    # take what's in the buffer
    for i in 0..<avail:
      x[int(offset) + i] = ctx.buffer[ctx.buffer_pos + i]
    offset += uint32(avail)

    # refill buffer: AES256-ECB(key, ctr)
    AES256_ECB(ctx.key, ctx.ctr, ctx.buffer)
    ctx.buffer_pos = 0

    # increment ctr[12..15] (big-endian), exactly like rng.c
    var i = 15
    while i >= 12:
      if ctx.ctr[i] == 0xff'u8:
        ctx.ctr[i] = 0'u8
        dec i
      else:
        inc ctx.ctr[i]
        break

  return RNG_SUCCESS

# ---- AES-256-CTR DRBG (NIST) --------------------------------------------------
type
  AES256_CTR_DRBG_struct* = object
    Key*: array[32, byte]
    V*:   array[16, byte]
    reseed_counter*: uint64

var DRBG_ctx*: AES256_CTR_DRBG_struct

proc AES256_CTR_DRBG_Update(provided_data: ptr array[48, byte] = nil,
                            Key: var array[32, byte],
                            V:   var array[16, byte]) =
  var temp: array[48, byte]
  var ctrLocal: array[16, byte]
  var outBlk: array[16, byte]
  var off = 0
  for _ in 0..2:
    # increment V (big-endian 128-bit)
    var carry = 1
    var j = 15
    while j >= 0 and carry != 0:
      let s = int(V[j]) + carry
      V[j] = (s and 0xFF).byte
      carry = s shr 8
      dec j

    # AES256-ECB(Key, V)
    ctrLocal = V
    AES256_ECB(Key, ctrLocal, outBlk)
    for i in 0..15: temp[off + i] = outBlk[i]
    off += 16
  if provided_data != nil:
    for i in 0..47:
      temp[i] = temp[i] xor provided_data[][i]
  for i in 0..31: Key[i] = temp[i]
  for i in 0..15: V[i]   = temp[32 + i]

proc randombytes_init*(entropy_input: openArray[byte],
                       personalization_string: openArray[byte] = @[],
                       security_strength: int = 256) =
  ## entropy_input: 48 bytes; personalization_string: 0 or 48 bytes
  ## security_strength is ignored to match rng.c signature.
  doAssert entropy_input.len == 48
  doAssert personalization_string.len == 0 or personalization_string.len == 48

  var seed_material: array[48, byte]
  for i in 0..47: seed_material[i] = entropy_input[i]
  if personalization_string.len == 48:
    for i in 0..47:
      seed_material[i] = seed_material[i] xor personalization_string[i]

  for i in 0..31: DRBG_ctx.Key[i] = 0
  for i in 0..15: DRBG_ctx.V[i]   = 0
  AES256_CTR_DRBG_Update(addr seed_material, DRBG_ctx.Key, DRBG_ctx.V)
  DRBG_ctx.reseed_counter = 1

proc randombytes*(x: var openArray[byte]) =
  ## Fill x with pseudorandom bytes (must call randombytes_init first).
  var produced = 0
  var outBlk: array[16, byte]
  while produced < x.len:
    # increment V (big-endian)
    var carry = 1
    var j = 15
    while j >= 0 and carry != 0:
      let s = int(DRBG_ctx.V[j]) + carry
      DRBG_ctx.V[j] = (s and 0xFF).byte
      carry = s shr 8
      dec j

    # block = AES256-ECB(Key, V)
    var ctrLocal = DRBG_ctx.V
    AES256_ECB(DRBG_ctx.Key, ctrLocal, outBlk)

    let n = min(16, x.len - produced)
    for i in 0..<n:
      x[produced + i] = outBlk[i]
    produced += n
  AES256_CTR_DRBG_Update(nil, DRBG_ctx.Key, DRBG_ctx.V)
  inc DRBG_ctx.reseed_counter
