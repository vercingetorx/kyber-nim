import std/[sequtils, strutils]
import rng

const seed = "061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1"

proc unhex(s: string): seq[byte] =
  ## Parse hex with optional spaces/newlines.
  var i = 0
  while i < s.len:
    while i < s.len and s[i].isSpaceAscii: inc i
    if i+1 >= s.len: break
    result.add(parseHexInt(s[i..i+1]).byte)
    inc i, 2

randombytes_init(unhex(seed))

var buf: array[64, byte]
discard randombytes(buf)

for b in buf:
  stdout.write(b.toHex(2))
stdout.write("\n")

# correct output:
# 7C9935A0B07694AA0C6D10E4DB6B1ADD2FD81A25CCB148032DCD739936737F2DB505D7CFAD1B497499323C8686325E4792F267AAFA3F87CA60D01CB54F29202A
