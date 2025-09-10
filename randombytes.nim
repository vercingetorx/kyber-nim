proc randombytes*(output: var openArray[byte]) =
  try:
    var f = open("/dev/urandom")
    discard f.readBytes(output, 0, output.len)
    f.close()
  except:
    quit("Could not open /dev/urandom")
