from itertools import *
import struct
import zlib
import string
from time import *

import sys
sys.path.append('..')
import crypto

sbox = { chr(k):chr(v) for k, v in enumerate(crypto.sbox) }

flag_png_enc = open("../flag.png.enc", "r").read()

# this will become our recovered codebook
code = {}

# we will almost always use this function to add known codewords to the codebook
# Note: We throw an AssertionError is we try to redefine a codeword.
def it_is_known(code, a, b):
    code = dict(code) # make a copy of the codebook

    #if type(a) == str: a = list(a)
    #if type(b) == str: b = list(a)

    for x, y in zip(a, b):
        if x in code:
            assert code[x] == y
        code[x] = y

    return code

# 1. by the code generation in crypto.py all bytes will stay in the same
# orbit in the code as in the sbox. Also the code generation does not allow
# fixedpoint in the code. Thus all 2-cycles will be the same in the code as in the sbox.

def invert(lut): return {v:k for (k,v) in lut.items() }

def orbit(code, x):
    # This code is only relevant when we have an incomplete codebook.
    # It find the first known element in this cycle.
    inv_code = invert(code)
    seen = set()
    while x in inv_code:
        if x in seen: break
        seen.add(x)
        x = inv_code[x]

    # Now we simply follow the cycle around, until we either run out of
    # known codewords or we have been around the whole cycle.
    o = []
    while x not in o:
        o.append(x)
        if x not in code:
            o.append(None)
            break
        x = code[x]

    # return the orbit/cycle of x in code
    return o

# Now we can fix the 2-cycles
for i in range(256):
    o = orbit(sbox, chr(i))
    if len(o) == 2: # this is a 2-cycle
        code = it_is_known(code, o, o[::-1])

def print_codebook_info(code):
    print "Codebook length:", len(code)

# now we know 52 bytes already
print_codebook_info(code)

def decrypt(code, enc):
    return "".join(code.get(e,"\xff") for e in enc)

def decrypt_and_save(code, enc, filename):
    flag_png_dec = decrypt(code, flag_png_enc)
    open(filename, "w").write(flag_png_dec)

decrypt_and_save(code, flag_png_enc, "flag.png.dec.2")

# 2. Next we know some stuff from the png format

# PNG file header
code = it_is_known(code, flag_png_enc[:8], "\x89PNG\x0d\x0a\x1a\x0a")

# First chunk must be an IHDR and it have a fixed length.
code = it_is_known(code, flag_png_enc[8:8+8], "\x00\x00\x00\x0dIHDR")

# We also know that there must be an IEND chunk as the end
code = it_is_known(code, flag_png_enc[-8:], "IEND")

# Opening the decoded file i vbindiff at this point gives us that the next
# chunk must be a sBIT chunk which is again of fixed size
code = it_is_known(code, flag_png_enc[0x21:0x21+8], "\x00\x00\x00\x04sBIT")

# same for the pHYs chunk
code = it_is_known(code, flag_png_enc[0x31:0x31+8], "\x00\x00\x00\x09pHYs")

# now we know 68 bytes of the codebook
print_codebook_info(code)
decrypt_and_save(code, flag_png_enc, "flag.png.dec.2")

# 3. Now that we know some non-2-cycle codewords we might be able to figure out some more.
# Because of the structure of the sbox we know that there are only 3 cycle types: 2,3,4

def repair_cycles(code):
    # fix cycles missing only a single element
    for i in range(256):
        o1 = orbit(code, chr(i))
        o2 = orbit(sbox, chr(i))
        if None in o1 and len(o1) == len(o2):
            missing_element = list(set(o2) - set(o1))[0]
            code = it_is_known(code, o1[-2], missing_element)

    # fix cycles missing the link between first and last
    for i in range(256):
        o1 = orbit(code, chr(i))
        o2 = orbit(sbox, chr(i))
        if None in o1 and len(o1) > len(o2):
            code = it_is_known(code, o1[-2], o1[0])

    # fix 4-cycles which got split into 2 2-cycles, when we know one of the 2-cycles.
    for i in range(256):
        o1 = orbit(code, chr(i))
        o2 = orbit(sbox, chr(i))
        if None not in o1 and len(o1) < len(o2):
            bicycle = list(set(o2) - set(o1))
            code = it_is_known(code, bicycle, bicycle[::-1])

    return code

code = repair_cycles(code)

# Now we know 85 codewords
print_codebook_info(code)
decrypt_and_save(code, flag_png_enc, "flag.png.dec.3")


# 4. Again we open the file i vbindiff and find that the next chunk might be a
# tEXt chunk so lets test that.
code = it_is_known(code, flag_png_enc[0x4a:0x4a+8], "tEXt")

# .. it seems right, and it seem that the lenght of the chunk is 30
code = it_is_known(code, flag_png_enc[0x46:0x46+8], "\x00\x00\x00\x1etEXt")

# .. and the next chunk looks like a zTXt of length 0x93
code = it_is_known(code, flag_png_enc[0x88:0x88+8], "\x00\x00\x00\x93zTXt")

# if we look at the first tEXt chunk it seems like the name of the challenge:
# P..nf.. N.t.... G..p...s
# Painful Network Graphics

code = it_is_known(code, flag_png_enc[0x54:], "Painful Network Graphics")

# .. now we can see alot of broken strings in the recovered file
code = it_is_known(code, flag_png_enc[0x78:], "Author\x00br0ns")
code = it_is_known(code, flag_png_enc[0x12f:], "Copyright\x00Copyright Pwnies 2018")
code = it_is_known(code, flag_png_enc[0x180:], "Software\x00www.inkscape.org")
code = it_is_known(code, flag_png_enc[0x1a5:], "Disclaimer\x00We cannot be held liable for any loss of sanity")
code = it_is_known(code, flag_png_enc[0x1eb:], "Warning\x00")

# ... and we can repair some lengths
code = it_is_known(code, flag_png_enc[0x70:], "\x00\x00\x00\x0c")
code = it_is_known(code, flag_png_enc[0x178:], "\x00\x00\x00\x19")
code = it_is_known(code, flag_png_enc[0x5a70e:], "\x00\x00\x0c\xf1") # last IDAT has diffrent size

code = repair_cycles(code)

# This effort brings us to 144 known codewords. Halfway done!
print_codebook_info(code)
decrypt_and_save(code, flag_png_enc, "flag.png.dec.4")

# 5. Now we can list some chunks

def u32b(d): return struct.unpack(">L", d)[0]

def decode_chunks(code, enc):
    dec = [code.get(e, None) for e in enc]
    header, rest = dec[:8], dec[8:]
    enc_rest = enc[8:]

    chunks = []
    while rest:
        length, rest = rest[:4], rest[4:]
        if None in length: break # we can't decode more chunks
        length = u32b("".join(length))
        typ, rest = rest[:4], rest[4:]
        if None not in typ: typ = "".join(typ)
        data, rest = rest[:length], rest[length:]
        crc, rest = rest[:4], rest[4:]
        if None not in crc: crc = u32b("".join(crc))
        enc_chunk, enc_rest = enc_rest[:4+4+length+4], enc_rest[4+4+length+4:]

        chunks.append(((typ, data, crc), enc_chunk))

    return chunks

def print_chunks(code, chunks):
    print "All decodeable chunks:"
    for i, (dec_chunk, enc_chunk) in enumerate(chunks):
        missing = set(e for e in enc_chunk if e not in code)
        print i, dec_chunk[0], len(missing)

chunks = decode_chunks(code, flag_png_enc)
#print_chunks(code, chunks)

# 6. Bruteforcing!

def bruteforcer(code, enc_chunk, checker, i=0):
    code = dict(code)

    # search for the next unknown codeword
    while i < len(enc_chunk) and enc_chunk[i] in code: i += 1

    if i != len(enc_chunk):
        unknown = enc_chunk[i]
        for x in orbit(sbox, unknown):
            if x == unknown: continue # codebook have no fixedpoints
            code[unknown] = x

            if checker and not checker(code, enc_chunk): continue

            try:
                return bruteforcer(code, enc_chunk, checker, i=i)
            except AssertionError:
                pass

        assert False # no more options left, this was a bad path.
    else:
        # now we can decode the full chunk
        chunk = "".join(code[e] for e in enc_chunk)

        # crc is good?
        assert zlib.crc32(chunk[4:-4]) & 0xffffffff == u32b(chunk[-4:])

        # fix the cycles and we are done!
        return repair_cycles(code) # Yay, we have decrypted a full chunk

print "Bruteforcing!"

for i in range(12):
    chunks = decode_chunks(code, flag_png_enc)
    # chunk 5 and 10 are zTXt, we will fix them later
    if i in (5,10): continue
    code = bruteforcer(code, chunks[i][1],  None)
    print_codebook_info(code)


# 191 known code words
print_codebook_info(code)
chunks = decode_chunks(code, flag_png_enc)
#print_chunks(code, chunks)

def zTXt_checker(code, enc_chunk):
    # decrypt until first unknown codeword
    chunk = "".join(code[e] for e in takewhile(lambda e: e in code, enc_chunk))
    compressed = chunk[8:].split("\x00\x00")[1] # extract the deflate data

    # try to decompress it
    try:
        # making a decomprss object is neccesary, becuase python is weird
        decomp = zlib.decompressobj()
        decompressed = decomp.decompress(compressed)

        # assert that the string is printable.
        # Otherwise let the bruteforcer backtrack
        assert all(c in string.printable for c in decompressed)

    except zlib.error as e:
        return False # don't take this path.

    return True # this path might be good


code = bruteforcer(code, chunks[5][1], zTXt_checker)

# 229 known code words
print_codebook_info(code)
chunks = decode_chunks(code, flag_png_enc)
#print_chunks(code, chunks)

code = bruteforcer(code, chunks[10][1], zTXt_checker)

# 256 known code words. we are done!
print_codebook_info(code)
decrypt_and_save(code, flag_png_enc, "flag.png.dec.6")

import os
os.system('ln -s flag.png.dec.6 flag.png')
