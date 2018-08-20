#!/usr/bin/env python2.7
import sys
import hashlib

def die(s):
    print >>sys.stderr, s
    sys.exit(1)

#SBOX#

def init(key):
    code = range(0x100)
    for i in xrange(10000):
        x = y = i % len(code)
        for _ in xrange(ord(key[i % len(key)])):
            y = sbox[y]
        code[x], code[y] = code[y], code[x]

    # Avoid fix-points, bad for encryption
    for x, a in enumerate(code):
        if x != a:
            continue
        y = sbox[x]
        code[x], code[y] = code[y], code[x]

    return code

def encipher(code):
    while True:
        c = sys.stdin.read(1)
        if not c:
            break
        sys.stdout.write(chr(code[ord(c)]))

def decipher(code):
    while True:
        c = sys.stdin.read(1)
        if not c:
            break
        sys.stdout.write(chr(code.index(ord(c))))

if __name__ == '__main__':
    if len(sys.argv) != 3:
        die('usage: %s <key> (enc|dec) < infile > outfile' % sys.argv[0])
    key, cmd = sys.argv[1:]
    code = init(key)
    if cmd == 'enc':
        encipher(code)
    elif cmd == 'dec':
        decipher(code)
    else:
        die('invalid command')
