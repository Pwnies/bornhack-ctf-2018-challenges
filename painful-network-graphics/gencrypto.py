import os
import sys
import random
import math

min_len = 2
max_len = 4
# Reproducible builds, please
SEED = 0

random.seed(SEED)

def gensbox():
    def genlengths():
        lengths = []
        while True:
            left = 0x100 - sum(lengths)
            if left == 0:
                return lengths
            if left < min_len:
                return None
            lengths.append(random.randint(min_len, min(max_len, left)))
    while True:
        lengths = genlengths()
        if lengths:
            break

    S = range(0x100)
    sbox = [0] * 0x100
    for l in lengths:
        cycle = random.sample(S, l)
        cycle.append(cycle[0])
        for i in xrange(l):
            x = cycle[i]
            y = cycle[i + 1]
            S.remove(x)
            sbox[x] = y
    return sbox

def showcycles(perm):
    # Print cycles
    seen = set()
    for i in xrange(0x100):
        if i in seen:
            continue
        x = i
        print '(',
        while True:
            print x,
            seen.add(x)
            x = perm[x]
            if x == i:
                break
        print ')'

sbox = gensbox()
ITEMS_PER_LINE = 8
text = 'sbox = [\n'
for i in range(0, 0x100, ITEMS_PER_LINE):
    text +=  '    %s,\n' % ', '.join(
        '0x%02x' % x for x in sbox[i : i + ITEMS_PER_LINE])
text += ']'

print >>sys.stderr, text

crypto = file('crypto.template.py').read()
crypto = crypto.replace('#SBOX#', text)
file('crypto.py', 'w').write(crypto)
os.chmod('crypto.py', 0755)
