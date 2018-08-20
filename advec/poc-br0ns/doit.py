from pwn import *
elf = ELF('../vector')

def bits(x):
    return pwnlib.util.fiddling.bits(x, endian='little')

def unbits(x):
    return pwnlib.util.fiddling.unbits(x, endian='little')

def xor(xs, ys):
    return [x ^ y for x, y in zip(xs, ys)]

data = elf.read(elf.sym['main'], 256 + 31)

# NB: in the following our matrices are lists of columns, not rows as is more
# natural, but it makes the code neater

# This program uses a strange basis...
B = []
for i in xrange(256):
    B.append(bits(sha256sum(data[i : i + 32])))

# Use gauss-elimination to compute the transformation from E to B.  Notice that
# since we get I on the left anyways, there's no need to get the matrices into
# row-by-row representation
M = [v + [0] * i + [1] + [0] * (255 - i) for i, v in enumerate(B)]

for i in xrange(256):
    # find column with 1 at i
    for j in xrange(i, 256):
        if M[j][i]:
            break
    else:
        raise Exception('bad matrix')

    # swap them
    M[i], M[j] = M[j], M[i]

    # subtract to get 0's at i in all other columns
    for j in xrange(256):
        if i == j:
            continue
        if M[j][i]:
            M[j] = xor(M[j], M[i])

# The E->B transformation matrix is now on the right
P = [v[256:] for v in M]

start = bits(elf.read(elf.sym['start_vector'], 32))
target = bits(elf.read(elf.sym['target_vector'], 32))

# The matrix we want... in basis E
u = xor(start, target)

# Change to B
v = [0] * 256
for i, b in enumerate(u):
    if b:
        v = xor(v, P[i])

p = process('../vector')
p.sendline(unbits(v).encode('hex'))
print p.recvall()
