'''This script simultaneously acts as a playground, test bed, flag generation
and a solution to the challenge.  A bit messy, I know.

'''
import itertools
import random
import math
import struct
import sys

# deterministic build
random.seed(0)

flag = ''
with open('flag', 'r') as f:
    flag = ' ' + f.read().strip() + ' '

N = 50

class NoInverse(Exception):
    pass

# Consider matrices over GF(P), P prime or GF(2^n), whatever makes the better
# challenge...
modP = True

if modP:
    # Z/Zp
    P = 257

    fmt = '%%%dd' % (math.log10(P) + 1)
    def scalar2str(x):
        return fmt % x

    def egcd(a, b):
        if a == 0:
            return (b, 0, 1)
        else:
            g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

    def scalar_add(x, y):
        return (x + y) % P

    def scalar_sub(x, y):
        return (x - y) % P

    def scalar_mul(x, y):
        return (x * y) % P

    def scalar_inv(x):
        g, y, _ = egcd(x, P)
        if g != 1:
            raise NoInverse
        return y % P

else:
    # GF(2^8)
    P = 2**8 # bad naming, so sue me
    R = 0x11b

    def scalar2str(x):
        return bin(x)[2:].rjust(8, '0')

    def scalar2str(x):
        return '0x%02x' % x

    def scalar_add(x, y):
        return x ^ y
    scalar_sub = scalar_add

    def scalar_mul(x, y):
        if x > y:
            x, y = y, x
        z = 0
        while x:
            if x & 1:
                z ^= y
            c, y, x = y >> 7, y << 1, x >> 1
            if c:
                y ^= R
        return z

    def deg(x):
        d = -1
        while x:
            d += 1
            x >>= 1
        return d

    def scalar_divmod(x, y):
        if not y:
            return
        dx = deg(x)
        dy = deg(y)
        if dy > dx:
            return 0, x
        y <<= dx - dy
        q = 0
        for i in xrange(dx, dy - 1, -1):
            # Multiply by X
            q <<= 1
            if x >> i & 1:
                # Coefficient of X^i is non-zero
                q |= 1
                x = scalar_sub(x, y)
            # Divide by X
            y >>= 1
        return q, x

    def egcd(a, b):
        if a == 0:
            return (0, 1)
        else:
            q, r = scalar_divmod(b, a)
            y, x = egcd(r, a)
        return (scalar_sub(x, scalar_mul(q, y)), y)

    def scalar_inv(x):
        return egcd(x, R)[0]

    # Just some testing code
    def scalar_test():
        a = random.randrange(0, 0x100)
        b = random.randrange(0, 0x100)
        c = scalar_mul(a, b)
        print 'a = %s, b = %s, a*b = c = %s' % (scalar2str(a), scalar2str(b), scalar2str(c))
        print 'deg(a) = %d, deg(b) = %d, deg(c) = %d' % (deg(a), deg(b), deg(c))
        # print 'c/a = %d, c/b = %d' % (scaler_div(c, a), scaler_div(c, b))
        q, r = scalar_divmod(c, a)
        print 'c//a = q = %s, c%%a = r = %s' % (scalar2str(q), scalar2str(r))
        print 'deg(c) = %d, deg(q) = %d, deg(r) = %d' % (deg(c), deg(q), deg(r))
        print 'q * a + r = %s' % scalar2str(scalar_add(scalar_mul(q, a), r))

        ainv = scalar_inv(a)
        binv = scalar_inv(b)
        print 'a^-1 = %s, b^-1 = %s' % (scalar2str(ainv), scalar2str(binv))
        a_ = scalar_mul(c, binv)
        b_ = scalar_mul(c, ainv)
        print 'c*a^-1 = %s, c*b^-1 = %s' % (scalar2str(a_), scalar2str(b_))
        assert a == a_
        assert b == b_

# Derived
def scalar_div(x, y):
    return scalar_mul(x, scalar_inv(y))

def scalar_neg(x):
    return scalar_sub(0, x)

# LinAlg

def vector_scale(a, v):
    return [scalar_mul(a, x) for x in v]

def vector_add(u, v):
    return [scalar_add(x, y) for x, y in zip(u, v)]

def vector_sub(u, v):
    return [scalar_sub(x, y) for x, y in zip(u, v)]

def vector_neg(v):
    return map(scalar_neg, v)

def dot_product(u, v):
    return reduce(scalar_add, [scalar_mul(x, y) for x, y in zip(u, v)])

def matrix_sub(A, B):
    return [vector_sub(u, v) for u, v in zip(A, B)]

def matrix_scale(a, A):
    return [vector_scale(a, v) for v in A]

def matrix_apply(A, v):
    return [dot_product(u, v) for u in A]

def column(A, i):
    return [v[i] for v in A]

def I(size=N, scale=1):
    I = []
    for i in xrange(size):
        I.append([0] * i + [scale] + [0] * (size - i - 1))
    return I

def gauss_elim(A):
    '''Gauss-elimination'''
    d = len(A)

    for i in range(d):
        # Find first row with not 0 at index i
        for j in xrange(i, d):
            if A[j][i]:
                break
        else:
            continue

        # Swap rows
        A[i], A[j] = A[j], A[i]

        # Get a leading 1
        A[i] = vector_scale(scalar_inv(A[i][i]), A[i])

        # Get all zeros at index i in all other rows
        for j in range(d):
            if i == j:
                continue
            if A[j][i]:
                A[j] = vector_sub(A[j], vector_scale(A[j][i], A[i]))

    return A

def matrix_inv(A):
    M = [u + v for u, v in zip(A, I())]
    M = gauss_elim(M)
    return [v[N:] for v in M]

def solve(A, b):
    '''Solves Av = b for v'''
    n = len(A[0]) # number of vars
    M = [v + [x] for v, x in zip(A, b)]
    M = gauss_elim(M)

    # If system was overdetermined we must have last rows = <0>
    for v in M[n:]:
        if any(v):
            raise Exception('unsolvable')
    return [v[-1] for v in M[:n]]

def matrix_mul(A, B):
    C = []
    for u in A:
        w = []
        for i in xrange(N):
            v = column(B, i)
            w.append(dot_product(u, v))
        C.append(w)
    return C

def eigenvalue(A, v):
    u = matrix_apply(A, v)
    # Av = u =? a * v
    # => a = v^-1 * u
    a = None
    for x, y in zip(v, u):
        if x == y == 0:
            continue
        if bool(x) ^ bool(y):
            return
        a_ = scalar_mul(scalar_inv(x), y)
        a = a or a_
        if a != a_:
            return
    return a

def vector2str(v):
    return '[%s]' % ', '.join(map(scalar2str, v))

def matrix2str(A):
    return '[%s]' % ',\n '.join(vector2str(v) for v in A)

# these were used for testing at one point
def random_vector():
    return [random.randrange(0, P) for _ in xrange(N)]

def random_matrix():
    return [random_vector() for _ in xrange(N)]


# Flag generation below

# For testing:
# flag = 'X'
# N = 3

def from_eigens(es):
    D = I()
    P = I()
    for i in xrange(N):
        D[i][i] = es[i][0]
        for j in xrange(N):
            P[i][j] = es[j][1][i]
    Pinv = matrix_inv(P)
    A = matrix_mul(matrix_mul(P, D), Pinv)
    return A

def randoms(n):
    alph = '<>'
    return ''.join(random.choice(alph) for _ in xrange(n))

text = ''
for i in xrange(N - 1):
    if i == (N - 1) // 2:
        pad = N - 1 - len(flag)
        line = randoms(pad // 2) + flag + randoms((pad + 1) // 2) + '\n'
    else:
        line = randoms(N - 1) + '\n'
    assert len(line) == N
    text += line
assert len(text) == N * (N - 1)
flag = text

print 'generating eigenvectors'
es = []
for i in range(1, N + 1):
    v = [1] + map(ord, flag[(i - 1) * (N - 1) : i * (N - 1)])
    es.append((i, v))

print 'generating matrix A from eigenvectors'
A = from_eigens(es)
enc_flag = matrix2str(A)

if modP:
    lizards = file('lizards.template.py').read()
else:
    lizards = file('lizards2.template.py').read()
lizards = lizards.replace('#FLAG#', enc_flag)
file('lizards.py', 'w').write(lizards)

# flag is generated, no need for all that testing below
# exit()

# verify
print 'verifying that eigenthings are indeed eigenthings of A...',
n = 0
for a, v in es:
    print v
    assert a == eigenvalue(A, v)
print 'OK!'

# Solution below
print 'solving challenge'
def eigenvector(A, a):
    # If we solve Av = av <=> (A - aI)v = <0> we just get v = <0>, so that's no
    # good.  But we know that v1 = 1 (from the challenge).  Let M = (A - aI),
    # then we solve:
    #
    #   Mv = 0                   <=>
    #   col(M, 0) + M'v' = 0     <=>
    #   M'v' = -col(M, 0)
    #
    # where v' = <v1 ... v50>
    #            /M1,2 ... M2,50\
    #            | .   .        |
    #       M' = | .    .       |  (i.e. column 1 is missing)
    #            | .     .      |
    #            \Mn,2     Mn,50/

    # M = matrix_sub(A, I(scale=a))
    # M_ = [v[1:] for v in M]
    # v_ = solve(M_, vector_neg(column(M, 0)))
    # v = [1] + v_
    # return v

    # Update: I finally grogged it; see below.

    # This is still a bit of a mystery to me, but can't argue with root^Wflag.
    #
    # Kokjo's PoC (which admittedly doesn't find v50, but its close enough)
    # solves this system:
    #
    #  M'v' = col(M, 50)
    #
    # where v' = <v1 ... v49>
    #            /M1,1 ... M2,49\
    #            | .   .        |
    #       M' = | .    .       |  (i.e. column 50 is missing)
    #            | .     .      |
    #            \Mn,1     Mn,49/
    #
    # Then he computes v'' = v'1^-1 * v', and it's close to correct.  Weird
    # thing is it works for every i != 1, not just 50.

    # M = matrix_sub(A, I(scale=a))
    # def f(i):
    #     M_ = [v[:i] + v[i+1:] for v in M]
    #     v_ = solve(M_, column(M, i))
    #     v_ = v_[:i] + [-1] + v_[i:]
    #     return vector_scale(scalar_inv(v_[0]), v_)
    # v_ = f(48)
    # print vector2str(v_)
    # exit()

    # OK, here's whats going on.  Let's generalize the above:
    #
    #  M'v' = col(M, i)
    #
    # where v' = <v1 ... vi, v{i+1} ... v50>
    #            /M1,1 ... M1,i M1_{i+1} ... M2,49\
    #            | .         .                    |
    #       M' = | .            .                 |
    #            | .               .              |
    #            \Mn,1 ... Mn_i Mn_{i+1} ... Mn,49/
    #       (i.e. column/index `i` is missing)
    #       v'' = <v1 ... vi, -1, v{i+1} ... v50>
    #
    # Solving the system above is equivalent to finding the eigenvector with -1
    # at inde `i`.  Since the eigenvectors has no zero's such a vector surely
    # exists because any eigenvector can be scaled arbitrarily.
    #
    # But the eigenvector required by the challenge has a leading 1, which is
    # why Kokjo scales by v1^-1.  Where he fails is that he forgets to include
    # the implicit -1, e.g. he uses v' where he should be using v''.  As an
    # added bonus this now also works for `i = 1`.  Here is a fixed solution:

    M = matrix_sub(A, I(scale=a))
    def f(i):
        M_ = [v[:i] + v[i+1:] for v in M]
        v_ = solve(M_, column(M, i))
        v__ = v_[:i] + [-1 % P] + v_[i:]
        v = vector_scale(scalar_inv(v__[0]), v__)
        return v
    v1 = f(random.randrange(0, N))
    v2 = f(random.randrange(0, N))
    assert v1 == v2
    return v1

for i in xrange(1, N + 1):
    v = eigenvector(A, i)
    # print vector2str()
    sys.stdout.write(''.join(map(chr, v[1:])))

# Test every vector, just to be sure.  Only works for very small N, naturally
#print 'bruteforcing all possible eigenvectors'
#def eigens(A):
#    for v in itertools.product(range(P), repeat=N - 1):
#        v = [1] + list(v)
#        a = eigenvalue(A, v)
#        if a:
#            yield (a, v)
#
#for a, v in eigens(A):
#    print 'v = %s, Av = %dv' % (vector2str(v), a)
