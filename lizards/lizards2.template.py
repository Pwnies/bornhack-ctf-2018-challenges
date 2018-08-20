#!/usr/bin/env python2
import sys

A = 50
B = 256
C = \
#FLAG#
D = 0x11b

def E(a, b):
    return a ^ b
F = E
def G(a, b):
    if a > b:
        a, b = b, a
    c = 0
    while a:
        if a & 1:
            c ^= b
        d, b, a = b >> 7, b << 1, a >> 1
        if d:
            b ^= D
    return c
def H(a):
    b = -1
    while a:
        b += 1
        a >>= 1
    return b
def I(a, b):
    if not b:
        return
    c = H(a)
    d = H(b)
    if d > c:
        return 0, a
    b <<= c - d
    e = 0
    for i in xrange(c, d - 1, -1):
        e <<= 1
        if a >> i & 1:
            e |= 1
            a = F(a, b)
        b >>= 1
    return e, a
def J(a, b):
    if a == 0:
        return (0, 1)
    else:
        c, d = I(b, a)
        e, f = J(d, a)
    return (F(f, G(c, e)), e)
def K(a):
    return J(a, D)[0]
def L(a, b):
    return reduce(E, [G(c, d) for c, d in zip(a, b)])
def M(a):
    return [L(b, a) for b in C]
def N(a):
    b = M(a)
    c = None
    for d, e in zip(a, b):
        if d == e == 0:
            continue
        if bool(d) ^ bool(e):
            return
        f = G(K(d), e)
        c = c or f
        if c != f:
            return
    return c

if __name__ == '__main__':
    a = sys.stdin.read().ljust(A * (A - 1))
    for b in range(1, A + 1):
        c = [1] + map(ord, a[(b - 1) * (A - 1) : b * (A - 1)])
        if N(c) != b:
            print 'NO!'
            exit(1)
    print 'OK!'
