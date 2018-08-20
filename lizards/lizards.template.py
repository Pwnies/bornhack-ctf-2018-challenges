#!/usr/bin/env python2
import sys

A = 50
B = 257
C = \
#FLAG#
def D(a, b=B):
    if a:
        c, d = D(b % a, a)
        return (d - (b // a) * c, c)
    return (0, 1)
def E(a):
    b, _ = D(a)
    return b % B
def F(a, b):
    return (a + b) % B
def G(a, b):
    return (a * b) % B
def H(a, b):
    return reduce(F, [G(c, d) for c, d in zip(a, b)])
def I(a):
    return [H(b, a) for b in C]
def J(a):
    b = I(a)
    c = None
    for d, e in zip(a, b):
        if d == e == 0:
            continue
        if bool(d) ^ bool(e):
            return
        f = G(E(d), e)
        c = c or f
        if c != f:
            return
    return c

if __name__ == '__main__':
    a = sys.stdin.read().ljust(A * (A - 1))
    for b in range(1, A + 1):
        c = [1] + map(ord, a[(b - 1) * (A - 1) : b * (A - 1)])
        if J(c) != b:
            print 'NO!'
            exit(1)
    print 'OK!'
