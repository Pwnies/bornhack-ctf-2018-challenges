from template import *

assert Y(A)((3, 3))  == 6
assert Y(A)((10, 7)) == 17

assert Y(M)((2, 3))  == 6
assert Y(M)((10, 7)) == 70

# poly is: 5 * x^2 + 4 * x + 2

def poly(n):
    return 5 * n**2 + 4 * n + 2

xs = list(range(12))
vx = map(poly, xs)
vy = map(Y(F), xs)

assert vx == vy
