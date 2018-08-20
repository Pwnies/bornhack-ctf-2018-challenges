import lizards

add = lizards.F
mul = lizards.G
dotproduct = lizards.H
apply_matrix = lizards.I
inv = lizards.E

def apply_matrix2(m, v):
    return [dotproduct(b, v) for b in m]

def scale_vector(r, v):
    return [mul(r, a) for a in v]

def scale_matrix(r, m):
    return [scale_vector(r, v) for v in m]

def add_vector(v1, v2):
    assert len(v1) == len(v2)
    return [add(a,b) for a,b in zip(v1, v2)]

def sub_vector(v1, v2):
    return add_vector(v1, scale_vector(-1, v2))

def add_matrix(m1, m2):
    assert len(m1) == len(m2) and len(m1) > 0
    assert all(len(v1) == len(m1[0]) for v1 in m1)
    assert all(len(v1) == len(v2) for v1, v2 in zip(m1, m2))
    return [add_vector(v1, v2) for v1, v2 in zip(m1, m2)]

def sub_matrix(m1, m2):
    return add_matrix(m1, scale_matrix(-1, m2))

def gauss_elim(m):
    m = map(list, m)
    for i in range(len(m)):
        for j in range(i, len(m)):
            if m[i][j]:
                m[i], m[j] = m[j], m[i]
                break
        else:
            continue
        
        m[i] = scale_vector(inv(m[i][i]), m[i])

        for j in range(len(m)):
            if i == j: continue
            if m[j][i]:
                m[j] = sub_vector(m[j], scale_vector(m[j][i], m[i]))

    return m

def identity(scale=1, n=len(lizards.C)):
    return [[int(i == j)*scale for i in range(n)] for j in range(n)]

def print_matrix(m):
    for xs in m:
        for x in xs:
            print str(x).rjust(3, "0"),
        print

import sys
for n in range(1, 50+1):
    m = gauss_elim(sub_matrix(lizards.C, identity(n)))
    v = map(lambda v: v[49], m)
    v = scale_vector(inv(v[0]), v)
    s = "".join(map(chr, v[1:]))
    sys.stdout.write(s)
    sys.stdout.flush()
