# -*- coding: utf-8 -*-

'''
Der Lambda-Kalkül ist eine formale Sprache zur Untersuchung von Funktionen.
Er beschreibt die Definition von Funktionen und gebundenen Parametern und
wurde in den 1930er Jahren von Alonzo Church und Stephen Cole Kleene eingeführt.
'''

# I dont speak this language...
# Maybe you do?

V = 2 # test {{V}}
N = 5 # test {{N}}
Y = lambda f: f (lambda x: Y(f)(x))
A = lambda f: lambda (a, b): a if not b else 1 + f((a, b-1))
M = lambda f: lambda (n, m): 0 if not n else Y(A)((m, f((n-1, m))))
C = lambda f: lambda v: map(lambda (a, b): a(b), zip([lambda x: x, lambda x: x >> 1, lambda x: x + V*True], [5, 8, False]))[v]
F = lambda f: lambda x: reduce(lambda a, b: Y(A)((a, b)), [Y(M)((Y(C)(0), Y(M)((x, x)))), Y(M)((Y(C)(1), x)), Y(C)(2)])

def to_str(n):
    s = '%x' % n
    s = '0' + s if len(s) % 2 != 0 else s
    return s.decode('hex')

if __name__ == '__main__':
    flag = Y(F)(N)
    print '%x -> %s' % (flag, to_str(flag))
