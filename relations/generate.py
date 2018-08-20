import random
import numpy as np

with open('./flag', 'r') as f:
    flag = map(ord, f.read().strip())

print 'import sys'
print
print 'a = map(ord, sys.argv[1])'
print 's = 0'
print

for _ in range(len(flag) * 16):
    indecies = np.random.choice(len(flag), size=10, replace=False)
    vs       = [np.random.choice(0x100) for _ in range(8)]
    values   = vs + map(lambda v: flag[v], indecies)
    res      = reduce(lambda x, y: x ^ y, values)

    terms    = []
    terms    += ['a[0x%02x]' % i for i in indecies]
    terms    += ['0x%02x' % v for v in vs]
    terms    += ['0x%02x' % res]

    random.shuffle(terms)

    print 's += %s' % ' ^ '.join(terms)

print
print 'if s == 0:'
print '    print "correct flag"'
