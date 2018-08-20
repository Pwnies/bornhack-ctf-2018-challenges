from kalkul import *

flag = to_str(5 * N**2 + 4 * N + V)

print flag

with open('flag', 'r') as f:
    assert f.read().strip() == flag

print 'confirmed flag recoverable'
