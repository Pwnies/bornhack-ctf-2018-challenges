import re
import sys
import os
import atexit

# icestorm can give us a "nice" verilog program from the bitstream
# http://www.clifford.at/icestorm/
if not os.path.exists('chip.v'):
    os.system('iceunpack ../../challenge.bin chip.asc')
    os.system('icebox_vlog -ls chip.asc > chip.v')

# the following is much faster with pypy
if 'pypy' not in sys.executable and 0 == os.system('which pypy > /dev/null'):
    os.execvp('pypy', ['pypy'] + sys.argv)

# read and un-tokenize the chip output by icestorm
def T(s):
    # eat comments
    s = re.sub(r'/\*.*?\*/', '', s)
    # add spaces for tokenization
    for c in ',;=?!:@()':
        s = s.replace(c, ' ' + c + ' ')
    # normalize spacing
    s = re.sub(r'\s+', ' ', s)
    # recover '<='
    s = s.replace('< =', '<=')
    return s.split()

chip = file('chip.v').read()
tokens = T(chip)

# write the transformed program back to disk on exit
atexit.register(lambda: file('chip1.v', 'w').write(
    ' '.join(tokens).replace(';', ';\n')
))

# find patterns in the token list
X = object() # bind token
Q = object() # wildcard (quiz: why did I choose Q?)
def match(*pattern, **kwargs):
    i = kwargs.get('start', 0)
    while i <= len(tokens) - len(pattern):
        out = [i]
        for tok, pat in zip(tokens[i : i + len(pattern)], pattern):
            if not isinstance(pat, (tuple, list)):
                pat = (pat,)
            pat = tuple(pat)
            if pat not in ((X,), (Q,)) and tok not in pat:
                break
            if X in pat:
                out.append(tok)
        else:
            if len(out) == 1:
                out = out[0]
            yield out
        i += 1

# some utility functions
def insert(pos, *what):
    tokens[pos:pos] = list(what)

def remove(pos, num):
    toks = tokens[pos:pos + num]
    tokens[pos:pos + num] = []
    return toks

def change(pos, num, *what):
    toks = remove(pos, num)
    insert(pos, *what)
    return toks

def remove_decl(var):
    for pos, what, in match((X, 'reg', 'wire'), var):
        if what == 'reg':
            num = 5
        else:
            num = 3;
        remove(pos, num)

# rewrite to singleton defs
for pos in match('wire', Q, ','):
    change(pos + 2, 1, ';', 'wire')

for pos in match('reg', Q, '=', Q, ','):
    change(pos + 4, 1, ';', 'reg')

# collect constants
vals = {}
for _, reg, val in match('reg', X, '=', X, ';'):
    vals[reg] = val

# remove aliases and inline constants
def rename(old, new):
    for i, t in enumerate(tokens):
        if t == old:
            tokens[i] = new

while True: # fixed-point iteration
    again = False
    for pos, lhs, rhs in match('assign', X, '=', X, ';'):
        remove(pos, 5)
        remove_decl(lhs)
        rename(lhs, rhs)
        again = True
    if not again:
        break

# remove if's with constant conditions
for pos, cond in match('if', '(', (X, "1'b1", "1'b0"), ')'):
    if cond[-1] == '1':
        remove(pos, 4)
    else:
        # go back to 'always @ ...'
        pos -= 6
        end = match(';', start=pos).next()
        remove(pos, end - pos + 1)

# renumber vars
# input pin_E16 goes to n31
# output (renamed to) n313 comes from n219 or n227
rename('n313', 'pin_out')
rename('pin_E16', 'pin_in')
rename('n219', 'x000')
rename('n227', 'y000')

# a pattern emerges: if pin_D16 is low a lot of regs is set to the value of some
# other reg, so lets number them sensibly
while True:
    again = False
    for _, lhs, rhs in match(X, '<=', 'pin_D16', '?', ("1'b0", "1'b1"), ':', X):
        if lhs[0] in 'xy' and rhs[0] not in 'xy':
            n = int(lhs[1:])
            rhs2 = lhs[0] + '%03d' % (n + 1)
            rename(rhs, rhs2)
            again = True
    if not again:
        break

# looks like a shift register... lets sort those statements
stmts = []
insertat = None
pos = 0
while pos < len(tokens):
    tok = tokens[pos]
    if tok == 'always':
        if insertat is None:
            insertat = pos
        end = match(';', start=pos).next()
        stmts.append(remove(pos, end - pos + 1))
    else:
        pos += 1
for stmt in sorted(stmts):
    insert(insertat, *stmt)

# pin_in was renamed through this, so we fix it
rename('y032', 'pin_in')

# now it's easy to see that there are two shift registers: X = {x0-254,y31} and
# Y = {y0-31}.  notice that both share the first bit which is fed from pin_in if
# pin_D16 is low
#
# The output is latched from either x0 or y0 depending on n223 which depends on
# n502 which is set to the result of some magic circuitry involving Y
#
# What we also see is that Y are initialized to 0 but X is initialized to some
# non-0 value.  let's investigate

bits = ''
for _, var, val in match(X, '<=', 'pin_D16', '?', X):
    if var[0] == 'x' or var == 'y031':
        bits += val[-1]

out = ''
for i in xrange(0, len(bits), 8):
    out += chr(int(bits[i : i + 8], 2))
print out
