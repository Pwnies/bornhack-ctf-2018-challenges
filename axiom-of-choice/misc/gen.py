#!/usr/bin/env pypy
import string
import random
from lsys import LSystem

MIN_SIZE=50
MAX_SIZE=1000
AXIOM_ANY=True

class Timeout(Exception):
    pass

def timeout(t):
    import signal
    def handler(*_args):
        raise Timeout
    signal.signal(signal.SIGALRM, handler)
    def deco(f):
        def wrapper(*args, **kwargs):
            signal.alarm(t)
            ret = f(*args, **kwargs)
            signal.alarm(0)
            return ret
        return wrapper
    return deco

@timeout(2)
def rand(consts, musthaves, nvars, rulesmm, gensmm, amm, lmm, rmm):
    nrules = random.randint(*rulesmm)
    vars = string.lowercase[:nvars]

    def rnds(a, (min, max)):
        s = ''
        n = random.randint(min, max)
        nop = dict(['<>', '><', '+-', '-+', '/\\', '\\/', '!!'])
        l2r = dict(['()', '[]'])
        r2l = {r: l for l, r in l2r.items()}
        ns = {c: 0 for c in l2r}
        while len(s) < n:

            # Must close all parens
            if sum(ns.values()) + len(s) == n:
                t = []
                for l in l2r:
                    t.append(l2r[l] * ns[l])
                random.shuffle(t)
                s += ''.join(t)

            else:
                a_ = list(a)
                def rm(c):
                    if c in a_:
                        a_.remove(c)

                # if starting a group, need 1 char to open, sum(ns) + 1 chars to
                # close, and one extra char in between to avoid empty group
                if n - len(s) < sum(ns.values()) + 3:
                    for c in l2r:
                        rm(c)

                # don't immediately close group
                if len(s) > 0 and s[-1] in l2r:
                    rm(l2r[s[-1]])

                # don't do no-ops
                if len(s) > 0 and s[-1] in nop:
                    rm(nop[s[-1]])

                # only close a group if already open
                for l, r in l2r.items():
                    if ns[l] == 0 and r in a_:
                        rm(r)

                c = random.choice(a_)
                if c in l2r:
                    ns[c] += 1
                elif c in r2l:
                    l = r2l[c]
                    ns[l] -= 1
                s += c

                # print ''.join(a_).ljust(len(a)), len(s), s

        return s

    lhss = []
    while len(lhss) < nrules:
        lhs = rnds(vars, lmm)
        if lhs in lhss:
            continue
        lhss.append(lhs)
    # vars = ''.join(set(''.join(lhss)))
    # print vars
    # rename variables
    tr = {}
    lhss_ = []
    for lhs in lhss:
        lhs_ = ''
        for v in lhs:
            if v not in tr:
                tr[v] = string.lowercase[len(tr)]
            lhs_ += tr[v]
        lhss_.append(lhs_)
    lhss = lhss_

    vars = string.lowercase[:len(tr)]
    syms = vars + vars.upper() + consts
    rhss = [rnds(syms, rmm) for _ in xrange(nrules)]
    if musthaves:
        for rhs in rhss:
            for c in rhs:
                if c in musthaves:
                    break
            else:
                continue
            break
        else:
            return

    rules = zip(lhss, rhss)

    if AXIOM_ANY:
        axiom = rnds(syms, amm)
    else:
        axiom = rnds(vars, amm)
    ls = LSystem(axiom, rules, gensmm[0])
    for ngens in xrange(gensmm[0], gensmm[1] + 1):
        (w, h), pixels = ls.draw()

        # Some systems just fills in (a number of) borders, which is boring
        if len(pixels) < (w + h) * 2:
            # print 'too few'
            pass

        elif w < MIN_SIZE or h < MIN_SIZE:
            # print 'too small'
            pass

        elif w > MAX_SIZE or h > MAX_SIZE:
            # print 'too large'
            pass
        else:
            break

        ls.step()
    else:
        return

    return {'axiom': axiom, 'rules': rules, 'ngens': ngens}

def gen(*args):
    while True:
        try:
            parms = rand(*args)
        except Timeout:
            # print 'timeout'
            continue
        if parms:
            break
    return parms

genargs = [

    (
        '^[]!/\\',        # Constants
        '!',              # Must include
        10,               # Max. variables
        (2, 6),           # Rules
        (6, 13),          # Generations
        (3, 4),           # Axiom length
        (1, 2),           # LHS length
        (1, 5),           # RHS length
    ),

    (
        '()[]^<>!+-./\\', # Constants
        '',               # Must include
        10,               # Max. variables
        (3, 6),           # Rules
        (8, 12),          # Generations
        (3, 4),           # Axiom length
        (1, 2),           # LHS length
        (2, 5),           # RHS length
    ),

    (
        '[]^<>+/\\',      # Constants
        '',               # Must include
        5,                # Max. variables
        (3, 6),           # Rules
        (8, 12),          # Generations
        (3, 4),           # Axiom length
        (1, 2),           # LHS length
        (2, 5),           # RHS length
    ),

    (
        '^+-[]<>/\\',     # Constants
        '',               # Must include
        8,                # Max. variables
        (3, 6),           # Rules
        (8, 12),          # Generations
        (3, 4),           # Axiom length
        (1, 2),           # LHS length
        (3, 8),           # RHS length
    ),

    (
        '^[]!<>/\\.',     # Constants
        '/',              # Must include
        10,               # Max. variables
        (1, 5),           # Rules
        (7, 13),          # Generations
        (3, 4),           # Axiom length
        (1, 2),           # LHS length
        (2, 5),           # RHS length
    ),

    (
        '^()!<>/\\',      # Constants
        '',               # Must include
        10,               # Max. variables
        (1, 3),           # Rules
        (7, 13),          # Generations
        (3, 4),           # Axiom length
        (1, 2),           # LHS length
        (2, 5),           # RHS length
    ),

]

if __name__ == '__main__':
    import os
    import sys
    import json
    import tempfile

    if len(sys.argv) != 3:
        print >>sys.stderr, 'usage: %s <dir> <num>' % sys.argv[0]
        exit(1)

    dir = sys.argv[1]
    num = int(sys.argv[2])

    if not os.path.exists(dir):
        os.mkdir(dir)

    for i in xrange(num):
        args = random.choice(genargs)
        print args
        parms = gen(*args)
        print parms

        tmp = tempfile.mktemp(prefix='aoc-')
        json.dump(parms, file(tmp, 'wb'))

        n = 0
        while True:
            path = '%s/%d.lsys' % (dir, n)
            if not os.path.exists(path):
                break
            n += 1
        os.rename(tmp, path)
        print path
