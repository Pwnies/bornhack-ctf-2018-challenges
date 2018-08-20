#!/usr/bin/env python2
from lsys import LSystem

bt = LSystem(
    '////+a^',
    [['a', '^B[^A]^A'],
     ['b', 'BB'],
    ]
)

for i in xrange(1, 7):
    bt.step()
    print i, bt
    img = bt.toimg()
    if img:
        w, h = img.size
        img = img.resize((w * 4, h * 4))
        img.save('../app/static/example-%d.png' % i)
