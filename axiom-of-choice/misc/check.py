import sys
import os
import json

from lsys import LSystem
from PIL import Image

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print >>sys.stderr, 'usage: %s <n> <axiom>' % sys.argv[0]
        exit(1)

    n = int(sys.argv[1])
    cpath = '../app/challenges/%d.lsys' % n
    ipath = '../app/static/%d.png' % n
    axiom = sys.argv[2]

    parms = json.load(file(cpath, 'rb'))
    img1 = Image.open(ipath)
    w, h = img1.size
    w /= 4
    h /= 4
    img1 = img1.resize((w, h))

    img2 = LSystem(axiom, parms['rules'], parms['ngens']).toimg()

    # img1.save('foo.png')
    # img2.save('bar.png')
    file('foo.png', 'wb').write(img1.tobytes())
    file('bar.png', 'wb').write(img2.tobytes())



    if img1.tobytes() == img2.tobytes():
        print >>sys.stderr, 'good'
        exit(0)
    else:
        print >>sys.stderr, 'bad'
        exit(1)
