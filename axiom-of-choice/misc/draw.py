#!/usr/bin/env python2
from lsys import LSystem

def draw(path, parms, scale=None):
    img = LSystem(**parms).toimg()
    if scale:
        w, h = img.size
        img = img.resize((w * scale, h * scale))
    img.save(path)

if __name__ == '__main__':
    import os
    import sys
    import glob
    import json

    if len(sys.argv) not in (3, 4):
        print >>sys.stderr, 'usage: %s <indir> <outdir> [<scale>]' % sys.argv[0]
        exit(1)
    idir = sys.argv[1]
    odir = sys.argv[2]
    try:
        scale = int(sys.argv[3])
    except:
        scale = None
    for ipath in glob.glob('%s/*.lsys' % idir):
        n = os.path.basename(os.path.splitext(ipath)[0])
        opath = os.path.join(odir, n) + '.png'
        if os.path.exists(opath):
            continue
        print ipath, '->', opath
        parms = json.load(file(ipath, 'rb'))
        draw(opath, parms, scale)
