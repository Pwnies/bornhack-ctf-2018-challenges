# coding: utf-8
import urllib
import re
import sys
import os
import subprocess
import requests
from StringIO import StringIO
from PIL import Image

AXIOM_ANY=True

if AXIOM_ANY:
    os.system('gcc -DAXIOM_ANY -O9 axiom.c -o axiom')
else:
    os.system('gcc -O9 axiom.c -o axiom')

def solve(rules, ngens, idata):
    img = Image.open(StringIO(idata)).convert('RGBA')
    w, h = img.size
    w /= 4
    h /= 4
    img = img.resize((w, h))
    data = img.tobytes()

    argv = ['./axiom', str(ngens), str(w), str(h)]
    for lhs, rhs in rules:
        argv += [lhs, rhs]

    proc = subprocess.Popen(
        argv,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
    )

    o, _e = proc.communicate(data)
    return o.strip()

s = requests.Session()
URL='http://aoc.pwnies.dk:8081/'
URL='http://127.0.0.1:8081/'

axiom = None
while True:
    data = {}
    if axiom:
        data['axiom'] = axiom
    r = s.get(URL + 'challenge', data=data)
    assert r.ok
    if 'flag{' in r.text:
        print re.findall(r'flag\{[^}]+\}', r.text)[0]
        break

    ngens, = re.findall(r'at generation (\d+)', r.content)
    rules = []
    for lhs, rhs in re.findall(
            r'<tt>([^<]+)</tt>&nbsp;→&nbsp;<tt>([^<]*)</tt>', r.content):
        lhs = lhs.strip()
        rhs = rhs.replace('&gt;', '>').replace('&lt;', '<')
        rules.append((lhs, rhs))
    iurl, = re.findall(r'img src="(static/\d+.png)"', r.content)
    print iurl
    r2 = s.get(URL + iurl)
    assert r2.ok
    idata = r2.content

    axiom = solve(rules, ngens, idata)
