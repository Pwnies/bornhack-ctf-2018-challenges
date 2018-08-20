#!/usr/bin/env python2.7
import os
import json
import datetime
import random

from PIL import Image
from glob import glob
from lsys import LSystem
from flask import Flask, request, session, abort, render_template, url_for
from StringIO import StringIO
from base64 import b64encode

FLAG = open('flag').read()

POPULATION_LIMIT = 1000

CHALLENGE_DIR = 'challenges/'
CHALLENGES = 10

STATIC_DIR = 'static/'

# Configuration
HOST = 'aoc.pwnies.dk'
PORT = 8081
DEBUG = True
SECRET_KEY = '={\x80\xb7\xec\xf5\x88\x99\xb2\x8e>\xfb0\xb1\x90\xc3R\xfc8\xeb\x86\xe2-\xd4\x88\x9c\xc3\x17\x99n\xe2\xf5'
PERMANENT_SESSION_LIFETIME = datetime.timedelta(minutes=30)

app = Flask(__name__)
app.config.from_object(__name__)

@app.route('/')
@app.route('/introduction')
def introduction():
    return render_template('introduction.html')

@app.route('/playground', methods=('GET', 'POST'))
def playground():
    def render(**kwargs):
        kwargs.update(request.form)
        return render_template('playground.html', **kwargs)

    if request.method == 'GET':
        return render()
    else:
        axiom = request.form.get('axiom')
        rules = filter(
            lambda (l, r): l,
            zip(request.form.getlist('lhs'), request.form.getlist('rhs'))
        )
        ngens = int(request.form.get('ngens'))
        if not rules:
            return render(error='No rules given')

        if not all([axiom, rules, ngens]):
            abort(400)

        def split(s, n=80):
            t = ''
            while len(s) > n:
                t += s[:n] + '<br />'
                s = s[n:]
            return t + s

        ls = LSystem(axiom, rules, limit=POPULATION_LIMIT)
        gs = []
        for _ in xrange(ngens):
            try:
                ls.step()
            except ValueError:
                return render(error='Population size limit exceeded')
            img = ls.toimg()
            if img:
                w, h = img.size
                img = img.resize((w * 4, h * 4))
                s = StringIO()
                img.save(s, 'png')
                s.seek(0)
                img = b64encode(s.read())
            gen = split(str(ls))
            gs.append((gen, img))

        return render(generations=gs)

@app.route('/challenge', methods=('GET', 'POST'))
def challenge():
    def render(**kwargs):
        kwargs.update(request.form)
        return render_template('challenge.html', **kwargs)

    if 'challenges' not in session or 'axiom' not in request.form:
        cs = [os.path.splitext(os.path.basename(f))[0]
              for f in glob(CHALLENGE_DIR + '*.lsys')]
        challenges = random.sample(cs, CHALLENGES)
        session['challenges'] = challenges

    challenges = session['challenges']

    def getchal(chal):
        cpath = CHALLENGE_DIR + chal + '.lsys'
        ipath = STATIC_DIR + chal + '.png'
        parms = json.load(file(cpath, 'rb'))
        rules = parms['rules']
        ngens = parms['ngens']
        return rules, ngens, ipath

    msg = None
    axiom = request.form.get('axiom')
    if axiom:
        rules, ngens, ipath = getchal(challenges.pop(0))
        img1 = Image.open(ipath)
        w, h = img1.size
        w /= 4
        h /= 4
        img1 = img1.resize((w, h))
        img2 = LSystem(axiom, rules, ngens).toimg()
        solved = img1.tobytes() == img2.tobytes() if img2 else False

        if solved:
            msg = 'Good, keep going'
        else:
            session.pop('challenges')
            return render(error='Nope, that\'s not it.')

        session['challenges'] = challenges

    if challenges == []:
        return render(flag=FLAG)

    rules, ngens, ipath = getchal(challenges[0])
    ljust = max(len(lhs) for lhs, rhs in rules)
    rules = [(lhs.ljust(ljust), rhs) for lhs, rhs in rules]

    return render(rules=rules, ngens=ngens, img=ipath, msg=msg)

if __name__ == '__main__':
    app.run(host=HOST,
            port=PORT,
            threaded=True,
    )
