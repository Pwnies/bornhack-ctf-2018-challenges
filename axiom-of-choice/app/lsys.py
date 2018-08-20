import string

class LSystem(object):
    def __init__(self, axiom, rules, ngens=0, limit=None):
        self.generations = [axiom]
        self.rules = rules
        self.limit = limit
        self.step(ngens)

    def step(self, ngens=1):
        for _ in xrange(ngens):
            s = self.generations[-1]
            t = ''
            i = 0
            while i < len(s):
                for lhs, rhs in self.rules:
                    if s[i : i + len(lhs)].lower() == lhs.lower():
                        t += rhs
                        i += len(lhs)
                        break
                else:
                    t += s[i]
                    i += 1
                if self.limit and len(t) > self.limit:
                    raise ValueError('Size limit exceeded')
            self.generations.append(t)
        return self

    @property
    def gen(self):
        return len(self.generations) - 1

    def __str__(self):
        return self.generations[-1]

    def __len__(self):
        return len(str(self))

    def draw(self):
        stack = []
        drawing = dict()
        palette = [
            (0xfc, 0xe9, 0x4f),
            (0xfc, 0xaf, 0x3e),
            (0xe9, 0xb9, 0x6e),
            (0x8a, 0xe2, 0x34),
            (0x72, 0x9f, 0xcf),
            (0xad, 0x7f, 0xa8),
            (0xef, 0x29, 0x29),
        ]

        pen = [False]
        col = [0]
        pos = [0, 0]
        dir = [0, 1]

        def tl():
            dir[0], dir[1] = -dir[1], dir[0]
        def tr():
            dir[0], dir[1] = dir[1], -dir[0]
        def fwd():
            pos[0], pos[1] = pos[0] + dir[0], pos[1] + dir[1]
        def nc():
            col[0] = (col[0] + 1) % len(palette)
        def pc():
            col[0] = (col[0] - 1) % len(palette)
        def pt():
            pen[0] = not pen[0]
        def pd():
            pen[0] = True
        def pu():
            pen[0] = False
        def mbpaint():
            if pen[0]:
                paint()
        def paint():
            drawing[tuple(pos)] = palette[col[0]]
        def push():
            stack.append((pen[0], col[0], pos[::], dir[::]))
        def pop():
            pen[0], col[0], (pos[0], pos[1]), (dir[0], dir[1]) = stack.pop()

        for c in self.generations[-1]:
            mbpaint()

            if c == '(':
                push()

            elif c == ')':
                pop()

            elif c == '[':
                push()
                tl()

            elif c == ']':
                pop()
                tr()

            elif c == '^':
                fwd()

            elif c == '<':
                tl()

            elif c == '>':
                tr()

            elif c == '!':
                pt()

            elif c == '+':
                pd()

            elif c == '-':
                pu()

            elif c == '/':
                nc()

            elif c == '\\':
                pc()

            elif c == '.':
                paint()

            elif c in string.uppercase:
                fwd()

        if not drawing:
            return (0, 0), {}

        minx = min(drawing)[0]
        maxx = max(drawing)[0]
        miny = min(drawing, key=lambda (_, y): y)[1]
        maxy = max(drawing, key=lambda (_, y): y)[1]

        w = maxx - minx + 1
        h = maxy - miny + 1

        return (w, h), {(x - minx, y - miny): c \
                        for (x, y), c in drawing.iteritems()}

    def toimg(self):
        # Late import because of pypy
        from PIL import Image

        (w, h), pixels = self.draw()
        if w == h == 0:
            return None

        img = Image.new('RGB', (w, h), 'white')

        for px, c in pixels.iteritems():
            img.putpixel(px, c)

        return img

# btree = LSystem(
#     '!####a',
#     ('a', 'b[a]a'),
#     ('b', 'bb'),
# )
# for i in range(10):
#     # print i
#     # print btree
#     btree.step()
# print btree
# btree.draw().save('btree.png')
