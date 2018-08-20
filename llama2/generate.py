collatz = {0: 0, 1:0}

def collatz_length(n):
    global collatz
    if n in collatz:
        return collatz[n]
    else:
        i = collatz_length(3*n + 1 if n & 1 else n >> 1) + 1
        collatz[n] = i
        return i

d = {}

for i in range(2**20):
    n = collatz_length(i)
    if n < 256 and n not in d: d[n] = i

with open("flag", "r") as flag:
    flag = flag.read().strip()

with open("template.py", "r") as template:
    template = template.read()

print template.replace("d = []", "d = %r" % ([d[ord(c)] for c in flag], ))

    
