import gmpy2

# embed the flag in a polynomial

with open('./flag', 'r') as f:
    flag = int(f.read().strip().encode('hex'), 16)

# poly is: 5 * x^2 + 4 * x + C

def poly(n):
    return 5 * n**2 + 4 * n

N = gmpy2.isqrt(5 * flag) / 5
V = flag - poly(N)

print 'V:', hex(V)
print 'N:', hex(N)

assert poly(N) + V == flag

with open('template.py', 'r') as f:
    templ = f.read()

templ = templ.replace('V = 2 # test {{V}}', 'V = 0x%x' % V)
templ = templ.replace('N = 5 # test {{N}}', 'N = 0x%x' % N)

with open('kalkul.py', 'w') as f:
    f.write(templ)
