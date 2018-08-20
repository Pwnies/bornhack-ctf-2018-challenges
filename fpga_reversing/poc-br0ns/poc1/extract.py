from pwn import *

bs = ''
for l in read('bits').splitlines():
    # SCLK rising edge
    if l[0] == '1':
        bs += l[1]

print unbits(bs, endian='little')[::-1].strip('\0')
