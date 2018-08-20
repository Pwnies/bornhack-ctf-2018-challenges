from pwn import *
import random
context(endian="big")

ha = random.randint(0, 2**32 - 1)
la = random.randint(0, 2**32 - 1)
hb = ha ^ 0x80000000
lb = la ^ 0x80000000

data1 = (p32(ha) + p32(la)).encode("hex")
data2 = (p32(hb) + p32(lb)).encode("hex")

r = process("./securehash.py")
r.recvuntil("Data1>")
r.sendline(data1)
r.recvuntil("Data2>")
r.sendline(data2)
print r.recvall().strip()

