#!/usr/bin/python2.7 -u
import struct

KEY_SIZE = 16
DATA_SIZE = 8
ROUNDS = 32

def p32(n): return struct.pack(">L", n)
def u32(d): return struct.unpack(">L", d)[0]
def p64(n): return struct.pack(">Q", n)
def u64(d): return struct.unpack(">Q", d)[0]

def group(n, data):
    while data:
        yield data[:n]
        data = data[n:]

def xor(xs, ys): return "".join(chr(ord(x)^ord(y)) for x,y in zip(xs, ys))

def DaviesMeyer(E):
    def hash_func(data):
        data_len = len(data)
        data += "\x00" * (KEY_SIZE - (data_len % KEY_SIZE))
        data += ("\xff" * (KEY_SIZE - 8)) + p64(data_len)

        assert len(data) % KEY_SIZE == 0

        state = "\x00"*DATA_SIZE
        for chunk in group(KEY_SIZE, data):
            state = xor(state, E(chunk, state))

        return state

    return hash_func

def TEA(key, data):
    assert len(key) == KEY_SIZE
    assert len(data) == DATA_SIZE

    def f(i, ka, kb, s):
        return (((i << 4) + ka) ^ (i + s) ^ ((i >> 5) + kb)) & 0xffffffff
    
    k0, k1, k2, k3 = map(u32, group(4, key))
    l, r = map(u32, group(4, data))

    delta = 0x9e3779b9
    s = 0
    
    for _ in range(ROUNDS):
        s = (s + delta) & 0xffffffff
        l = (l + f(r, k0, k1, s)) & 0xffffffff
        r = (r + f(l, k2, k3, s)) & 0xffffffff
    
    return p32(l) + p32(r)

HASH = DaviesMeyer(TEA)

if __name__ == "__main__":
    print "Give collision, pl0x"

    data1 = raw_input("Data1> ").decode("hex")
    data2 = raw_input("Data2> ").decode("hex")

    assert data1 != data2
    assert HASH(data1) == HASH(data2)

    with open("flag", "r") as flag:
        print flag.read().strip()
