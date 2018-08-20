from elftools.elf.elffile import ELFFile
import hashlib
import os
import struct
import Crypto.Cipher.ARC4 as rc4
import sys

BITS = 256
if len(sys.argv) != 2:
    print "%s <file to fixup>" % sys.argv[0]

FILENAME = sys.argv[1]

def sha256(data): return hashlib.sha256(data).digest()

def p32(v): return struct.pack("<L", v)

def to_bits(vec): return [int((vec >> i) & 1) for i in range(BITS)]

def to_int(vec): return int(vec[::-1].encode("hex"), 16)

def from_bits(bits): return sum(b*(2**n) for (b,n) in zip(bits, range(256)))

def from_int(i): return hex(i)[2:].strip("L").rjust(64, "0").decode("hex")[::-1]

for i in range(100):
    data = os.urandom(BITS/8)
    assert from_int(to_int(data)) == data
    assert from_int(from_bits(to_bits(to_int(data)))) == data

def dump_matrix(mat):
    print "\n".join("".join(str(e) for e in v) for v in mat)

def gauss_elim(mat, n=BITS):
    mat = map(list, mat)
    for i in range(n):
        for j in range(i, n):
            if mat[j][i]:
                mat[i], mat[j] = mat[j], mat[i]
                break
        else:
            raise ValueError("non invertible matrix")

        for j in range(n):
            if mat[j][i] and i != j:
                mat[j] = [x^y for (x,y) in zip(mat[j], mat[i])]

    return mat

def concat(mat1, mat2): return [x+y for (x,y) in zip(mat1, mat2)]

def identity(n=BITS): return [[int(i==j) for j in range(n)] for i in range(n)]

def zero(n=BITS): return [[0 for j in range(n)] for i in range(n)]

def invert(mat, n=BITS):
    return [row[n:] for row in gauss_elim(concat(mat, identity(n)))]

def mult(mat1, mat2, n=BITS):
    mul = zero(n)
    for i in range(n):
        for j in range(n):
            mul[i][j] = sum(mat1[i][t]*mat2[t][j] for t in range(n)) & 1
    return mul

e = ELFFile(open(FILENAME, "r"))
symtab = e.get_section_by_name(".symtab")

def lookup_symbol(name):
    sym = symtab.get_symbol_by_name(name)[0]
    print sym.entry
    sec = e.get_section(sym["st_shndx"])
    print sec.header
    sym_file_offset = sym["st_value"] - sec["sh_addr"] + sec["sh_offset"]
    return sym_file_offset, sym["st_size"]


with open(FILENAME, "rb+") as f:
    main_off, main_size = lookup_symbol("main")

    f.seek(main_off)
    main_data = f.read(main_size)

    hash_data_length = main_size - 256 

    hash_data_length_off, _ = lookup_symbol("hash_data_length")
    f.seek(hash_data_length_off)
    f.write(struct.pack("L", hash_data_length))

    for i in range(20):
        print i
        data = main_data.replace("AAAA", p32(i))

        basis = [sha256(data[i:hash_data_length+i])[:BITS/8] for i in range(BITS)]

        assert len(set(basis)) == BITS

        mat = map(to_bits, map(to_int, basis))
        try:
            inv = invert(mat)
            break
        except ValueError:
            continue

#    assert mult(mat, inv) == identity()
    
    for i, vec in enumerate(basis):
        print "basis[%d]: %s" % (i, vec.encode("hex"))

    f.seek(main_off)
    f.write(data)

    start_vector = to_int("A"*32)
    input_vector = to_int("A11 y0ur b@s3 @r3 b310ng t0 us!!")

    target_vector = start_vector
    hash_data = ""
    for idx, bit in enumerate(to_bits(input_vector)):
        if bit:
            target_vector ^= to_int(basis[idx])
            hash_data += basis[idx]

    start_vector_off, _ = lookup_symbol("start_vector")
    f.seek(start_vector_off)
    f.write(from_int(start_vector))

    target_vector_off, _ = lookup_symbol("target_vector")
    f.seek(target_vector_off)
    f.write(from_int(target_vector))
    
    
    crypto = rc4.new(sha256(hash_data))
    flag_data = crypto.encrypt("flag{I don't always use linalg, but when i do my basis is sha256 of main}\n\x00")

    flag_data_off, _ = lookup_symbol("flag_data")
    f.seek(flag_data_off)
    f.write(flag_data)
