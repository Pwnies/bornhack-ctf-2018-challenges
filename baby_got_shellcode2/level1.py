import ctypes, sys
from mmap import MAP_SHARED, MAP_ANONYMOUS, PROT_READ, PROT_WRITE, PROT_EXEC

def run_shellcode(s):
    libc = ctypes.CDLL('libc.so.6')
    pages = (len(s) + 0xfff) & ~0xfff
    libc.mmap.restype = ctypes.POINTER(ctypes.c_ubyte)
    ptr = libc.mmap(0, pages, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_SHARED | MAP_ANONYMOUS, -1, 0)
    ctypes.memmove(ptr, s, len(s))
    ctypes.cast(ptr, ctypes.CFUNCTYPE(ctypes.c_int))()

def read_shellcode():
    return raw_input('Please give me shellcode (as hex):\n> ').decode('hex')

def validate_shellcode(s):
    for c in s:
        assert ord(c) != 0x0f
        assert ord(c) != 0xcd
    assert True

shellcode = read_shellcode()
print 'Validating shellcode...'
validate_shellcode(shellcode)
print 'Ok!'
print 'Running %d bytes of shellcode' % len(shellcode)
run_shellcode(shellcode)
