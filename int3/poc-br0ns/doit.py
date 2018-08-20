from pwn import *
context(arch='amd64')

from collections import defaultdict

elf = ELF('../int3')

beg = 0x2228
end = 0x24c0
check = elf.read(beg, end - beg)
check = disasm(check, vma=beg)

class Jump(object):
    def __init__(self):
        self.src = None
        self.dst = None
        self.jif = []

    def add(src, dst, (mask, flgs)):
        self.src = src
        self.dst = dst
        self.jif.append((mask, flgs))

flow = defaultdict(list)
for src, mask, flgs, dst in group(4, unpack_many(elf.read(0x508c, 56 * 32))):
    flow[(src, dst)].append((mask, flgs))

CF = 0x001
PF = 0x008
AF = 0x010
ZF = 0x040
SF = 0x080
TF = 0x100
IF = 0x200
DF = 0x400
OF = 0x800

def flgs2jcc(flgs):
    flgs = sorted(flgs)

    if (0, 0) in flgs:
        return 'jmp'

    if flgs == [(CF, CF)]:
        return 'jb'

    if flgs == [(ZF, ZF)]:
        return 'je'

    if flgs == [(ZF, 0)]:
        return 'jne'

    if flgs == [(CF, CF),
                (ZF, ZF)]:
        return 'jbe'

    if flgs == [(SF | OF, SF),
                (SF | OF, OF)]:
        return 'jl'

    if flgs == [(ZF, ZF),
                (SF | OF, SF),
                (SF | OF, OF)]:
        return 'jle'

    raise Exception('flgs2jcc')

jmps = defaultdict(list)
dsts = set()
for (src, dst), flgs in sorted(flow.items()):
    src -= 1
    offset = dst - src
    jcc = flgs2jcc(flgs)
    jmps[src].append('%s loc_%x' % (jcc, dst))
    dsts.add(dst)

prog = [
    '.intel_syntax noprefix',
    '.text',
    '.global check',
    'check:',
    'push r12',
    'push rbp',
    'push rbx',
    'mov rbx, rdi',
    'sub rsp, 0x20',
    'call strlen',
    'xor edx, edx',
    'cmp eax, 44',
    'je loc_2228',
    'add rsp, 0x20',
    'mov eax, edx',
    'pop rbx',
    'pop rbp',
    'pop r12',
    'ret',
]

data = defaultdict(int)
for line in check.splitlines():
    m = re.match(r'\s+([0-9a-f]+):\s+(?:[0-9a-f]{2}\s)+\s*([^#]*)(?:#\s0x(.+))?', line)
    addr, code, daddr = m.groups()
    if not code:
        continue
    code = code.strip()
    addr = int(addr, 16)

    if daddr:
        daddr = int(daddr, 16)
        if 'BYTE' in code:
            numb = 1
        elif 'XMMWORD' in code:
            numb = 16
        else:
            numb = 8
        for i in xrange(numb):
            data[daddr + i] = [None, ord(elf.read(daddr + i, 1))]
        lbl = 'loc_%x' % daddr
        data[daddr][0] = lbl

        code = re.sub(r'rip\+0x[0-9a-f]+', lbl, code)

    if addr in dsts:
        prog.append('loc_%x:' % addr)

    if addr in jmps:
        prog += jmps[addr]
    else:
        prog.append(code)

prog += [
    '.data',
    '.align 16',
    'magic:',
]
for _, (lbl, byte) in sorted(data.items()):
    if lbl:
        prog.append('%s:' % lbl)
    prog.append('.byte 0x%02x' % byte)

prog = '\n'.join(prog) + '\n'
write('check.asm', prog)

write('wrapper.c', '''
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int check(char *);

int main(int argc, char *argv[0]) {
  check(argv[1]);
}
''')

os.system('as -64 -o check.o check.asm')
os.unlink('check.asm')

os.system('gcc -no-pie wrapper.c check.o -o wrapper')
os.unlink('check.o')
os.unlink('wrapper.c')

# I have no idea how this binary works, but from poking around I can see that
# the last byte of magic is xor'ed with the last byte of the flag, the second to
# last with both the last and the second to last byte of the flag, and so on.
# So we just black-box the thing.
cmd = ''
for c in [
    'b check',
    'r',
    'fin',
    'x/44bx &magic',
    'c',
    'q',
]:
    cmd += '-ex "%s" ' % c
bad_flag = 'A' * 44
output = subprocess.check_output(
    'gdb -q -nh %s --args ./wrapper %s' % (cmd, bad_flag),
    shell=True
)
# os.unlink('wrapper')

delta = []
for line in re.findall(r'0x[0-9a-f]+:.*', output):
    for b in re.findall(r'\s(0x[0-9a-f]{2})', line):
        delta.append(int(b, 16))

flag = []
for i in reversed(range(44)):
    c = ord('A') ^ delta[i]
    flag.insert(0, c)
    for j in range(i):
        delta[j] ^= delta[i]
print unordlist(flag)
