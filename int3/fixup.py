import re
import sys

CF = 1 << 0
PF = 1 << 2
AF = 1 << 4
ZF = 1 << 6
SF = 1 << 7
OF = 1 << 11

unique_counter = 0
def unique(label):
    global unique_counter
    unique_counter = unique_counter + 1
    return ".%s_%d" % (label, unique_counter)

def fixup_jump(match, mvs):
    print >> sys.stderr, match.group(0)
    label = unique("fixup")
    for (mask, value) in mvs:
        print ".pushsection \".data.jmps\""
        print ".quad %s" % label
        print ".quad 0x%x" % mask
        print ".quad 0x%x" % value
        print ".quad %s" % match.group(1)
        print ".popsection" 
    print "int3"
    print label + ":" 

fixups = [
    (re.compile(r"\s*je\s+(.*)$"), lambda m: fixup_jump(m, [(ZF, ZF)])),
    (re.compile(r"\s*jne\s+(.*)$"), lambda m: fixup_jump(m, [(ZF, 0)])),
    (re.compile(r"\s*jl\s+(.*)$"), lambda m: fixup_jump(m, [(SF+OF, SF), (SF+OF, OF)])),
    (re.compile(r"\s*jle\s+(.*)$"), lambda m: fixup_jump(m, [(ZF, ZF), (SF+OF, SF), (SF+OF, OF)])),
    (re.compile(r"\s*jg\s+(.*)$"), lambda m: fixup_jump(m, [(SF+OF, SF+OF), (SF+OF, 0)])),
    (re.compile(r"\s*jbe\s+(.*)$"), lambda m: fixup_jump(m, [(CF, CF), (ZF, ZF)])),
    (re.compile(r"\s*jmp\s+(.*)$"), lambda m: fixup_jump(m, [(0, 0)]))
]

if len(sys.argv) != 2:
    print "%s <assembly.s>" % sys.argv[0]
    exit(0)

print ".section .data.jmps"
print ".globl JUMP_TABLE"
print "JUMP_TABLE:"

for line in open(sys.argv[1], "r"):
    line = line.rstrip()
    for fixup in fixups:
        m = fixup[0].match(line)
        if m:
            fixup[1](m)
            break
    else:
        pass
        print line

print ".section .rodata.jmps"
print ".quad 0"
print ".quad 0"
print ".quad 0"
print ".quad 0"
