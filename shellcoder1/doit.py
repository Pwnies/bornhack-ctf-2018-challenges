from pwn import *

print asm("""
xchg ecx, eax
inc eax
l:
    add ebx, eax
    xchg ebx, eax
    loop l
""").encode("hex")


