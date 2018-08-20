from pwn import *
context(arch="arm", bits=32, endian="little")

tag = u32("FLAG")

print asm("""
    loop:
        tst r0, 1
        addne r0, r0, r0, lsl 1
        addne r0, r0, 1
        addne r1, r1, 1
        lsr r0, r0, 1
        add r1, r1, 1
        cmp r0, 1
        bne loop
    mov r0, r1
""" % locals()).encode("hex")


