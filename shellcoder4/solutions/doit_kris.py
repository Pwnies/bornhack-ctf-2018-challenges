#!/usr/bin/env python2
from pwn import *
context(arch = "arm")

print(enhex(asm('''

start:
    TST R0, 1
    ADDNE R0, R0, R0, LSL 1
    ADDNE R0, R0, 1
    LSREQ R0, R0, 1
    ADD R1, R1, 1
    CMP R0, 1
    BNE start
    MOV R0, R1

''')))
