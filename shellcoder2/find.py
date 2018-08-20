#!/usr/bin/python2.7 -u
import signal; signal.alarm(5)
from engine import X86ShellcodeExecuter
import os
import random

DATA_SIZE = 1024*1024
ITERATIONS = 10

if __name__ == "__main__":
    print "See if you can find the flag reliably"
    print "Input: EDI = pointer to some data"
    print "Output: EDI = pointer to flag"
    print "Constraints: \\x00-free and len(shellcode) <= 11"
    print "Timeout: 100ms per execution, 5s in total connection time"

    shellcode = raw_input("shellcode> ").decode("hex")

    assert "\x00" not in shellcode
    assert len(shellcode) <= 11

    flag = open("flag", "r").read().strip()

    for n in range(ITERATIONS):
        data = os.urandom(DATA_SIZE)
        position = random.randint(0, DATA_SIZE-len(flag) -1) & ~3
        data = data[:position] + flag + data[position + len(flag):]
        e = X86ShellcodeExecuter(shellcode)
        data_addr = e.malloc(DATA_SIZE)
        e.uc.mem_write(data_addr, data)
        e["edi"] = data_addr
        e.run()
        found = e.uc.mem_read(e["edi"], len(flag))
        assert found == flag

    print "Awesome shellcode! Have a flag:"
    print flag
