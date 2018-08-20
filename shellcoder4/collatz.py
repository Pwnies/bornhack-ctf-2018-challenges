#!/usr/bin/python2.7 -u
import signal; signal.alarm(5)
from engine import ArmShellcodeExecuter
import os
import random

lengths = { 1: 0 }

def collatz_length(n):
    global lengths
    if n not in lengths:
        lengths[n] = collatz_length(3*n + 1 if n & 1 else n / 2) + 1
    return lengths[n]

if __name__ == "__main__":
    print "Input: R0 = N"
    print "Output: R0 = Length of the collatz sequence of N"
    print "Constraints: len(shellcode) <= 36"
    print "Timeout: 100ms per execution, 5s in total connection time"

    shellcode = raw_input("shellcode> ").decode("hex")

    assert len(shellcode) <= 36

    for i in range(128):
        e = ArmShellcodeExecuter(shellcode)
        n = random.randint(0, 2**20)
        e["r0"] = n
        e.run()
        assert e["r0"] == collatz_length(n)

    print "Awesome shellcode! Have a flag:"
    print open("flag", "r").read().strip()
