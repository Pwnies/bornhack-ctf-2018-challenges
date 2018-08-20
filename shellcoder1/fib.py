#!/usr/bin/python2.7 -u
import signal; signal.alarm(5)
from engine import X86ShellcodeExecuter

if __name__ == "__main__":
    print "Make your best fibonacci shellcode"
    print "Input: EAX = n"
    print "Output: EAX = fib(n)"
    print "Constraints: \\x00-free and len(shellcode) <= 7"
    print "Timeout: 100ms per execution, 5s in total connection time"

    shellcode = raw_input("shellcode> ").decode("hex")

    assert "\x00" not in shellcode
    assert len(shellcode) <= 7
    
    a, b = 1, 0
    for n in range(1, 42):
        a, b = a+b, a
        e = X86ShellcodeExecuter(shellcode)
        e["eax"] = n
        e.run()
        assert e["eax"] == a

    print "Awesome shellcode! Have a flag:"
    print open("flag", "r").read().strip()
