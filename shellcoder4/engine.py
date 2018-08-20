from unicorn import *
from collections import *
import random
import struct

ARCH = namedtuple("ARCH", ["name", "arch", "mode", "bits", "endian", "consts", "reg_prefix", "sp", "pc"])

X86 = ARCH("x86", UC_ARCH_X86, UC_MODE_32, 32, "<", x86_const, "UC_X86_REG_", "ESP", "EIP")
ARM = ARCH("arm", UC_ARCH_ARM, UC_MODE_ARM, 32, "<", arm_const, "UC_ARM_REG_", None, None)
THUMB = ARCH("thumb", UC_ARCH_ARM, UC_MODE_THUMB, 32, "<", arm_const, "UC_ARM_REG_", None, None)
SPARC32 = ARCH("sparc64", UC_ARCH_SPARC, UC_MODE_SPARC32 | UC_MODE_BIG_ENDIAN, 32, "<", sparc_const, "UC_SPARC_REG_", "sp", None)

class ShellcodeExecuter(object):
    ARCH = None
    MIN_HEAP_SIZE = 4096
    STACK_SIZE = 0
    TIMEOUT_MS = 100*1000

    def __init__(self, shellcode):
        self.uc = Uc(self.ARCH.arch, self.ARCH.mode)
        self.stack = None
        self.heap = None
        self.shellcode = shellcode
        self.shellcode_addr = self.malloc(len(shellcode))
        self.uc.mem_write(self.shellcode_addr, self.shellcode) 
        if self.STACK_SIZE: self.setup_stack()

    def setup_stack(self):
        assert self.ARCH.sp != None

        self.stack = self.malloc(self.STACK_SIZE) + self.STACK_SIZE
        self[self.ARCH.sp] = self.stack
    
    def push(self, value):
        assert self.ARCH.sp != None
        assert self.stack != None

        self.stack -= self.ARCH.bits / 8
        self.uc.mem_write(self.stack, self.pack(value))
        self[self.ARCH.sp] = self.stack
    
    def pack(self, value):
        fmt = self.ARCH.endian + "L" if self.ARCH.bits == 32 else "Q"
        return struct.pack(fmt, value)

    def unpack(self, data):
        fmt = self.ARCH.endian + "L" if self.ARCH.bits == 32 else "Q"
        return struct.unpack(fmt, data)[0]
        
    def dump_state(self):
        regs = [reg[len(self.ARCH.reg_prefix):]
                for reg in dir(self.ARCH.consts)
                if reg.startswith(self.ARCH.reg_prefix)]

        for reg in sorted(regs):
            try:
                print "%s: 0x%x" %(reg, self[reg])
            except TypeError:
                pass
            except ValueError:
                pass
            except UcError:
                pass

    def lookup_reg_const(self, name):
        return getattr(self.ARCH.consts, self.ARCH.reg_prefix + name.upper())

    def __getitem__(self, reg):
        return self.uc.reg_read(self.lookup_reg_const(reg))
    
    def __setitem__(self, reg, val):
        return self.uc.reg_write(self.lookup_reg_const(reg), val)

    def malloc(self, size):
        # Fix alignment
        size += ((self.ARCH.bits / 8) - 1)
        size &= ~((self.ARCH.bits / 8) - 1)

        # setup heap or allocate more space as needed
        if not self.heap or self.heap[1] < size:
            allocation_size = max(self.MIN_HEAP_SIZE, (size + 0xfff) & 0xfffff000)
            allocation_addr = random.randint(0, 2**31) & 0xfffff000
            self.uc.mem_map(allocation_addr, allocation_size)
            self.heap = (allocation_addr, allocation_size)
        
        # allocate a chunk on the heap
        addr = self.heap[0]
        self.heap = (self.heap[0] + size, self.heap[1] - size)
        return addr

    def setup(self):
        pass

    def check(self):
        return True

    def run(self):
        self.setup()
        try:
            self.uc.emu_start(
                self.shellcode_addr,
                self.shellcode_addr + len(self.shellcode),
                timeout = self.TIMEOUT_MS,
            )
        except UcError as e:
            print e
            self.dump_state()
        return self.check()

class X86ShellcodeExecuter(ShellcodeExecuter):
    ARCH = X86

class Sparc32ShellcodeExecuter(ShellcodeExecuter):
    ARCH = SPARC32

class ArmShellcodeExecuter(ShellcodeExecuter):
    ARCH = ARM
