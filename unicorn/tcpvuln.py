from unicorn import *
from unicorn.arm_const import *
from capstone import *
import binascii
import struct
import sys
import pdb
import lief

# FIXME, some hardcoded values

STACK = 0x40800000 # got it from gdb

def hook_mem_write_unmapped(mu, access, address, size, value, user_data):
    pc = mu.reg_read(UC_ARM_REG_PC)
    print("Unmapped write, instruction pointer = 0x%x" %pc)
    print("Address = 0x%x" %address)


# useful to debug invalid instruction exceptions

def hook_code(mu, address, size, user_data):
    pc = mu.reg_read(UC_ARM_REG_PC)
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    CODE = mu.mem_read(address, size)
    for inst in md.disasm(CODE,address):
        print("0x%x:\t%s\t%s" %(inst.address, inst.mnemonic, inst.op_str))

# IANAP (I am not a programmer) but here is my first ever ELF image loader
# Unicorn wasn't doing it for me
# https://www.freelists.org/post/unicorn-engine/Does-Unicorn-contain-an-elf-parser-to-load-codesAnd-various-questions,2
def loadELF(mu, file, imagebase=0):

    # we will try to observe a sensible page size
    PAGE_SIZE = 4096
    binary = lief.parse(file)

    # scan virtual addresses to map memory, ignore sections with virtual address set to 0
    va = []
    for section in binary.sections:
        if section.virtual_address > 0:
            va.append(section.virtual_address)
    va.sort()
    vasize = imagebase + va[len(va)-1]
    pagealignedsize = vasize + PAGE_SIZE - vasize % PAGE_SIZE
    mu.mem_map(imagebase, pagealignedsize)

    # load section data from file into memory
    for section in binary.sections:
        if section.virtual_address > 0:
            mu.mem_write(section.virtual_address + imagebase, section.content.tobytes())
            print("loading {} at 0x{:02X}, size: {}".format(section.name,section.virtual_address, section.size))


print("Emulate arm 32 bits code")
try:
    # Initialize emulator in arm 32bit mode
    mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)

    # hook unmapped memory accesses to debug them
    mu.hook_add(UC_HOOK_MEM_WRITE_UNMAPPED, hook_mem_write_unmapped, None)
    #mu.hook_add(UC_HOOK_CODE, hook_code, begin=0x34200, end=0x34218)
    # Like pressing next all the time in gdb
    mu.hook_add(UC_HOOK_CODE, hook_code)
    #mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED, hook_mem_read_unmapped, None)
    #mu.hook_add(UC_ERR_FETCH_UNMAPPED, hook_mem_fetch_unmapped, None)

    # load test binary and vulnerable libraries
    loadELF(mu, 'tcpvuln') 
    
    # map 8KB memory for stack 
    mu.mem_map(STACK, 8 * 1024 )
    mu.reg_write(UC_ARM_REG_SP, STACK + 8 * 1024)
    

    # initialize stack, set sp 1kb below top of stack as we need access above it ?
    #mu.mem_write(STACK + 4 * 1024 - 0xf4, struct.pack("<I", 0x66cb00))  # from static analysis
    
    # initialize machine registers, from static & angr analysis
    #mu.reg_write(UC_ARM_REG_R4, 0x1000440 + 0x440 ) #see 7f3930
    #mu.reg_write(UC_ARM_REG_R11, 0x1000440 )


    # hook puts, putc
    #mu.hook_add(UC_HOOK_CODE, hook_puts, begin=ADDRESS + 0x7f369c, end=ADDRESS + 0x7f369c)

    # emulate main function in tcpvuln text section
    mu.emu_start(0x106f4, 0x108c4)

    # now print out some registers
    print("Looks like we got the flag!!, saving to disk")

    
    # at this point, r3 contains the size of decompressed data 

except UcError as e:
    print(e)

