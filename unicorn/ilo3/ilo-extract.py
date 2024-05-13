from unicorn import *
from unicorn.arm_const import *
import struct
import sys

# Artefacts where left in the code, hopefully to help understand it.
# Try to redo the whole thing from scratch is left as an exercise to the reader
# Reverse engineering not fully done, many questions remain

# run getilo.sh script to get this file
with open('ilo3_120.bin', 'rb') as f:
    text = f.read()

# Memory map
ADDRESS = 0x0000000 # Text section, also contains data
FLAG    = 0x2000000 # where the flag will be stored once challenge is solved
ENTRY   = ??? # Where we start
STOP    = ??? # We want to get there
STACK   = 0x7FFE0000 # put stack high in your address space
YOLO    = 0xF9FF0000 # Maybe memory mapped register, no clue
B0      = 0xB0000000 # No clue what is there
A1      = 0xA1000000 # No clue, stuff gets written there
UART    = 0xC0000000 # Looks like uart, used by putc

# Need our own puts
def hook_puts(mu, address, size, user_data):
    r0 = mu.reg_read(UC_ARM_REG_R0)
    data = []
    index = 0
    while True:
        b = bytes(mu.mem_read(r0+index, 1))
        index += 1
        if b == b"\x00":
            break
        else:
            data.append(b)

    fmt = b"".join(data)        
    sys.stdout.write("{}\n".format(fmt.decode('utf8')))
    # return where we were called
    lr = mu.reg_read(UC_ARM_REG_LR)
    mu.reg_write(UC_ARM_REG_PC, lr)


# Same for putc
def hook_putc(mu, address, size, user_data):
    r0 = mu.reg_read(UC_ARM_REG_R0)
    sys.stdout.write("{}\n".format(chr(r0)))
    # return where we were called
    lr = mu.reg_read(UC_ARM_REG_LR)
    mu.reg_write(UC_ARM_REG_PC, lr)

# gets called if write access outside of mapped memory occurs
def hook_mem_write_unmapped(mu, access, address, size, value, user_data):
    pc = mu.reg_read(UC_ARM_REG_PC)
    print("Unmapped write, instruction pointer = 0x{:02X}".format(pc))
    print("Adress: {:02X}".format(address))

def hook_mem_read_unmapped(mu, access, address, size, value, user_data):
    pc = mu.reg_read(UC_ARM_REG_PC)
    print("Unmapped read, instruction pointer = 0x{:02X}".format(pc))
    print("Address: {:02X}".format(address))

def hook_mem_fetch_unmapped(mu, access, address, size):
    pc = mu.reg_read(UC_ARM_REG_PC)
    #print("Unmapped fetch Instruction pointer = 0x%x" %pc)
    #print("Adress: {:02X}".format(address))


# Trace all instructions, useful for debugging purposes
def hook_code(mu, address, size, user_data):  
    print('>>> Tracing instruction at 0x{:02X}'.format(address))

def donothing(mu, address, size, user_data):
    pass

# Step over some instruction we would like to avoid
def step_over(mu, address, size, user_data):
    pc = mu.reg_read(UC_ARM_REG_PC)
    mu.reg_write(UC_ARM_REG_PC, pc+4)


# Dump common registers, would be cool to dump part of the stack as well
def cpu_state(mu):
    print("PC = 0x{:02X}".format(mu.reg_read(UC_ARM_REG_PC)))
    print("SP = 0x{:02X}".format(mu.reg_read(UC_ARM_REG_SP)))
    print("R0 = 0x{:02X}".format(mu.reg_read(UC_ARM_REG_R0)))
    print("R1 = 0x{:02X}".format(mu.reg_read(UC_ARM_REG_R1)))
    print("R2 = 0x{:02X}".format(mu.reg_read(UC_ARM_REG_R2)))
    print("R3 = 0x{:02X}".format(mu.reg_read(UC_ARM_REG_R3)))
    print("R4 = 0x{:02X}".format(mu.reg_read(UC_ARM_REG_R4)))
    print("R5 = 0x{:02X}".format(mu.reg_read(UC_ARM_REG_R5)))
    print("R6 = 0x{:02X}".format(mu.reg_read(UC_ARM_REG_R6)))
    print("R7 = 0x{:02X}".format(mu.reg_read(UC_ARM_REG_R7)))
    print("R8 = 0x{:02X}".format(mu.reg_read(UC_ARM_REG_R8)))
    print("R9 = 0x{:02X}".format(mu.reg_read(UC_ARM_REG_R9)))
    print("R10 = 0x{:02X}".format(mu.reg_read(UC_ARM_REG_R10)))
    print("R11 = 0x{:02X}".format(mu.reg_read(UC_ARM_REG_R11)))
    print("R12 = 0x{:02X}".format(mu.reg_read(UC_ARM_REG_R12)))
    print("R13 = 0x{:02X}".format(mu.reg_read(UC_ARM_REG_R13)))
    print("R14 = 0x{:02X}".format(mu.reg_read(UC_ARM_REG_R14)))
    print("R15 = 0x{:02X}".format(mu.reg_read(UC_ARM_REG_R15)))

# Fix decompression function arguments, running out of time to fully understand why they aren't right in the first place
def fix_decomp_args(mu, address, size, user_data):
    # R0 = 1st arg = ???
    # Would be offset where decompression should start
    mu.reg_write(UC_ARM_REG_R0, ???)
    # R1 = 2nd arg = ??? length of compressed data, need to dereference pointer
    mu.reg_write(UC_ARM_REG_R1, struct.unpack("<I", mu.mem_read(???))[0])


print("Emulate arm 32 bits code")
try:
    # Initialize emulator in arm 32bit mode
    mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)

    # map 8MB memory for this emulation
    mu.mem_map(ADDRESS, 8 * 1024 * 1024)
    
    # map 16MB memory for flag, as data is being decompressed
    mu.mem_map(FLAG, 16 * 1024 * 1024)
    
    # map 4KB memory for stack 
    mu.mem_map(STACK, 5 * 1024 )
    
    # 3 other sections that we need to map, serves unknown purposes  
    mu.mem_map(YOLO, 0x10000)
    mu.mem_map(B0, 0x4000)
    mu.mem_map(A1, 0x10000)

    # most likely UART, strings and characters are being written to it
    mu.mem_map(UART, 0x4000)

    # Magic number to make sure file is iLO image, recovered from static analysis
    mu.mem_write(0xf9fffffc, struct.pack("<I", ???))
    

    # write machine code to be emulated to memory
    mu.mem_write(ADDRESS, text)

    # initialize stack, set sp 1kb below top of stack as we need access above it ?
    mu.reg_write(UC_ARM_REG_SP, STACK + 4 * 1024)
    mu.mem_write(STACK + 4 * 1024 - 0xfc, struct.pack("<I", 0x54c4b0))  # from static analysis
    
    # initialize machine registers, from static & angr analysis
    mu.reg_write(UC_ARM_REG_R0, 0x0)
    #mu.reg_write(UC_ARM_REG_R4, 0x000440 + 0x440) #see 7f3930
    #mu.reg_write(UC_ARM_REG_R5, 0x000440)
    #mu.reg_write(UC_ARM_REG_R6, 0x1)
    #mu.reg_write(UC_ARM_REG_R7, 0xF87F5568)

    # need to initialize pointer at r5[0xd] before decompression, see 7f3990
    mu.mem_write(0x0000440 + 0xd*4, struct.pack("<I", FLAG))  # from static analysis
    

    # uart, from puts execution
    mu.mem_write(0xc00000f5, struct.pack("<I", 0xffffffff))  # to indicate we are ready to receive char
    mu.mem_write(0xc00000f0, struct.pack("<I", 0x0))  # to hold char

    # hook unmapped memory accesses to debug them
    mu.hook_add(UC_HOOK_MEM_WRITE_UNMAPPED, hook_mem_write_unmapped, None)
    mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED, hook_mem_read_unmapped, None)
    mu.hook_add(UC_ERR_FETCH_UNMAPPED, hook_mem_fetch_unmapped, None)

    # hook all instruction in case we need debugging
    #mu.hook_add(UC_HOOK_CODE, hook_code)

    # Try and step over branch at 0x7f3868, 0x7f3888, 7f38cc
    mu.hook_add(UC_HOOK_CODE, step_over, begin=ADDRESS + 0x7f3868, end=ADDRESS + 0x7f3868)
    mu.hook_add(UC_HOOK_CODE, step_over, begin=ADDRESS + 0x7f3888, end=ADDRESS + 0x7f3888)
    mu.hook_add(UC_HOOK_CODE, step_over, begin=ADDRESS + 0x7f38cc, end=ADDRESS + 0x7f38cc)
    mu.hook_add(UC_HOOK_CODE, step_over, begin=ADDRESS + 0x7f38d4, end=ADDRESS + 0x7f38d4)

    # Jump over functions that will cause crash, unneeded in our case
    mu.hook_add(UC_HOOK_CODE, step_over, begin=ADDRESS + 0x7f391c, end=ADDRESS + 0x7f3998)

    # Fix arguments to decompression function, didn't had time to get it right
    mu.hook_add(UC_HOOK_CODE, fix_decomp_args, begin=ADDRESS + ???, end=ADDRESS + ???)
    
    
    # hook puts, putc
    mu.hook_add(UC_HOOK_CODE, hook_puts, begin=ADDRESS + 0x7f3778, end=ADDRESS + 0x7f3778)
    mu.hook_add(UC_HOOK_CODE, hook_putc, begin=ADDRESS + 0x7f0858, end=ADDRESS + 0x7f0858)

    # emulate code in infinite time & unlimited instructions
    mu.emu_start(ADDRESS+ENTRY, ADDRESS + STOP)

    # now print out some registers
    print("Looks like we got the flag!!, saving to disk")

    # at this point, register ??? contains the size of decompressed data 
    flagsize = mu.reg_read(???)
    flagdata = mu.mem_read(FLAG, flagsize)
    with open('flag.bin', 'wb') as f:
        f.write(flagdata)
    cpu_state(mu)

except UcError as e:
    print(e)
