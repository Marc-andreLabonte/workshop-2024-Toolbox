from qiling import *
from qiling.const import QL_VERBOSE
from qiling.const import QL_INTERCEPT
from qiling.os.const import STRING
from capstone import *
import lief
import struct
import pdb
import re



# prepare for buffer overflow, r1 must point to our password string in memory
"""
From where we jump, querystring is in memory pointed by r2, therefore we need
to find password parameter and set r1 to the beginning of our password.

At last, we jump to where strcpy is being called ... and we're done
"""
def tooverflow(ql: Qiling) -> None:

    # fetch querystring in r2
    data = []
    index = 0
    while True:
        b = bytes(ql.mem.read(ql.arch.regs.r2 + index, 1))
        index += 1
        if b == b"\x00":
            break
        else:
            data.append(b)

    fmt = b"".join(data)
    # find password parameter
    match = re.search(b".*(password=).*", fmt)
    # set r1 to point to actual password, so after the =
    ql.arch.regs.r1 = ql.arch.regs.r2 + match.start(1) + len('password=')
    
    # jump to strcpy
    ql.arch.regs.pc = 0x1021794

# convert the program logging function to printf
# Still not a programmer, printf implementation broken and incomplete
def logger2printf(ql: Qiling) -> None:

    # fetch format string in r1
    data = []
    index = 0
    while True:
        b = bytes(ql.mem.read(ql.arch.regs.r1 + index, 1))
        index += 1
        if b == b"\x00":
            break
        else:
            data.append(b)

    fmt = b"".join(data)
    print(fmt)
    # jump over original function
    ql.arch.regs.pc = ql.arch.regs.lr

# we want to avoid some external library calls to went we hit the plt, we go back to return address    
def skipplt(ql: Qiling) -> None:
    ql.arch.regs.pc = ql.arch.regs.lr

def skip(ql: Qiling) -> None:
    ql.arch.regs.pc += 4

def stop(ql: Qiling) -> None:
    ql.log.info('killer switch found, stopping')
    ql.emu_stop()


def simple_dissassembler(ql: Qiling, address: int, size: int, md: Cs) -> None:
    buf = ql.mem.read(address, size)

    for insn in md.disasm(buf, address):
        ql.log.debug(f':: {insn.address:#x} : {insn.mnemonic:24s} {insn.op_str}')

def dumpctx(ql: Qiling) -> None:
    #print("local_44: {}".format(ql.arch.regs.r3))
    print(f'R0: {ql.arch.regs.r0:#x}')
    print(f'R1: {ql.arch.regs.r0:#x}')
    print(f'R10: {ql.arch.regs.r0:#x}')
    print(gets(ql.arch.regs.r0))
    #print(gets(ql.arch.regs.r1))
    ql.emu_stop()

def successnotzero(ql: Qiling) -> None:
    ql.arch.regs.r0 = 1

def successzero(ql: Qiling) -> None:
    ql.arch.regs.r0 = 0


# IANAP (I am not a programmer) but here is my first ever ELF image loader
# qiling has one but too strict sometimes
def loadELF(ql: Qiling, file: str, imagebase: int) -> None:

    # we will try to observe a sensible page size
    PAGE_SIZE = 4096
    binary = lief.parse(file)

    # scan virtual addresses to map memory, ignore sections with virtual address set to 0
    va = []
    for section in binary.sections:
        if section.virtual_address > 0:
            va.append(section.virtual_address)
    va.sort()
    # FIXME: won't work if last section larger than page size
    vasize = va[len(va)-1]
    pagealignedsize = vasize + PAGE_SIZE - vasize % PAGE_SIZE
    ql.mem.map(imagebase, pagealignedsize)

    # load section data from file into memory
    for section in binary.sections:
        if section.virtual_address > 0:
            ql.mem.write(section.virtual_address + imagebase, section.content.tobytes())
            print("loading {} at 0x{:02X}, size: {}".format(section.name,section.virtual_address+imagebase, section.size))

if __name__ == "__main__":
    # execute Windows EXE under our rootfs
    # set up command line argv and emulated os root path
    #argv = ['out/bin/sh', '/usr/local/bin/app.sh']
    argv = ['./tcpvuln'] 
    #env = {'LD_LIBRARY_PATH': '/usr/local/lib/'}


   
    #argv = ['out/bin/test']
    rootfs = r'.'

    # instantiate a Qiling object using above arguments and set emulation verbosity level to DEBUG.
    # additional settings are read from profile file
    #ql = Qiling(argv, rootfs, env, verbose=QL_VERBOSE.DEBUG, profile='linux.ql', multithread=True)
    ql = Qiling(argv, rootfs, verbose=QL_VERBOSE.DEBUG, multithread=False)

    # map emulated fs '/proc' dir to the hosting os '/proc' dir
    ql.add_fs_mapper('/proc', '/proc')
    ql.add_fs_mapper('/dev', '/dev')

    # load vulnerable lib
    #loadELF(ql, 'vuln.so', 0x1000000)

    ql.hook_code(simple_dissassembler, begin=0x106f4, end=0x108dc, user_data=ql.arch.disassembler)

    # Pour vrai on plus le temps, on jump direct au buffer overflow
    ql.hook_address(tooverflow, 0x102142c) # to overflow

    # skip troublesome function
    ql.hook_address(skip, 0x10213f8)
   
    # replace logger by our own broken printf
    ql.hook_address(logger2printf, 0x1017da0)


        # stat() is failing, don't know why
    ql.hook_address(successnotzero, 0x90029bd0)
    ql.hook_address(successnotzero, 0x90028380)
    #ql.hook_address(successnotzero, 0x900485bc)
    ql.hook_address(successzero, 0x9005c240)


    
     #ql.hook_address(maprintf, 0x90033b6c)
    #ql.os.set_api('printf', myprintf, QL_INTERCEPT.CALL)
    #jql.hook_address(stop, 0x9fc4)
    # do the magic!
    #ql.run( begin=0x5657407c, end=0x56574080)
    ql.run()
