from capstone import *
import sys


with open(sys.argv[1], 'rb') as f:
    CODE = f.read()


md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
address = 0x0
for inst in md.disasm(CODE,address):
    print("0x%x:\t%s\t%s" %(inst.address, inst.mnemonic, inst.op_str))
