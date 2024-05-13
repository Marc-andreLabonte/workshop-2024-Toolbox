import angr
import claripy
import base64
from unicorn import *                                                                
from unicorn.arm_const import *
from capstone import *
import struct


def inforegs(state):
    print("pc: {:02X}".format(state.solver.eval(state.regs.pc, cast_to=int)))
    print("sp: {:02X}".format(state.solver.eval(state.regs.sp, cast_to=int)))
    print("r0: {:02X}".format(state.solver.eval(state.regs.r0, cast_to=int)))
    print("r1: {:02X}".format(state.solver.eval(state.regs.r1, cast_to=int)))

ciphertext = base64.b64decode(b'CfX5cDTu10UkytBYP5mKB32Nghcb1tdbLdbAFynWyhc93M5SPcrdFyrX314h3N1FJtffFy7X3Bct0NZWPcCYUjfJ1FgmzdlDJtbWSg==')

project = angr.Project('obfuscation.bin', main_opts={'backend': 'blob', 'arch': 'arm', 'base_addr': 0x10000, 'entry_point': 0x10000})
#project = angr.Project('decode')
start_address = 0x10000
state = project.factory.blank_state(
    addr=start_address,
    add_options = { angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                    angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS}
)  


sp = claripy.BVV(0x20000, 32)
state.regs.sp = sp

lr = claripy.BVV(0x0, 32)
state.regs.lr = lr 

r1 = claripy.BVS('r1', 32)
state.regs.r1 = r1

# put ciphertext on the stack and set r0 to point to it
for i in range(0, len(ciphertext)):
    state.mem[state.regs.sp+0x10+i].uint8_t = ciphertext[i]

r0 = claripy.BVV(0x20000+0x10, 32)
state.regs.r0 = r0

@project.hook(0x100b4, length=4)
def skip_strlen(state):
    # we need to loop only 4 times to find key
    r0 = claripy.BVV(4, 32)
    state.regs.r0 = r0
    
simgr = project.factory.simgr(state)
simgr.explore(find=0x100d8)

def UnicornHookCode(mu, address, size, user_data):
    pc = mu.reg_read(UC_ARM_REG_PC)
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    CODE = mu.mem_read(address, size)
    for inst in md.disasm(CODE,address):
        print("0x%x:\t%s\t%s" %(inst.address, inst.mnemonic, inst.op_str))

def UnicornHookFetchUnmapped(mu, access, address, size):
    pc = mu.reg_read(UC_ARM_REG_PC)
    fp = mu.reg_read(UC_ARM_REG_FP)
    r0 = mu.reg_read(UC_ARM_REG_R0)
    print("Unmapped fetch Instruction pointer = 0x{:02X} fp: 0x{:02X}".format(pc,fp))
    print("r0 = 0x{:02X}".format(r0))
    print("Address: {:02X}".format(address)) 

def UnicornHookPrintf(mu, address, size, user_data):
    mu.reg_write(UC_ARM_REG_PC, mu.reg_read(UC_ARM_REG_PC) + 4)
    # le texte en clair est dans r1
    r1 = mu.reg_read(UC_ARM_REG_R1)
    data = []
    index = 0
    while True:
        b = bytes(mu.mem_read(r1 + index, 1))
        index += 1
        if b == b"\x00":
            break
        else:
            data.append(b)

    fmt = b"".join(data)
    #sys.stdout.write("{}\n".format(hex(r0)))
    print(fmt)

def UnicornHookStrlen(mu, address, size, user_data):
    mu.reg_write(UC_ARM_REG_PC, mu.reg_read(UC_ARM_REG_PC) + 4)
    mu.reg_write(UC_ARM_REG_R0, len(ciphertext))

def UnicornHookKey(mu, address, size, user_data):
    r1 = mu.reg_read(UC_ARM_REG_R1)
    key = struct.unpack("<I", mu.mem_read(r1, 4))[0]
    print(f"{key=}") 
    #print("r0 = 0x{:02X}".format(r0))

def UnicornDecodeTitre(key):
    try:
        # Initialize emulator in arm 32bit mode
        mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)

        # On charge le binaire à la même adresse, 0x10000
        with open('obfuscation.bin', 'rb') as f:
            data = f.read()
        mu.mem_map(0x10000, 1024)   # Allocation de la mêmoire
        mu.mem_write(0x10000, data) # Chargement du binaire

        SP = 0x20000 + 1 * 1024
        mu.mem_map(0x20000, 2 * 1024 )
        mu.reg_write(UC_ARM_REG_SP, SP)

        mu.reg_write(UC_ARM_REG_LR, 0)
        mu.reg_write(UC_ARM_REG_FP, SP)

        mu.mem_write(SP + 0x20, ciphertext)
        mu.reg_write(UC_ARM_REG_R0, SP + 0x20)
        mu.reg_write(UC_ARM_REG_R1, key)

        mu.hook_add(UC_HOOK_CODE, UnicornHookStrlen, begin=0x100b4, end=0x100b4)
        mu.hook_add(UC_HOOK_CODE, UnicornHookPrintf, begin=0x100d4, end=0x100d4)

        mu.emu_start(0x10000, 0x100d8)

    except UcError as e:
        print(e)




if simgr.found:
    solution_state = simgr.found[0]
    inforegs(simgr.found[0])
    constrained_parameter_address = solution_state.regs.r1
    constrained_parameter_size_bytes = 4 
    constrained_parameter_bitvector = solution_state.memory.load(
      constrained_parameter_address,
      constrained_parameter_size_bytes
    )

    # We want to constrain the system to find an input that will make
    # constrained_parameter_bitvector equal the desired value.
    # (!)
    constrained_parameter_desired_value = b"FLAG"
    # Specify a claripy expression (using Pythonic syntax) that tests whether
    # constrained_parameter_bitvector == constrained_parameter_desired_value.
    # We will let z3 attempt to find an input that will make this expression
    # true.
    constraint_expression = constrained_parameter_bitvector == constrained_parameter_desired_value
    
    solution_state.add_constraints(
        constrained_parameter_bitvector == constrained_parameter_desired_value
    )

    print(solution_state.solver.eval(constrained_parameter_bitvector,cast_to=bytes))
    # Solve for the constrained_parameter_bitvector.
    key = solution_state.solver.eval(r1,cast_to=int)

    print("key: {}, running unicorn".format(key))
    UnicornDecodeTitre(key)
    


else:
    raise Exception('Could not find the solution')


