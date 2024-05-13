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


# Step 1: Load decryption function in Angr to recover the key
# Note that we are dealing with a single function, not a full executable file.  
# Therefore, we need to use the blob backend instead of the ELF one. 
project = angr.Project(???, main_opts={'backend': 'blob', 'arch': 'arm', 'base_addr': 0x10000, 'entry_point': 0x10000})


start_address = 0x10000
state = project.factory.blank_state(
    addr=start_address,
    add_options = { angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                    angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS}
)  


# Step 2: We need to set the whole initial state including creating a stack since we don't have a whole executable
# We keep some ARM documentation handy: https://iitd-plos.github.io/col718/ref/arm-instructionset.pdf

# Top of stack set at 0x20000
sp = claripy.BVV(0x20000, 32)
state.regs.sp = sp

# Link register can be set to 0, a concrete value
lr = claripy.BVV(0x0, 32)
state.regs.lr = lr 

# ??? is the register we are interested in, we make it symbolic
# We find that register from static analysis
??? = claripy.BVS('???', 32)
state.regs.??? = ???

# We put ciphertext on the stack and set ??? to point to it
for i in range(0, len(ciphertext)):
    state.mem[state.regs.sp+0x10+i].uint8_t = ciphertext[i]

??? = claripy.BVV(0x20000+0x10, 32)
state.regs.??? = ???


# Our strlen() replacement hook in Angr

@project.hook(0x100b4, length=4)
def skip_strlen(state):
    # we need to loop only 4 times to find key
    ??? = claripy.BVV(4, 32)
    state.regs.??? = ???
    
simgr = project.factory.simgr(state)
simgr.explore(find=0x100d8)


# This hook is use to debug our Unicorn execution
# It will run before each instruction and provide us with a way to inspect and manipulate the code as it is run

def UnicornHookCode(mu, address, size, user_data):
    pc = mu.reg_read(UC_ARM_REG_PC)
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    CODE = mu.mem_read(address, size)
    for inst in md.disasm(CODE,address):
        print("0x%x:\t%s\t%s" %(inst.address, inst.mnemonic, inst.op_str))

# This hook will run if there is any access to unmapped memory, also useful for debugging

def UnicornHookFetchUnmapped(mu, access, address, size):
    pc = mu.reg_read(UC_ARM_REG_PC)
    fp = mu.reg_read(UC_ARM_REG_FP)
    r0 = mu.reg_read(UC_ARM_REG_R0)
    print("Unmapped fetch Instruction pointer = 0x{:02X} fp: 0x{:02X}".format(pc,fp))
    print("r0 = 0x{:02X}".format(r0))
    print("Address: {:02X}".format(address)) 

# Printf is missing, call ends up in the void, so we reimplement here

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

# And we need to redo strlen() in Unicorn as well

def UnicornHookStrlen(mu, address, size, user_data):
    mu.reg_write(UC_ARM_REG_PC, mu.reg_read(UC_ARM_REG_PC) + 4)
    mu.reg_write(UC_ARM_REG_R0, len(ciphertext))

def UnicornHookKey(mu, address, size, user_data):
    r1 = mu.reg_read(UC_ARM_REG_R1)
    key = struct.unpack("<I", mu.mem_read(r1, 4))[0]
    print(f"{key=}") 
    #print("r0 = 0x{:02X}".format(r0))



# Last step: Unicorn main loop, runs the decryption with the key given by Angr, recover the full plaintext

def UnicornDecodeTitre(key):
    try:
        # Initialize emulator in arm 32bit mode
        mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)

        # On charge le binaire à la même adresse, 0x10000
        with open('???', 'rb') as f:
            data = f.read()
        mu.mem_map(0x10000, 1024)   # Allocation de la mêmoire
        mu.mem_write(0x10000, data) # Chargement du binaire

        # On met la pile au même endroit que dans Angr
        # On se garde de l'espace au dessus du pointeur de pile pour injecter notre ciphertext
        SP = 0x20000 + 1 * 1024
        mu.mem_map(0x20000, 2 * 1024 )
        mu.reg_write(UC_ARM_REG_SP, SP)

        # On met r11, lr a zéo
        mu.reg_write(UC_ARM_REG_LR, 0)
        # Unicorn utilise un registre dédié comme frame pointer
        mu.reg_write(UC_ARM_REG_FP, SP)

        # On doit aussi injecter notre ciphertext et notre clé, dans r0 et r1
        mu.mem_write(SP + 0x20, ciphertext)
        mu.reg_write(UC_ARM_REG_R0, SP + 0x20)
        mu.reg_write(UC_ARM_REG_R1, key)

        #mu.hook_add(UC_HOOK_CODE, UnicornHookCode, None)
        #mu.hook_add(UC_HOOK_CODE, UnicornHookKey, begin=0x14, end=0x14)
        mu.hook_add(UC_HOOK_CODE, UnicornHookStrlen, begin=???, end=???)
        mu.hook_add(UC_HOOK_CODE, UnicornHookPrintf, begin=???, end=???)
        #mu.hook_add(UC_HOOK_MEM_FETCH_UNMAPPED, UnicornHookFetchUnmapped, None)
        #mu.hook_add(UC_ERR_FETCH_UNMAPPED, UnicornHookFetchUnmapped, None)

        # Where shall execution start and end is obtained through static analysis
        mu.emu_start(???, ???)

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
    
    # Somehow we know that our plaintext starts with the four letters "FLAG"
    constrained_parameter_desired_value = b"???"
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


