import angr
import claripy
import base64

def inforegs(state):
    print("pc: {:02X}".format(state.solver.eval(state.regs.pc, cast_to=int)))
    print("sp: {:02X}".format(state.solver.eval(state.regs.sp, cast_to=int)))
    print("r0: {:02X}".format(state.solver.eval(state.regs.r0, cast_to=int)))
    print("r1: {:02X}".format(state.solver.eval(state.regs.r1, cast_to=int)))

ciphertext = base64.b64decode(b'CfX5cDT41lYjwMtSb9zMFyrByFsg0MxWO9DXWW/b0Vku0MpSb9jOUiyZ+Vkoy5QXGtfRVCDL1hcqzZhmJtXRWSjE')
#ciphertext = b'CfX5cDT41lYjwMtSb9zMFyrByFsg0MxWO9DXWW/b0Vku0MpSb9jOUiyZ+Vkoy5QXGtfRVCDL1hcqzZhmJtXRWSjE'

#project = angr.Project('title.bin', main_opts={'backend': 'blob', 'arch': 'arm', 'base_addr': 0x0, 'entry_point': 0x0})
project = angr.Project('decode')
start_address = 0x10e00
state = project.factory.blank_state(
    addr=start_address,
    add_options = { angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                    angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS}
)  

r1 = claripy.BVS('r1', 32)
state.regs.r1 = r1

@project.hook(0x10e00, length=0)
def skip_check_equals_(state):
    # put ciphertext on the stack
    for i in range(0, len(ciphertext)):
        state.mem[state.regs.r2+i].uint8_t = ciphertext[i]


@project.hook(0x10d24, length=4)
def skip_strlen(state):
    # we need to loop only 4 times to find key
    r0 = claripy.BVV(4, 32)
    state.regs.r0 = r0
    

simgr = project.factory.simgr(state)

simgr.explore(find=0x10d48)

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

    print("key: {}".format(key))


else:
    raise Exception('Could not find the solution')


