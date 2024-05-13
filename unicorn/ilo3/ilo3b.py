import angr
import claripy


project = angr.Project("./pe_from_scratch.exe", auto_load_libs=False)
start_address = 0x17f3948
state = project.factory.blank_state(addr=start_address)
#state = project.factory.entry_state()
#state.regs.r0 = 0

# set register state, from earlier experiments
r4 = state.solver.BVV(0x1000440, 32)
r5 = state.solver.BVV(0x1000440, 32)
state.regs.r4 = r4
state.regs.r5 = r5

r6 = state.solver.BVV(0x1, 32) # compression type, see cmp at 17f3938
r7 = state.solver.BVV(0xF87F5568, 32) # loaded at 17f3868
state.regs.r6 = r6
state.regs.r7 = r7

# set stack somewhere
sp = state.solver.BVV(0x7FFEFF20, 32)
state.regs.sp = sp 

# stack
state.mem[sp-0xfc].uint32_t = 0x54c4b0

# uart, from puts execution
state.mem[0xc00000f5].uint32_t = 0xffffffff  # to indicate we are ready to receive char
state.mem[0xc00000f0].uint32_t = 0x0  # to hold char


# Define r2 as symbolic bit vector
r2 = claripy.BVS('r2', 32)
state.regs.r2 = r2

# Define r12 as symbolic bit vector
r12 = claripy.BVS('r12', 32)
state.regs.r12 = r12

# f9fffffc is a fixed value
f9fffffc = state.solver.BVV(0x334f4c69, 32)
state.mem[0xf9fffffc].uint32_t = f9fffffc

simgr = project.factory.simulation_manager(state)


def is_successful(state):
    #cond1 = state.solver.eval(state.regs.r2, cast_to=int) == 0xffff 
    #cond2 = state.solver.eval(state.regs.pc, cast_to=int) == 0x17f377c
    # "testing Expressions for truthiness does not do what you want, as these expressions can be symbolic"
    #return claripy.BoolV(state.regs.r2 == claripy.BVV(0xffff,32))
    return  state.solver.eval(state.regs.pc, cast_to=int) == 0x17f37e4

def should_abort(state):
    return  state.solver.eval(state.regs.pc, cast_to=int) >= 0x17f3ae8


def inforegs(state):
    print("pc: {:02X}".format(state.solver.eval(state.regs.pc, cast_to=int)))
    print("r0: {:02X}".format(state.solver.eval(state.regs.r0, cast_to=int)))
    print("r1: {:02X}".format(state.solver.eval(state.regs.r1, cast_to=int)))
    print("r2: {:02X}".format(state.solver.eval(state.regs.r2, cast_to=int)))
    print("r3: {:02X}".format(state.solver.eval(state.regs.r3, cast_to=int)))
    print("r4: {:02X}".format(state.solver.eval(state.regs.r4, cast_to=int)))
    print("r5: {:02X}".format(state.solver.eval(state.regs.r5, cast_to=int)))
    print("r12: {:02X}".format(state.solver.eval(state.regs.r12, cast_to=int)))


avoid_addr = [0x17f3ae0, 0x17f3ae4, 0x17f3ae8]
simgr.explore(find=0x17f3998, avoid=avoid_addr)

if simgr.found:
    solution_state = simgr.found[0]
    for state in simgr.found:
        print("instruction pointer is : 0x{:02X}".format(state.solver.eval(state.regs.pc, cast_to=int)))
else:
    raise Exception('Could not find the solution')


