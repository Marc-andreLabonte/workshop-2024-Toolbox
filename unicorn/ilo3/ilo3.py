import angr
import claripy


#project = angr.Project("./ilo3_193.bin", auto_load_libs=False)
project = angr.Project('ilo3_120.bin', main_opts={'backend': 'blob', 'arch': 'arm', 'base_addr': 0x1000000, 'entry_point': 0x17f37a0})
start_address = 0x17f37a4
state = project.factory.blank_state(
    addr=start_address,
    add_options = { angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                    angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS}
)


sp = claripy.BVV(0x2000000, 32)
state.regs.sp = sp

lr = claripy.BVV(0x0, 32)
state.regs.lr = lr 

#arg1 = claripy.BVV(0x1000000, 32)
r0 = claripy.BVS('r0', 32)
# r0 should be constrained between 0x1000000 and 0x17fffff
state.add_constraints(claripy.And(r0 >= claripy.BVV(0x1000000,32), r0 < claripy.BVV(0x1800000,32)))
state.regs.r0 = r0

# Define r12 as symbolic bit vector
#r12 = claripy.BVS('r12', 32)
#state.regs.r12 = r12

# f9fffffc is a fixed value
f9fffffc = state.solver.BVV(0x334f4c69, 32)
state.mem[0xf9fffffc].uint32_t = f9fffffc

# f9fffff8 is unknown
f9fffff8 = state.solver.BVS('f9fffff8', 32)
#state.solver.add(claripy.And(f9fffff8 >= claripy.BVV(0x1000000-1,32), f9fffff8 < claripy.BVV(0x1800000-(0x1800000-0x17f3750),32)))
state.mem[0xf9fffff8].uint32_t = f9fffff8
#state.solver._solver.timeout =  10000
simgr = project.factory.simulation_manager(state)


def is_successful(state):
    #cond1 = state.solver.eval(state.regs.r2, cast_to=int) == 0xffff 
    #cond2 = state.solver.eval(state.regs.pc, cast_to=int) == 0x17f377c
    # "testing Expressions for truthiness does not do what you want, as these expressions can be symbolic"
    #return claripy.BoolV(state.regs.r2 == claripy.BVV(0xffff,32))
    return  state.solver.eval(state.regs.pc, cast_to=int) == 0x17f3758

def should_abort(state):
    return  state.solver.eval(state.regs.pc, cast_to=int) >= 0x17f3ae8


def inforegs(state):
    print("pc: {:02X}".format(state.solver.eval(state.regs.pc, cast_to=int)))
    print("sp: {:02X}".format(state.solver.eval(state.regs.sp, cast_to=int)))
    print("r0: {:02X}".format(state.solver.eval(state.regs.r0, cast_to=int)))
    print("r1: {:02X}".format(state.solver.eval(state.regs.r1, cast_to=int)))
    print("r2: {:02X}".format(state.solver.eval(state.regs.r2, cast_to=int)))
    print("r3: {:02X}".format(state.solver.eval(state.regs.r3, cast_to=int)))
    print("r4: {:02X}".format(state.solver.eval(state.regs.r4, cast_to=int)))
    print("r5: {:02X}".format(state.solver.eval(state.regs.r5, cast_to=int)))
    print("r12: {:02X}".format(state.solver.eval(state.regs.r12, cast_to=int)))


avoid_addr = [0x17f3b40, 0x17f3b44, 0x17f3b48]
simgr.explore(find=0x17f3824, avoid=avoid_addr)

if simgr.found:
    solution_state = simgr.found[0]
    constrained_r12 = solution_state.regs.r12
    constrained_r0 = solution_state.regs.r0
    solution_state.add_constraints(constrained_r0 == constrained_r12)
    inforegs(solution_state)
    print("First arg should be: 0x{:02X}".format(solution_state.solver.eval(r0, cast_to=int)))
else:
    raise Exception('Could not find the solution')


