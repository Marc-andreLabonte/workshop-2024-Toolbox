import angr
import claripy
import sys

def main(argv):
  path_to_binary = './easymath'
  project = angr.Project(path_to_binary)
  print(project.loader)

  # Find start of the solve() function in Ghidra
  start_address = 0x00401139
  initial_state = project.factory.blank_state(addr=start_address)

  # We want Angr to play with solve() first argument, x so we define it as symbolic 
  # x is a 32 bit value as it is being picked up from edi which is a 32 bits register
  x = claripy.BVS('x', 32)

  # solve() first argument is passed in the edi register so we define it in our initial state
  initial_state.regs.rdi = x

  # Then we can start our simulation
  simulation = project.factory.simgr(initial_state)


  # From solve function, we want to look for 'correct answer' being print on stdout
  def is_successful(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return b'correct answer' in stdout_output 

  # We discard states where 'Try again' is being printed, we don't want to go there
  def should_abort(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return b'Try again' in stdout_output 

  # Note that we could also specify a specific adress to find and a list of addresses to avoid
  simulation.explore(find=is_successful, avoid=should_abort)


  # Woohoo! Angr reach destination 
  if simulation.found:
    solution_state = simulation.found[0]

    # concretize (recover) the value of x that allowed us to reach our destination
    solution0 = solution_state.solver.eval(x, cast_to=int)

    print("Solution found, patch binary so solve argument is equal to: {}\n".format(solution0))
  else:
    raise Exception('Could not find the solution')

if __name__ == '__main__':
  main(sys.argv)
