#/usr/bin/env python

'''
This is an example that uses angr to assist in solving a crackme. In this example, angr is
used to bypass an infinite loop to focus on password code.
'''

# lots of imports
import angr, time, logging, claripy

# Start a timer for comparison
before = time.time()

# set up logging
logger = logging.getLogger('angr')
logger.setLevel(logging.INFO)   

# load the binary, set up simState obj, and sim manager obj.
proj = angr.Project("07")
state = proj.factory.entry_state(addr=0x0804893c)
buffer_val_start = claripy.BVS('buffer',0x40*8)
buffer_addr = proj.loader.find_symbol('buffer').rebased_addr
state.memory.store(buffer_addr,buffer_val_start)
simgr = proj.factory.simgr(state)

simgr.explore(find=lambda s: 'Good Job.' in s.posix.dumps(1))

if simgr.found:
    print(simgr.found[0].solver.eval(buffer_val_start, cast_to=str))

# End time
after = time.time()
print "Time elapsed: {}".format(after - before)