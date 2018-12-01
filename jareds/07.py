import angr, logging, claripy

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Start at a particular location, set the buffer symbolic, and execute
proj = angr.Project('07')
start_state = proj.factory.entry_state(addr=0x0804893c)
buffer_val_start = claripy.BVS('buffer',0x40*8)
buffer_addr = proj.loader.find_symbol('buffer').rebased_addr
start_state.memory.store(buffer_addr,buffer_val_start)
simgr = proj.factory.simgr(start_state)
simgr.explore(find=lambda s: 'Good Job.' in s.posix.dumps(1))

if simgr.found:
    print(simgr.found[0].solver.eval(buffer_val_start, cast_to=str))
