import angr
import logging
logger = logging.getLogger('angr')
logger.setLevel(logging.WARNING)

p = angr.Project('01')
s = p.factory.entry_state()
sm = p.factory.simgr(s)
#sm.run()
#seadend_list = sm.deadended
#i = 0
#for state in deadend_list:
#    print("state=%i\n" % i)
#    print("stdin=%s\n" % state.posix.dumps(0))
#    print("stdout=%s\n" % state.posix.dumps(1))
#    print("stderr=%s\n" % state.posix.dumps(2))
#    print("\n\n\n")

def maybe_good(state):
    so = state.posix.dumps(1)
    return "Good Job" in so

sm.explore(find=maybe_good,avoid=0x080485a8)

import IPython
IPython.embed()
