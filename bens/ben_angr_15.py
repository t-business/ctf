import angr
import claripy
import logging
logger = logging.getLogger('angr')
logger.setLevel(logging.WARNING)

p = angr.Project('15')
s = p.factory.entry_state()
sm = p.factory.simgr(s)



class ignoreme(angr.SimProcedure):
    def run(self):
        return 0

def findgoodjob(state):
    state.add_constraints(state.regs.eax == 0x484f4a47)

p.hook(0x08048524, findgoodjob)

def goodjorb(state):
    so = state.posix.dumps(1)
    return "Good Job" in so



sm.explore(find=goodjorb)


#f = sm.found[0] # this is the good "found" state

#f.posix.dumps(0)

import IPython
IPython.embed()
