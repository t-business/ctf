import angr
import claripy
import logging
logger = logging.getLogger('angr')
logger.setLevel(logging.WARNING)

p = angr.Project('17')
s = p.factory.entry_state()
sm = p.factory.simgr(s)



class ignoreme(angr.SimProcedure):
    def run(self):
        return 0

goodjobstr = 0x42585353 # = BXSS

print_good = 0x42585249 # = BXRI

#def firstkey(state):
#    state.add_constraints(state.regs.eax == 0xb11403)

#def properpointer(state):
#    state.add_constraints(state.regs.eax == passwordbuffer)

#p.hook(0x080485d9, firstkey)

#p.hook(0x0804860c, properpointer)
#p.hook(0x080485f5, properpointer)

def goodjorb(state):
    so = state.posix.dumps(1)
    return "Good Job" in so



sm.explore(find=goodjorb)


#f = sm.found[0] # this is the good "found" state

#f.posix.dumps(0)

import IPython
IPython.embed()
