import angr
import claripy
import logging
logger = logging.getLogger('angr')
logger.setLevel(logging.WARNING)

p = angr.Project('09')
s = p.factory.entry_state()
sm = p.factory.simgr(s)

pw = p.loader.find_symbol('password').rebased_addr

class check_equals(angr.SimProcedure):
    def run(self, str1):
        tmp = self.state.memory.load(str1,16)
        localpw = self.state.memory.load(pw,16)
        self.state.add_constraints(tmp == localpw)
        return 1
        #return claripy.If (tmp == 'DPUARPNNRZEOBKWJ',1,0)
        #return str1=='AUPDNNPROEZRJWKB'

p.hook_symbol('check_equals_XYMKBKUHNIQYNQXE',check_equals())

def goodjorb(state):
    so = state.posix.dumps(1)
    return "Good Job" in so



sm.explore(find=goodjorb)

#f = sm.found[0] # this is the good "found" state

#f.posix.dumps(0)

import IPython
IPython.embed()
