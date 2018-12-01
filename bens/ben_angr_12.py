import angr
import claripy
import logging
logger = logging.getLogger('angr')
logger.setLevel(logging.WARNING)

p = angr.Project('12')
s = p.factory.entry_state()
sm = p.factory.simgr(s,veritesting=True)

# = p.loader.find_symbol('local_35').rebased_addr

#class complexfunction(angr.SimProcedure):
#    def run(self, str1):
#        tmp = self.state.memory.load(str1,32)
#        localpw = self.state.memory.load(pw,16)
#        self.state.add_constraints(tmp == localpw)
#        return 1
        #return claripy.If (tmp == 'DPUARPNNRZEOBKWJ',1,0)
        #return str1=='AUPDNNPROEZRJWKB'

#p.hook_symbol('check_equals_XYMKBKUHNIQYNQXE',check_equals())

class ignoreme(angr.SimProcedure):
    def run(self):
        return 0

def setzero(state):
    state.add_constraints(state.regs.ebx == state.regs.eax)

#p.hook(0x08048659,setzero)



def complexf(i):
    return (10 + (i + 0x5d)*2)%26 + 0x41
 

   

#class complexfunction(angr.SimProcedure):
#    def run(self, str1):
#        tmp = self.state.memory.load(str1,20)

def goodjorb(state):
    so = state.posix.dumps(1)
    return "Good Job" in so



sm.explore(find=goodjorb)


#f = sm.found[0] # this is the good "found" state

#f.posix.dumps(0)

import IPython
IPython.embed()
