import angr
import claripy
import logging
logger = logging.getLogger('angr')
logger.setLevel(logging.WARNING)

p = angr.Project('08')
s = p.factory.entry_state()
sm = p.factory.simgr(s)

pw = p.loader.find_symbol('password').rebased_addr

class check_equals(angr.SimProcedure):
    def run(self, str1):
        tmp = self.state.memory.load(str1,16)
        realpw = self.state.memory.load(pw,16)
        self.state.add_constraints(tmp == realpw)
        return 1
        #return claripy.If (tmp == 'DPUARPNNRZEOBKWJ',1,0)
        #return str1=='AUPDNNPROEZRJWKB'

p.hook_symbol('check_equals_AUPDNNPROEZRJWKB',check_equals())

def goodjorb(state):
    so = state.posix.dumps(1)
    return "Good Job" in so



sm.explore(find=goodjorb)

#f = sm.found[0] # this is the good "found" state

#symf = f.fs.unlinks[0][1] #the file was unlinked, so we check the unlinked files

#buf = symf.read(0,64)[0] # we want to see what was read from the file.  we read 64 bytes, which is a bitvector

#f.solver.eval(buf) #this evaluates the buffer, i.e. tells us the value

#hexstring = hex(f.solver.eval(buf, cast_to=str)) #convert to a hexstring

#hexlist = [hexstring[i:i+2] for i in range(0,len(hexstring),2)] # turn it into a list where each element is two chars

#ans = [unichr(int(c,16)) for c in hexlist[1:-1]] #this prints the ascii character.  Exclude the first element (which is '0x') and the last element (which is 'L')


import IPython
IPython.embed()
