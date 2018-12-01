import angr
import logging
logger = logging.getLogger('angr')
logger.setLevel(logging.WARNING)

p = angr.Project('07')
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

class ignoreme(angr.SimProcedure):
    def run(self):
        return 0

p.hook_symbol('ignore_me',ignoreme())

def maybe_good(state):
    so = state.posix.dumps(1)
    return "Good Job" in so



sm.explore(find=maybe_good)

f = sm.found[0] # this is the good "found" state

symf = f.fs.unlinks[0][1] #the file was unlinked, so we check the unlinked files

buf = symf.read(0,64)[0] # we want to see what was read from the file.  we read 64 bytes, which is a bitvector

#f.solver.eval(buf) #this evaluates the buffer, i.e. tells us the value

hexstring = hex(f.solver.eval(buf, cast_to=str)) #convert to a hexstring

#hexlist = [hexstring[i:i+2] for i in range(0,len(hexstring),2)] # turn it into a list where each element is two chars

#ans = [unichr(int(c,16)) for c in hexlist[1:-1]] #this prints the ascii character.  Exclude the first element (which is '0x') and the last element (which is 'L')


import IPython
IPython.embed()
