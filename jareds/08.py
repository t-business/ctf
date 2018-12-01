import angr, logging, claripy

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# # Turn on Veritesting (frequent state merging)
# proj = angr.Project('08')
# simgr = proj.factory.simgr(veritesting=True)
# simgr.explore(find=lambda s: 'Good Job.' in s.posix.dumps(1))
# if simgr.found:
#     print(simgr.found[0].posix.dumps(0))

# # Stop after first loop, check for string
# proj = angr.Project('08')
# simgr = proj.factory.simgr()
# simgr.explore(find=0x0804866c)
# if simgr.found:
#     st = simgr.found[0]
#     buffer_addr = proj.loader.find_symbol('buffer').rebased_addr
#     buffer_bytes = st.memory.load(buffer_addr, 16)
#     #password_bytes = 'AUPDNNPROEZRJWKB'
#     password_addr = proj.loader.find_symbol('password').rebased_addr
#     password_bytes = st.memory.load(password_addr, 16)
#     st.add_constraints(buffer_bytes == password_bytes)
#     print(st.posix.dumps(0))

# # Stub out equality check
# proj = angr.Project('08')
# class eq(angr.SimProcedure):
#     def run(self,buffer_addr):
#         buffer_bytes = self.state.memory.load(buffer_addr, 16)
#         password_addr = proj.loader.find_symbol('password').rebased_addr
#         password_bytes = self.state.memory.load(password_addr, 16)
#         return claripy.If(buffer_bytes == password_bytes, claripy.BVV(1,32), claripy.BVV(0,32))
# proj.hook_symbol('check_equals_AUPDNNPROEZRJWKB', eq())
# simgr = proj.factory.simgr()
# simgr.explore(find=lambda s: 'Good Job.' in s.posix.dumps(1))
# if simgr.found:
#     print(simgr.found[0].posix.dumps(0))

# # Invert complex_function for each character
# proj = angr.Project('08')
# state = proj.factory.blank_state()
# fun_addr = proj.loader.find_symbol('complex_function').rebased_addr
# complex_function = proj.factory.callable(fun_addr)
# buffer_val_start = claripy.BVS('buffer', 16*8)
# target = 'AUPDNNPROEZRJWKB'
# for (i,target_char) in enumerate(target):
#     print(i)
#     old_char = buffer_val_start.get_byte(i)
#     new_char = complex_function(old_char, 0xf-i)
#     state.add_constraints(new_char == claripy.BVV(ord(target_char),32),
#                           old_char > 0x40,
#                           old_char < 0x5b)
# print repr(state.solver.eval(buffer_val_start, cast_to=str))

# Invert complex_function for each character, exhausting concretely
proj = angr.Project('08')
fun_addr = proj.loader.find_symbol('complex_function').rebased_addr
state = proj.factory.blank_state(add_options=angr.options.unicorn)
complex_function = proj.factory.callable(fun_addr, concrete_only=True, base_state=state)
target = 'AUPDNNPROEZRJWKB'
result = ''
for (i,target_char) in enumerate(target):
    for old_char in range(256):
        new_char_bv = complex_function(old_char, 0xf-i)
        new_char = claripy.Solver().eval(new_char_bv,1)[0]
        if new_char == ord(target_char):
            result += chr(old_char)
            break
print result

import IPython
IPython.embed()
