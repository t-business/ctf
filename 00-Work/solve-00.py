#!/usr/bin/env python

'''
This is an example that uses angr to assist in solving a crackme, given as
a 400-level crypto challenge in WhitehatCTF in 2015. In this example, angr is
used to reduce the keyspace, allowing for a reasonable brute-force.
'''

# lots of imports
import angr
import time

def main():
    # load the binary
    print '[*] loading the binary'
    p = angr.Project("00")

    # This block constructs the initial program state for analysis.
    # Because we're going to have to step deep into the C++ standard libraries
    # for this to work, we need to run everyone's initializers. The full_init_state
    # will do that. In order to do this peformantly, we will use the unicorn engine!
    state = p.factory.full_init_state(args=['./00'], add_options=angr.options.unicorn)

    # It's reasonably easy to tell from looking at the program in IDA that the key will
    # be 29 bytes long, and the last byte is a newline.


    # Construct a SimulationManager to perform symbolic execution.
    # Step until there is nothing left to be stepped.
    simgr = p.factory.simulation_manager(state)
    simgr.run()

    while simgr.active:
        # in order to save memory, we only keep the recent 20 deadended or
        # errored states
        simgr.run()
        print len(simgr.active)

    # Now take any deadended symbolic branch that has the string "Good Job." somewhere in the branch
    # and move it to a different stash called password. Once in the stash, dump the (1) stdout. If was (0), stdin.
    # If (2), stderr. Regardless, returns data as a flat string. The filter_func lambda is looking
    # for the match of the given string.
    simgr.move(from_stash='deadended', to_stash='password', filter_func=lambda s: 'Good Job.' in s.posix.dumps(1))

    # assert that there is actually members of the password stash or throw an exception. 
    assert simgr.password
    
    # To see how many deadends and password branches in each stash
    print simgr

    # Read the most recent entry in the password (in this case there was only one)
    # and remove the new line character.
    flag = simgr.password[-1].posix.dumps(0).split("\n")[0]
    return flag

    # import ipdb; ipdb.set_trace()

def test():
    flag = main()
    assert flag.startswith('hxp{1_h0p3_y0u_d1dnt_p33l_th3_0ni0n_by_h4nd}')

if __name__ == "__main__":
    print main()
