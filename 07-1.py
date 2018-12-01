#!/usr/bin/env python

'''
This is an example that uses angr to assist in solving a crackme, given as
a 400-level crypto challenge in WhitehatCTF in 2015. In this example, angr is
used to reduce the keyspace, allowing for a reasonable brute-force.
'''

# lots of imports
import angr
import time
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def main():
    # Start a timer for comparison
    before = time.time()    

    # load the binary
    print '[*] loading the binary'
    p = angr.Project("07")

    # This block constructs the initial program state for analysis.
    # Because we're going to have to step deep into the C++ standard libraries
    # for this to work, we need to run everyone's initializers. The entry_state
    # will do that. In order to do this peformantly.
    state = p.factory.entry_state()

    # It's reasonably easy to tell from looking at the program in IDA that the key will
    # be 29 bytes long, and the last byte is a newline.


    # Construct a SimulationManager to perform symbolic execution.
    # Step until there is nothing left to be stepped.
    simgr = p.factory.simulation_manager(state, veritesting = True)
    simgr.run()

    while simgr.active:
        # in order to save memory, we only keep the recent 20 deadended or
        # errored states
        simgr.run()
        print len(simgr.active)

    simgr.move(from_stash='deadended', to_stash='password', filter_func=lambda s: 'Good Job.' in s.posix.dumps(1))

    # Print the number of branches
    print simgr

    assert simgr.deadended
    flag = simgr.password[-1].posix.dumps(0).split("\n")[0]

    # End time
    after = time.time()
    print "Time elapsed: {}".format(after - before)

    return flag

    # import ipdb; ipdb.set_trace()

if __name__ == "__main__":
    print main()
