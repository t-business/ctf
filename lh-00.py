#!/usr/bin/env python
import os
import angr
import logging
from hashlib import md5
import time
import multiprocessing as mp
import argparse, shlex

root_logger = logging.getLogger()
root_logger.setLevel(logging.WARNING)
logger = logging.getLogger(name=__name__)

def _set_log_level(level):
        #interpret specified level
        if not hasattr(logging,level):
                logger.error("Invalid log level specified: %s", level)
                logger.error("Using INFO.")
                level = "INFO"
        #set the level
        logger.setLevel(getattr(logging,level))

def main(command, corpus, testcase, ld_path):
	# Start a timer for comparison
	before = time.time()    

	# load the binary
	print '[*] loading the binary'
	p = angr.Project("00")

	# This block constructs the initial program state for analysis.
	s = p.factory.full_init_state()

	# Construct a SimulationManager to perform symbolic execution.
	simgr = p.factory.simulation_manager(s)

	while simgr.active:
		import IPython
		for s in simgr.active:
			addrs=s.addr


	# Print the number of branches
	print simgr


	# End time
	after = time.time()
	print "Time elapsed: {}".format(after - before)



if __name__ == "__main__":
	parser = argparse.ArgumentParser('lh-00.py', 
		description="Testing output for lighthouse.")

	parser.add_argument("-v", "--log-level", default="INFO", 
		help="Set the log level.", dest="level",
		choices=["DEBUG","INFO","WARNING","ERROR","CRITICAL"])
	
	parser.add_argument("-l", "--ld-path")
	
	parser.add_argument("-i", "--input-file", required=False)
	
	parser.add_argument("-o", "--corpus", default="/home/ctf/corpus")

	parser.add_argument("command", nargs=argparse.REMAINDER)

	args=parser.parse_args()

	_set_log_level(args.level)

	main(
		args.command, 
		args.corpus, 
		args.input_file,
		args.ld_path
)
