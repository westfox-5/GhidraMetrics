#!/usr/bin/python3

from os import getenv, path
import getopt
import subprocess
import shlex
import sys

## PATHS
HOME = None
GHIDRA_HOME = None
PROJECT_NAME = "GhidraMetricsProject"

## COLORS
WARN = '\033[93m'
FAIL = '\033[91m'
ENDC = '\033[0m'


def print_help():
	print("Usage: analyze.py [INPUT] [ARGS] [OPTIONS]")
	print("  INPUT:")
	print("    -F <file>				executes the analysis for the provided file only")
	print("    -D <directory>			executes the analysis for all the files in the provided directory")
	print("  ARGS:")
	print("    -m --metric-name <name>		metric to compute")
	print("    -f --function-name <name>		compute analysis for the provided function")
	print("    -p --export-path <path>		saves the result in <path> file")
	print("    -e --export-type <type>		saves the result in <type> format (txt, json)")
	print("  OPTIONS:")
	print("    -h --help				show this help")

def print_err(msg):
	print(f"{FAIL}ERROR:{ENDC} {msg}")

def info(msg):
	print(f"{WARN}INFO:{ENDC} {msg}")

def validate(options):
	if options['input-file'] is None and options['input-dir'] is None:
		print_help()
		print_err("missing input file or directory")
		exit(1)
	
	if options['script-args']['metricName'] is None:
		print_help()
		print_err("missing metric name")
		exit(1)

	if options['script-args']['exportType'] is None:
		print_help()
		print_err("missing export type")
		exit(1)

def __exec(cmd):
	info(cmd)
	process = subprocess.Popen(shlex.split(cmd))
	process.wait()
	return process.returncode

'''
echo ">>> gcc -o $INPUT-DIR/$INPUT-FILE $INPUT-DIR/$INPUT-FILE.c"
gcc -o $INPUT-DIR/$INPUT-FILE $INPUT-DIR/$INPUT-FILE.c

echo ">>> $GHIDRA_HOME/support/analyzeHeadless $PRJLOC $PRJNAME \
-import $INPUT-DIR/$INPUT-FILE \
-postScript $SCRIPT_NAME $SCRIPT_ARGS \
$CUSTFLAGS"

$GHIDRA_HOME/support/analyzeHeadless $PRJLOC $PRJNAME \
-import $INPUT-DIR/$INPUT-FILE \
-postScript $SCRIPT_NAME $SCRIPT_ARGS \
$CUSTFLAGS
'''
def run(options):
	global HOME
	global GHIDRA_HOME
	global PROJECT_NAME

	cmd = f"rm -r {path.join(HOME, PROJECT_NAME)}"
	__exec(cmd)

	in_file = options['input-file']
	cmd = f"gcc -o {in_file} {in_file}.c"
	__exec(cmd)

	script_args = " ".join( f"{k}={v}" for k,v in options['script-args'].items() if v is not None)
	cmd = f"{path.join(GHIDRA_HOME, 'support', 'analyzeHeadless')} {HOME} {PROJECT_NAME} -import {in_file} -postScript GhidraMetricsScript {script_args} -deleteProject"	
	__exec(cmd)


	exit(1)




if __name__ == "__main__":
	GHIDRA_HOME = getenv("GHIDRA_HOME")
	if GHIDRA_HOME is None:
		print_err("GHIDRA_HOME not found in env.")
		exit(1)
	

	HOME = getenv("HOME")
	if HOME is None:
		print_err("HOME not found in env.")
		exit(1)

	PROJECT_LOC = path.join(HOME, "GhidraMetricsProject")
	
	args, remainder = None, None
	try:
		args, remainder = getopt.getopt(sys.argv[1:], 'F:D:m:f:e:p:h,', ["metric-name=", "function-name=", "export-path=", "export-type=", "help="])
	except Exception:
		print_help()
		print_err("Invalid argument")
		exit(1)
	
	options = {
		'input-file': None,
		'input-dir': None,
		'script-args': {
			'metricName': None,
			'functionName': None,
			'exportType': None,
			'exportPath': None,
		}
	}
	
	for opt, arg in args:
		if opt in ('-F'):
			options['input-file'] = arg
		elif opt in ('-D'):
			options['input-dir'] = arg
		elif opt in ('-m', '--metric-name'):
			options['script-args']['metricName'] = arg
		elif opt in ('-f', '--function-name'):
			options['script-args']['functionName'] = arg
		elif opt in ('-e', '--export-type'):
			options['script-args']['exportType'] = arg
		elif opt in ('-p', '--export-path'):
			options['script-args']['exportPath'] = arg
		elif opt in ('-h', '--help'):
			print_help()
			exit(0)

	validate(options)

	run(options)
