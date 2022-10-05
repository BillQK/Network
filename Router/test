#!/usr/bin/env python3

import os
import subprocess
import sys
import re

EXECUTABLE_NAME = "3700router"
RUN_SCRIPT_NAME = "run"
CONFIG_DIR = "configs"

def die(message):
  print("ERROR: %s" % message)
  sys.exit(-1)

def get_files():
  if not os.path.exists(EXECUTABLE_NAME):
    die("Could not find bridge program '%s'" % EXECUTABLE_NAME)

  if not os.access(EXECUTABLE_NAME, os.X_OK):
    die("Could not execute bridge program '%s'" % EXECUTABLE_NAME)

  if not os.path.exists(RUN_SCRIPT_NAME):
    die("Could not find simulator '%s'" % EXECUTABLE_NAME)

  if not os.access(RUN_SCRIPT_NAME, os.X_OK):
    die("Could not execute simulator '%s'" % RUN_SCRIPT_NAME)


get_files()

def runTest(config):
  print("%s" % ("Test: %s" % (config)).ljust(60, ' '), end='')

  result = subprocess.check_output([os.path.join(os.getcwd(), RUN_SCRIPT_NAME), os.path.join(CONFIG_DIR, config)]).decode('utf-8')
  
  pattern = re.compile("Simulation complete. Errors detected\n\n(.*)", re.DOTALL)
  m = re.search(pattern, result)
  if m:
    print("[FAIL]\n%s" % m.group(1))
  else:
    pattern = re.compile("Simulation complete. No errors detected; congratulations", re.DOTALL)
    if re.search(pattern, result):
      print("[PASS]")
    else:
      print("[FAIL]\n%s" % result)

print("Milestone tests")
runTest("1-1-simple-send.conf")
runTest("1-2-simple-send.conf")

print("\nFinal tests")
runTest("2-1-loop-select-hpref.conf")
runTest("2-2-loop-select-sorg.conf")
runTest("2-3-loop-select-aspath.conf")
runTest("2-4-loop-select-orig.conf")
runTest("2-5-loop-select-ip.conf")
runTest("3-1-simple-revoke.conf")
runTest("3-2-bad-route.conf")
runTest("4-1-peering.conf")
runTest("4-2-provider.conf")
runTest("4-3-provider-peer.conf")
runTest("5-1-provider-default-route.conf")
runTest("5-2-longest-prefix.conf")
runTest("6-1-coalesce-simple.conf")
runTest("6-2-coalesce-complex.conf")
runTest("6-3-disaggregate.conf")
