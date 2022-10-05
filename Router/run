#!/usr/bin/env python3 

import atexit
import sys
import os
import time
import json
import random
import select
import signal
import socket
import subprocess
import struct
from functools import reduce
from collections import defaultdict

def die(msg):
  raise ValueError("Error: %s" % msg)

start = time.time()

def log(caller, msg):
  print("[%02.4f  %17s]: %s" % (time.time() - start, caller, msg))

#### PARAMETERS

EXECUTABLE_NAME = "3700router"

def get_config(config_file):
  # Load config file
  if not os.path.exists(config_file):
    die("Could not find config file '%s'" % config_file)

  try:
    with open(config_file) as f:
      config_data = f.read()
  except Exception as e:
    die("Unable to read data from config file '%s': %s" % (config_file, e))

  try:
    config = json.loads(config_data)
  except Exception as e:
    die("Unable to parse JSON in config file '%s': %s" % (config_file, e))

  return config

def get_executable():
  if not os.path.exists(EXECUTABLE_NAME):
    die("Could not find bridge program '%s'" % EXECUTABLE_NAME)

  if not os.access(EXECUTABLE_NAME, os.X_OK):
    die("Could not execute bridge program '%s'" % EXECUTABLE_NAME)

#### EVENT CODE

EVENTS = []

class Event:
  def __init__(self, time, func):
    self.time = time
    self.func = func

  def __str__(self):
    return "{ event at time: %.4f }" % (self.time)

  def execute(self):
    self.func()


def add_event(time, func):
  global EVENTS
  EVENTS.append(Event(time, func))
  EVENTS = sorted(EVENTS, key=lambda e: -1 * e.time)

def add_final_event(func):
  global EVENTS
  EVENTS.append(Event(EVENTS[0].time + 1, func))
  EVENTS = sorted(EVENTS, key=lambda e: -1 * e.time)

def next_event_time():
  global EVENTS
  return EVENTS[len(EVENTS)-1].time

def next_event_pop():
  global EVENTS
  return EVENTS.pop()

#### FD WRAPPER

class FDWrapper:
  def __init__(self, fd, parent):
    self.fd = fd
    self.parent = parent

  def fileno(self):
    return self.fd.fileno()

#### IP HELPER FUNCTIONS

def parse_ubyte(var):
  """ parse_byte : string -> int
      Helper Method that coerces the given string into an int and asserts it
      fits into one unsigned byte
  """
  val = int(var)
  if val < 0 or val > 255:
    raise ValueError("{} is outside range for byte".format(val))
  return val

def ip_quads(ipaddr):
  """ Split the given ipaddr into its quads """
  quads = str(ipaddr).split('.')
  if len(quads) != 4:
    raise ValueError("Not a proper quad: {}".format(ipaddr))
  return list(parse_ubyte(qdn) for qdn in quads)

def validate_ip(ipaddr):
  """ check that the given string is a valid ip address """
  try:
    ip_quads(ipaddr)
    return True
  except ValueError:
    return False

def validate_netmask(ipaddr):
  """ check that the given string is a valid netmask """
  if not validate_ip(ipaddr):
    return False
  ip_val = ip_aton(ipaddr)
  # Binary form should be 1{k}0{m}
  while ip_val % 2 == 0: # Strip Consecutive Zeros
    ip_val = ip_val >> 1
  while ip_val % 2 == 1: # Strip Consecutive Ones
    ip_val = ip_val >> 1
  return ip_val == 0 # Should be zero

def quads_to_str(quads):
  """ convert the given tuple to a dotted quad string """
  if len(quads) != 4:
    raise ValueError("Not given a proper quads! (Should be 4-tuple)")
  return "{}.{}.{}.{}".format(quads[0], quads[1], quads[2], quads[3])

def ip_change_quad(addr, posn, val):
  """ ip_change_quad: str x int x int -> str
      Helper method that changes the given quad in the given address to the
      given value
  """
  if not isinstance(posn, int):
    raise ValueError("Argument 'posn' to ip_change_quad must be an int")
  if posn < 0 or posn > 3:
    raise ValueError("Argument 'posn' to ip_change_quad must be in the range [0,3]")
  if not isinstance(val, int):
    raise ValueError("Argument 'val' to ip_change_quad must be an int")
  if val < 0 or val > 255:
    raise ValueError("Argument 'val' to ip_change_quad must be in the range [0,255]")

  quads = ip_quads(addr)
  quads[posn] = val
  return quads_to_str(quads)

def ip_aton(ipa):
  return struct.unpack(">I", socket.inet_aton(ipa))[0]

def ip_ntoa(ipa):
  return socket.inet_ntoa(struct.pack(">I", ipa))

def matches(network, netmask, ip):
  network = ip_aton(network)
  netmask = ip_aton(netmask)
  ip = ip_aton(ip)

  return (network & netmask) == (ip & netmask)

#### ROUTER CODE

ERRORS = []

def _cleanup_proc(p):
  if p.poll() is None:
    p.kill()

class PeerRouter:
  def __init__(self, network, netmask, peer_type, asn):
    self.network = network
    self.netmask = netmask
    self.ip = ip_change_quad(self.network, 3, 2)
    self.peer_type = peer_type
    self.asn = asn

    self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    self.socket.bind(('localhost', 0))

    self.port = self.socket.getsockname()[1]
    self.remote_port = None

    self.messages = []
    self.received = []

    self.read_count = 0

    self.table = None

  def get_fds(self):
    return [FDWrapper(self.socket, self)]

  def get_command_line_arg(self):
    return "%s-%s-%s" % (self.port, self.ip, self.peer_type)

  def was_announced(self, ip):
    nets = {}
    for m in self.messages:
      if m["type"] == "update":
        key = (m["msg"]["network"], m["msg"]["netmask"])
        nets[key] = m

      if m["type"] == "withdraw":
        for record in m["msg"]:
          key = (record["network"], record["netmask"])
          del nets[key]

    for network, netmask in nets.keys():
      if matches(network, netmask, ip):
        return True

    return False

  def read(self, fd):
    data, addr = fd.fd.recvfrom(65535)
    msg = json.loads(data.decode('utf-8'))
    log("Peer %s" % self.ip, "Read '%s'" % data.decode('utf-8'))
    
    if not self.remote_port:
      self.remote_port = addr[1]

    if msg["type"] == "data":
      if not self.was_announced(msg["dst"]):
        add_error(now(), "ERROR: Peer %s received message %s destined for a different network" % (self.ip, data.decode('utf-8')))
      else:
        self.read_count += 1

    if msg["type"] == "table":
      self.table = msg["msg"]

    if msg["type"] == "update" or msg["type"] == "withdraw":
      self.received.append(msg)

  def send(self, data):
    if not self.remote_port:
      raise ValueError("Cannot send on un-initialized PeerRouter!")
    log("Peer %s" % self.ip, "Sent '%s'" % data)
    self.socket.sendto(json.dumps(data).encode('utf-8'), ('localhost', self.remote_port))

    if data["type"] == "update" or data["type"] == "withdraw":
      self.messages.append(data)

  def get_hosts(self):
    networks = {}

    for msg in self.messages:
      if msg["type"] == "update":
        key = (msg["msg"]["network"], msg["msg"]["netmask"])
        networks[key] = msg
      elif msg["type"] == "withdraw":
        for record in msg["msg"]:
          key = (record["network"], record["netmask"])
          del networks[key]

    return networks

class StudentRouter:
  def __init__(self, asn, peers):
    self.asn = asn
    self.peers = peers

    self.process = None

  def __str__(self):
    return self.id

  def is_started(self):
    return self.process is not None

  def start(self):
    args = "%s %s %s" % (os.path.join(".", EXECUTABLE_NAME), self.asn, " ".join(map(lambda peer: peer.get_command_line_arg(), self.peers)))
    log("Simulator", "Starting router at AS %s with command '%s'" % (self.asn, args))
    self.process = subprocess.Popen(args,
                                    shell=True,
                                    stdin=subprocess.PIPE,
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE,
                                    preexec_fn=os.setsid)

    def make_non_blocking(fd):
      try:
        from fcntl import fcntl, F_GETFL, F_SETFL
        flags = fcntl(fd, F_GETFL) # get current p.stdout flags
        fcntl(fd, F_SETFL, flags | os.O_NONBLOCK)
      except ImportError:
        print("Warning:  Unable to load fcntl module; things may not work as expected.")

    make_non_blocking(self.process.stdout)
    make_non_blocking(self.process.stderr)

    atexit.register(self.stop)

  def stop(self):
    if self.process and self.process.poll() is None:
      os.killpg(os.getpgid(self.process.pid), signal.SIGTERM)
    self.process = None

  def get_fds(self):
    if self.process:
      return [FDWrapper(self.process.stdout, self), FDWrapper(self.process.stderr, self)]
    else:
      return []

  def read(self, fd):
    data = fd.fd.read(1500).decode('utf-8')
    if self.process.returncode is not None or len(data) == 0:
      die("Router crashed; exiting")

    for line in data.strip().split("\n"):
      log("Router", line)

def create_peer(peer):
  return PeerRouter(peer["network"], peer["netmask"], peer["type"], peer["AS"])

def create_router(router_data):
  peers = list(map(lambda peer: create_peer(peer), router_data["networks"]))
  router = StudentRouter(router_data["asn"], peers)

  add_event(0, lambda: router.start())

  return router

def add_error(ts, message):
  log("Simulator", message)
  ERRORS.append("At timestamp %s, %s" % (ts, message))

#### MESSAGES

class Message:
  def __init__(self, ts, data, router):
    self.ts = ts
    self.data = data
    self.router = router

    add_event(self.ts, self)

  def __call__(self):
    if self.data["type"] == "msg":
      src = self.data["msg"]["src"]
      for peer in router.peers:
        if peer.ip == src:
          peer.send(self.data["msg"])
          break

      def check_announcements():
        expected = self.data["expected"]

        errors = False
        for peer in self.router.peers:
          if peer.ip in expected:
            for msg in expected[peer.ip]:
              if msg not in peer.received:
                add_error(self.ts, "Peer %s did not receive expected route announcement %s" % (peer.ip, msg))
                errors = True

          for msg in peer.received:
            if peer.ip not in expected or msg not in expected[peer.ip]:
              add_error(self.ts, "Peer %s received unexpected route announcement %s" % (peer.ip, msg))
              errors = True

        if not errors:
          log("Simulator", "All expected annoucements forwarded")
#        else:
#          log("Simulator", "Expected forwarded annoucements %s, observed %s" % (json.dumps(expected), json.dumps(dict(map(lambda p: (p.ip, p.received), self.router.peers)))))

        for peer in self.router.peers:
          peer.received = []

      add_event(self.ts + 0.25, check_announcements)
    elif self.data["type"] == "data":
      for speer in self.router.peers:
        for snetwork, snetmask in speer.get_hosts():
          for dpeer in self.router.peers:
            if speer != dpeer:
              for dnetwork, dnetmask in dpeer.get_hosts():
                shost = ip_change_quad(snetwork, 3, 25)
                dhost = ip_change_quad(dnetwork, 3, 25)

                log("Simulator", "Sending data from %s to %s" % (dhost, shost))
                dpeer.send({"src": dhost, "dst": shost, "type": "data", "msg": { "ignore": "this" }})

      def check_data():
        errors = False
        for peer in self.router.peers:
          peer_count = peer.read_count
          expected_count = self.data["expected"][peer.ip] if peer.ip in self.data["expected"] else 0

          if peer_count != expected_count:
            errors = True
            add_error(self.ts, "ERROR: Peer %s expected to receive %d messages, but actually received %d" % (peer.ip, expected_count, peer_count))

        if not errors:
            log("Simulator", "All data message counts correct")
#        else:
#            log("Simulator", "Expected peer counts %s" % (json.dumps(dict(map(lambda p: (p.ip, p.read_count), self.router.peers)))))

        # Reset read count
        for peer in self.router.peers:
          peer.read_count = 0

      add_event(self.ts + 0.25, check_data)
    elif self.data["type"] == "dump":
      src = self.router.peers[0].ip
      dst = ip_change_quad(self.router.peers[0].ip, 3, 1)
      self.router.peers[0].send({"src": src, "dst": dst, "type": "dump", "msg": {}})

      def check_table():
        table = self.router.peers[0].table

        if table is None:
          add_error(self.ts, "ERROR: No routing table received in response to dump message")
          return

        errors = False

        for troute in table:
          hit = False
          for eroute in self.data["expected"]:
            if troute == eroute:
              hit = True

          if not hit:
            errors = True
            add_error(self.ts, "ERROR: Found unexpected route '%s' in table message" % troute)

        for eroute in self.data["expected"]:
          hit = False
          for troute in self.router.peers[0].table:
            if troute == eroute:
              hit = True

          if not hit:
            errors = True
            add_error(self.ts, "ERROR: Did not find expected route '%s' in table message" % eroute)

        if not errors:
          log("Simulator", "Routing table correct")
#        else:
#          log("Simulator", "Expected table %s, received table %s" % (json.dumps(self.data["expected"]), json.dumps(router.peers[0].table)))

      add_event(self.ts + 0.25, check_table)

#### MAIN PROGRAM

if len(sys.argv) != 2:
  die("Usage: ./run config-file")

get_executable()
config = get_config(sys.argv[1])

if "seed" in config:
  random.seed(config["seed"])

# Set up the bridges, get LAN info
router = create_router(config)

def send_message(message):
  log("Simulator", message)

# Set up the messages
ts = 2
for message in config["messages"]:
  Message(ts, message, router)
  ts += 1

def now():
  return time.time() - start

done = False
def finish():
  if len(ERRORS) == 0:
    log("Simulator", "Simulation complete. No errors detected; congratulations!")
  else:
    log("Simulator", "Simulation complete. Errors detected\n\n%s" % "\n".join(ERRORS))

  sys.exit(0)

add_final_event(finish)

try:
  while not done:
    time_to_event = next_event_time() - now()

    if time_to_event > 0:
      router_fds = router.get_fds()
      peer_fds = list(reduce(lambda a, b: a + b.get_fds(), router.peers, []))
      readable, _, exceptable = select.select(router_fds + peer_fds, [], router_fds + peer_fds, time_to_event)

      # handle any data
      for fd in readable:
        fd.parent.read(fd)

      # handle any exceptions
      for fd in exceptable:
        fd.parent.exception(fd)

    time_to_event = next_event_time() - now()
    if time_to_event <= 0:
      next_event_pop().execute()
except ValueError as e:
  print(e)
