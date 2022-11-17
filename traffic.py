import sys
import getopt
import time
from os import popen
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import sendp, IP, UDP, Ether, TCP
from random import randrange
import random

def generateSourceIP():
    #removing invalid ip
    not_valid = [10, 127, 254, 1, 2, 169, 172, 192]

    first = randrange(1, 256)

    while first in not_valid:
        first = randrange(1, 256)
    
    #sending random ip
    ip = ".".join([str(first), str(randrange(1,256)), str(randrange(1,256)), str(randrange(1,256))])

    return ip

def generateDestinationIP(start, end):
    first = 10
    second = 0; 
    third = 0;

    ip = ".".join([str(first), str(second), str(third), str(randrange(start,end))])
    #sending random ip

    return ip

def main(argv):
    try:
        opts, args = getopt.getopt(sys.argv[1:], 's:e:', ['start=','end='])
    except getopt.GetoptError:
        sys.exit(2)

    for opt, arg in opts:
        if opt =='-s':
            start = int(arg)
        elif opt =='-e':
            end = int(arg)

    if start == '':
        sys.exit()
    if end == '':
        sys.exit()
    
    interface = popen('ifconfig | awk \'/eth0/ {print $1}\'').read()
    
    msgs=['welcome to pox','traffic examination','traffic control','congestion control','network secure','high traffic','low traffic','mild traffic','No flooding']
    #some msg simulation to be added to packets
    
    portSolns = [i for i in range(81, 7899)]

    for i in range(1000):
        packets = Ether() / IP(dst = generateDestinationIP(start, end), src = generateSourceIP()) / UDP(dport = random.choice(portSolns), sport = 2) / msgs[randrange(-1,9)]
        print(repr(packets))

        sendp(packets, iface = interface.rstrip(), inter = 0.1)

if __name__ == '__main__':
  main(sys.argv)
