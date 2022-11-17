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
    #removing some non valid ip
    not_valid = [10, 127, 254, 1, 2, 169, 172, 192]

    #selects a random number in the range [1,256)
    first = randrange(1, 256)

    while first in not_valid:
        first = randrange(1, 256)
    
    ip = ".".join([str(first), str(randrange(1,256)), str(randrange(1,256)), str(randrange(1,256))])
    #sending random ip

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
	   
    #getting interface to pump
    interface = popen('ifconfig | awk \'/eth0/ {print $1}\'').read()

    max_time_interval = 0.1 #1/10
    min_time_interval = 0.04 #1/50
    
    portSolns = [i for i in range(81, 7899)]
    
    msgs=['welcome to pox','attack examination','attack control','congestion control','network secure','severe attack','mild atack','less severe traffic','flooding','Emergency message']
    #some msg simulation to be sent with packet
    
    for j in range(0,3):
        for i in range(300):
            packets = Ether() / IP(dst = generateDestinationIP(start,end), src = generateSourceIP()) / UDP(dport = random.choice(portSolns),sport = 2) / msgs[randrange(-1,10)]
            print(repr(packets))
            interval = min(max_time_interval, min_time_interval *(2**j))
            sendp(packets, iface = interface.rstrip(), inter = float(interval), count = 10)
            

if __name__ == '__main__':
  main(sys.argv)
