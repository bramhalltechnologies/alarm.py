# Author: Harrison Bramhall
#   Skeleton Provided By: Ming Chow - Tufts University
# Date: 2/21/2022
# Description: Intro to Security Class - Project 4 Using Python and scapy, write a program named alarm.py
#   that provides user the option to analyze a live stream of network packets or a set of PCAPs for incidents.
#   Your tool shall be able to analyze for the following incidents:
#       - NULL scan
#       - FIN scan
#       - Xmas scan
#       - Usernames and passwords sent in-the-clear via HTTP Basic Authentication, FTP, and IMAP
#       - Nikto scan
#       - Someone scanning for Remote Desktop Protocol (RDP) protocol

#!/usr/bin/python3

from scapy.all import *
import argparse

def packetcallback(packet):
  try:
    # The following is an example of Scapy detecting HTTP traffic
    # Please remove this case in your actual lab implementation so it doesn't pollute the alerts
    if packet[TCP].dport == 80:
      print("HTTP (web) traffic detected!")
  except:
    pass

parser = argparse.ArgumentParser(description='A network sniffer that identifies basic vulnerabilities')
parser.add_argument('-i', dest='interface', help='Network interface to sniff on', default='eth0')
parser.add_argument('-r', dest='pcapfile', help='A PCAP file to read')
args = parser.parse_args()
if args.pcapfile:
  try:
    print("Reading PCAP file %(filename)s..." % {"filename" : args.pcapfile})
    sniff(offline=args.pcapfile, prn=packetcallback)    
  except:
    print("Sorry, something went wrong reading PCAP file %(filename)s!" % {"filename" : args.pcapfile})
else:
  print("Sniffing on %(interface)s... " % {"interface" : args.interface})
  try:
    sniff(iface=args.interface, prn=packetcallback)
  except:
    print("Sorry, can\'t read network traffic. Are you root?")