from scapy.all import *
import sys


def print_summary(pkt):
    if 'IP' in pkt:
        ip_src=pkt['IP'].src
        ip_dst=pkt['IP'].dst

        print(" IP src: " + str(ip_src))
        print(" IP dst: " + str(ip_dst))


if __name__ == "__main__":
    a = sniff(iface="en0", prn=print_summary)
    


""" hostName = socket.gethostname()
ip = socket.gethostbyname(hostName)
print(hostName)
print(ip) """









