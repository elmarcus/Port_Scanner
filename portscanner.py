import sys
import optparse
import os
import subprocess
import logging
import socket
import struct

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from scapy.layers.inet import IP, ICMP, TCP, UDP


class Main(object):

    host = None
    port = None
    udp = False
    results = {}

    def __init__(self):
        self.parse_options()
        self.run()
        self.host = None
        self.port = None
        self.filename = None
        self.results = {}

    def parse_options(self):
        parser = optparse.OptionParser(usage="%prog [options]",
                                       version="%prog 0.1")

        #parse option for declaring the host, if host is not declared through any method, then program exits
        parser.add_option("-o", "--host", type="str", dest="host", default="-1")

        #parse option for declaring port or range of ports, if port is not declared, then program uses most popular ports
        #as default
        parser.add_option("-p", "--port", type="str", dest="port", default = "-1")

        #performed UDP scan along side normal TCP scan
        parser.add_option("-u", "--UDP", action="store_true", dest="UDP")

        (options, args) = parser.parse_args()

        self.host = options.host
        self.port = options.port
        self.udp = options.UDP

    def run(self):

        hosts = self.parse_host(self.host)
        ports = self.parse_port()

        #check if host is up
        for ip in hosts:

            #check if ip address is active via ping sweep
            if self.check_ip(ip):
                open_ports = []

                #for each port specified, scan each port
                for port in ports:

                    #perform TCP scan
                    tcp = self.scan_port_TCP(ip, port)

                    #if scan returned results, add them to output list
                    if tcp:
                        open_ports.append(tcp)

                    #if udp flag activated, perform UDP scan on port
                    if self.udp:
                        udp = self.scan_port_UDP(ip, port)

                        #if sccan returned results, add results to output list
                        if udp:
                            open_ports.extend(udp)

                self.results[ip] = open_ports

        #print results to terminal
        self.output_results()

    def parse_host(self, host):
        hosts = []

        #if no host was specified, exit program
        if host == "-1":
            sys.exit(0)

        #check if host is a file name, if yes, read in file
        if os.path.isfile(host):
            hosts = self.read_host_file()

        #check if host is a range of hosts
        elif("-" in host):
            #parse range of hosts
            print host
            hosts=self.parse_host_range(host)

        #check if host is a subnet mask
        elif('/' in host):
            hosts = self.parse_host_mask(host)

        #else, add host to the hostlist
        else:
            hosts.append(host)

        return hosts

    def parse_host_range(self, host):
        range = host.split("-")

        #if range of hosts is improperly configured
        if len(range) != 2:
            return range[0]

        #split range into 4 segements
        min_host = range[0].split(".")
        max_host = range[1].split(".")

        ports = []

        i = int(min_host[3])

        #while iterator is less than the max host, increment IP address
        while( i < int(max_host[3]) + 1):
            ports.append(min_host[0] + "." + min_host[1] + "." + min_host[2] + "." + str(i))
            i = i + 1

        return ports

    def parse_host_mask(self, host):
        hosts = []

        #split inputed host into network ip address and net mask bits
        network, net_bits = host.split('/')
        host_bits = 32 - int(net_bits)
        netmask = socket.inet_ntoa(struct.pack('!I', (1 << 32) - (1 << host_bits)))

        # f_seg =255 -int(netmask.split('.')[0])
        # s_seg =255 -int(netmask.split('.')[1])
        # t_seg = 255 -int(netmask.split('.')[2])

        #find remainder of fourth segement to increment
        fo_seg =255 - int(netmask.split('.')[3])

        #split the network ip address into 4 segments
        network_split = network.split(".")

        #for each address from 0 to exent of ip mask
        for i in range(0, fo_seg + 1):
            hosts.append(network_split[0]+"."+network_split[1] + "." + network_split[2] + "." +str(i))

        return hosts

    def read_host_file(self):
        file_hosts = []
        hosts =[]
        with open(self.host, 'rb') as f:
            #for every line in the file, append it to the hosts and strip the newline character
            for line in f:
                file_hosts.append(line.strip())

        #parse hosts found in file and add them to the output list
        for h in file_hosts:
            hosts.extend(self.parse_host(h))


        return hosts

    def parse_port(self):
        ports = []

        #if no ports a specified, then scan popular ports
        if(self.port == "-1"):
            ports = ["21","22","23","25","53","80", "443", "110", "135", "137", "136", "138", "1433"]
        else:

            #split ports by comma's if present
            portlist = self.port.split(",")

            for p in portlist:
                #extend the output port list by the parsed range of ports
                if("-" in p):
                    ports.extend(self.parse_port_range(p))
                #add port to the output list
                else:
                    ports.append(p)

        return ports

    def parse_port_range(self, port_range):

        ports = []
        #split range of ports into minimum port and maximum port
        range = port_range.split("-")

        min_port = int(range[0])
        max_port = int(range[1])


        #while minimum port is less than maximum port, increment minimum port and add it to output list
        while min_port != max_port + 1:
            ports.append(str(min_port))
            min_port= min_port + 1

        return ports

    def check_ip(self, ip):
        conf.verb = 0

        #perform ping on ip address, if ping takes longer than 2 seconds, timeout and report ping as failed
        ping = sr1(IP(dst = ip, ttl=20)/ICMP(), timeout=1)

        #if ping returns information, then port is up
        if ping != None:
            print str(ip) + " IS UP, COMMENCING SCAN"
            return True

        #if ping times out, return false
        else:
            print str(ip) + " IS DOWN, SKIPPING"
            return False

    def scan_port_TCP(self,ip, port):

        conf.verb = 0
        SYNACK = 0x12
        RST = 0x14
        src_port = RandShort()
        des_port = int(port)

        open_ports = []

        #send TCP packet to ip address on specified port, if response takes longer than 10 seconds, time out
        response = sr1(IP(dst = ip)/
                       TCP(sport = src_port, dport=des_port, flags="S"), timeout = 10)

        #if response times out. return false
        if(response == None):
            return None
        #if response contains TCP packet
        elif(response.haslayer(TCP)):
            #if response packet returns SYNACK flag, send ACKRST flag in response and return the port as open
            if(response.getlayer(TCP).flags == SYNACK):
                sr(IP(dst=ip) / TCP(sport=src_port, dport=des_port, flags="AR"), timeout=10)
                return str(des_port) + "/tcp"
            #if packet returned contains RST flag, then return the port as closed
            elif(response.getlayer(TCP).flags == RST):
                return None

    def scan_port_UDP(self, ip, port):

        des_port = int(port)

        #send udp packet to the specified IP address and port number
        response = sr1(IP(dst=ip)/UDP(dport=des_port), timeout=10)

        #if response times out, return closed
        if(response == None):
            return None
        #if reponse contains UDP packet, return port as open
        elif(response.haslayer(UDP)):
            return port + "/UDP"
        # if response contains ICMP layer
        elif(response.haslayer(ICMP)):
            #if ICMP layer contains code 3, return port as closed
            if response.getlayer(ICMP).type == "3" and response.getlayer(ICMP).code == "3":
                return None
            #if ICMP layer contains alternate codes, return port as filtered
            elif response.getlayer(ICMP).type == "3" and response.getlayer(ICMP).code in ["1","2","9","10","13"]:
                return port +"/UDP FILTERED"

    def output_results(self):
        #for each IP address in result dictionary, print ip address
        for k in self.results.keys():
            print k
            #for each ip address, print open ports
            for v in self.results[k]:
                print '\t' + v

if __name__ == '__main__':
    m = Main()