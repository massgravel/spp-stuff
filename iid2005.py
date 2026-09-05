#!/usr/bin/env python

import hashlib

IID_KEY = bytes([
    0x6B, 0xC8, 0x5E, 0xD4, 0xF0, 0xF8, 0xD8, 0x84,
    0x77, 0x41, 0x2A, 0x2F, 0x7D, 0x93, 0x13, 0xF4, 
    0x1B, 0x8A, 0x66, 0xE6, 0xA2, 0x15, 0x95, 0xBB, 
    0x0E, 0x9D, 0xB0, 0x67, 0x83, 0x32, 0x2B, 0x97, 
    0x49, 0xFE, 0xD9, 0xCD, 0x7C, 0x7D, 0xDC, 0xEE, 
    0xB0, 0x07, 0x12, 0xDF, 0xE7, 0x0B, 0x3B, 0xEB, 
    0x56, 0xBD, 0x98, 0xDF, 0xFD, 0x27, 0xA6, 0xCF, 
    0x5D, 0x84, 0x36, 0xC2, 0xF8, 0x73, 0x3A, 0x57
])

def decrypt(encrypted, key):
    size_half = len(encrypted) // 2
    size_half_dwords = size_half - (size_half % 4)
    last = encrypted[size_half*2:]
    encrypted = encrypted[:size_half*2]

    for i in range(16):
        first = encrypted[:size_half]
        second = encrypted[size_half:]
        sha1_result = hashlib.sha1(b"\x79" + first + key[0x3c - 4*i:0x40 - 4*i]).digest()
        sha1_result = sha1_result[:size_half_dwords] + sha1_result[size_half_dwords+4-(size_half%4) : size_half+4-(size_half%4)]
        encrypted = bytes(x^y for x,y in zip(second, sha1_result)) + first

    return encrypted + last

def encrypt(decrypted, key):
    size_half = len(decrypted) // 2
    size_half_dwords = size_half - (size_half % 4)
    last = decrypted[size_half*2:]
    decrypted = decrypted[:size_half*2]

    for i in range(16):
        first = decrypted[:size_half]
        second = decrypted[size_half:]
        sha1_result = hashlib.sha1(b"\x79" + second + key[4*i:4*i + 4]).digest()
        sha1_result = sha1_result[:size_half_dwords] + sha1_result[size_half_dwords+4-(size_half%4) : size_half+4-(size_half%4)]
        decrypted = second + bytes(x^y for x,y in zip(first, sha1_result))

    return decrypted + last

def add_cksum(n, dashes=False):
    cksums = []
    n = str(n).zfill(45)
    parts = [n[i:i+5] for i in range(0, len(n), 5)]

    for p in parts:
        cksum = 0
    
        for i, k in enumerate(map(int, p)):
            cksum += k * (i % 2 + 1)
    
        cksums.append(str(cksum % 7))

    n_out = ""

    for i in range(9):
        n_out += parts[i] + cksums[i] + ("-" if i != 8 and dashes else "")

    return n_out

def validate_cksum(n):
    n = n.replace("-", "")
    parts = [n[i:i+6] for i in range(0, len(n), 6)]

    for p in parts:
        cksum = 0
    
        for i, k in enumerate(map(int, p[:-1])):
            cksum += k * (i % 2 + 1)
    
        cksum %= 7
    
        if int(p[-1]) != cksum:
            return None

    n_out = "".join([p[:-1] for p in parts])

    return int(n_out)

def decode_iid(iid):
    iid_enc = validate_cksum(iid)

    if iid_enc is None:
        raise Exception("Invalid checksum")

    iid_enc_bytes = iid_enc.to_bytes(19, "little")
    iid_raw_bytes = decrypt(iid_enc_bytes, IID_KEY)
    iid_raw = int.from_bytes(iid_raw_bytes, "little")
    
    upgrade = int((iid_raw >> 8) & 1)
    serial = (iid_raw >> 9) & ((1 << 30) - 1)
    group = (iid_raw >> 49) & ((1 << 10) - 1)
    security = (iid_raw >> 39) & ((1 << 10) - 1)
    hwid_short = (iid_raw >> 64) & ((1 << 64) - 1)

    return hwid_short, security, group, serial, upgrade

def encode_iid(hwid_short, group, serial, security, upgrade):
    iid_raw = 1
    iid_raw |= ((upgrade & 1) << 8)
    iid_raw |= ((serial & ((1 << 30) - 1)) << 9)
    iid_raw |= ((security & ((1 << 10) - 1)) << 39)
    iid_raw |= ((group & ((1 << 10) - 1)) << 49)
    iid_raw |= ((hwid_short & ((1 << 64) - 1)) << 64)
    
    iid_raw_bytes = iid_raw.to_bytes(19, "little")
    iid_enc_bytes = encrypt(iid_raw_bytes, IID_KEY)
    iid_enc = int.from_bytes(iid_enc_bytes, "little")
    
    return add_cksum(iid_enc)

def get_shortauth(security, group, serial, upgrade):
    shortauth = (upgrade & 1)
    shortauth |= ((serial & ((1 << 30) - 1)) << 1)
    shortauth |= ((security & ((1 << 10) - 1)) << 31)
    shortauth |= ((group & ((1 << 10) - 1)) << 41)
    
    return shortauth.to_bytes(8, "little")

if __name__ == '__main__':

    import argparse

    p = argparse.ArgumentParser(
        'iid',
        description='pkey2005 IID decoder/encoder',
        allow_abbrev=True
    )

    sp = p.add_subparsers(title='Commands', dest='mode')
    enc_p = sp.add_parser('encode')
    enc_p.add_argument('hwid',     type=lambda i: int(i,0), help='Hardware ID')
    enc_p.add_argument('group',    type=lambda i: int(i,0), help='Group reference ID')
    enc_p.add_argument('serial',   type=lambda i: int(i,0), help='Serial number')
    enc_p.add_argument('security', type=lambda i: int(i,0), help='Security value')
    enc_p.add_argument('-u',       type=lambda i: int(i,0), help='Upgrade bit', dest='upgrade', default=0)

    dec_p = sp.add_parser('decode')
    dec_p.add_argument('iid', type=str)

    arg = p.parse_args()

    match arg.mode:
        case 'decode':
            hwid, security, group, serial, upgrade = decode_iid(arg.iid)

            print('\nIID      : [%s]\n' % (str(arg.iid)))
            print('            0xffffffffffffffff')
            print('HWID     : [0x%016x]\n' % hwid)
            print('            0x3ff')
            print('Group    : [0x%03x]\n' % group)
            print('            0x3fffffff')
            print('Serial   : [0x%08x]\n' % serial)
            print('            0x3ff')
            print('Security : [0x%03x]\n' % security)
            print('            0x1')
            print('Upgrade  : [0x%01x]\n' % upgrade)

        case 'encode':
            iid = encode_iid(arg.hwid, arg.group, arg.serial, arg.security, arg.upgrade)
            print(iid)

        case _:
            p.print_help()
