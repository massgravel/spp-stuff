#!/usr/bin/env python3

import struct
import sys
import os
import hashlib

TOKENS_VERSION = 3

BLOCK_SIZE = 16384
ENTRY_SIZE = 158
MAX_ENTRIES = (BLOCK_SIZE - 8) // ENTRY_SIZE

ENTRY_CONTENTS_HEADER = b'\x55' * 32
ENTRY_CONTENTS_FOOTER = b'\xAA' * 32

def parse_entry(f, offset):
    f.seek(offset)
    unpacked = struct.unpack('<lllll', f.read(20))

    if unpacked[0] != offset or unpacked[1] == 0 or unpacked[2] == 0:
        return None

    (name_b, ext_b) = struct.unpack('<130s8s', f.read(138))

    name = (
        name_b.decode('utf-16-le').rstrip('\0'),
        ext_b.decode('utf-16-le').rstrip('\0')
    )

    return (unpacked[2], unpacked[3], name)


def parse_block_entries(f, offset):
    o_entry = offset + ((MAX_ENTRIES - 1) * ENTRY_SIZE)
    entries = []

    for i in range(MAX_ENTRIES):
        entry = parse_entry(f, o_entry)
        o_entry -= ENTRY_SIZE

        if entry != None:
            entries.append(entry)

    return entries


def parse_block(f, offset):
    f.seek(offset)
    unpacked = struct.unpack('<ll', f.read(8))

    if unpacked[0] != offset:
        return None

    entries = parse_block_entries(f, f.tell())
    return (entries, unpacked[1])


def get_token(f, entry):
    (offset, length, name) = entry
    f.seek(offset)

    if f.read(32) != ENTRY_CONTENTS_HEADER:
        return None

    (h_len, h_sha256) = struct.unpack('<l32s', f.read(36))

    if length != h_len:
        return None

    contents = f.read(h_len)

    if f.read(32) != ENTRY_CONTENTS_FOOTER:
        return None

    return (name, contents)


def get_tokens(f):
    f.seek(0)

    if struct.unpack('<l32xl', f.read(40)) != (TOKENS_VERSION, 36):
        return None

    offset = 36
    all_entries = []

    while offset != 0:
        (entries, offset) = parse_block(f, offset)
        all_entries += entries

    tokens = []

    for entry in all_entries:
        token = get_token(f, entry)
        if token != None:
            tokens.append(token)

    return tokens


def build_entry_value(data):
    d_len = len(data).to_bytes(4, "little")
    d_sha256 = hashlib.sha256(data).digest()

    value = ENTRY_CONTENTS_HEADER
    value += d_len
    value += d_sha256
    value += data
    value += ENTRY_CONTENTS_FOOTER

    return (value, len(value))


def build_entry_meta(o_meta, populated, o_value, vd_len, name):
    return struct.pack(
            "<IIIII130s8s",
            o_meta,
            populated,
            o_value,
            vd_len,
            vd_len,
            name[0].encode('utf-16-le'),
            name[1].encode('utf-16-le')
        )


def build_entry(o_meta, o_value, entry):
    value, v_len = build_entry_value(entry[1])

    vd_len = len(entry[1])
    meta = build_entry_meta(o_meta, True, o_value, vd_len, entry[0])

    return (value, v_len, meta)


def build_entries_block(entries, o_start):
    meta_block = b''
    data_block = b''

    o_meta = o_start + 8 + ((MAX_ENTRIES - 1) * ENTRY_SIZE)
    o_data = o_start + BLOCK_SIZE + 32

    next_block = 0
    write_entries = len(entries)
    write_next_block_offset = False

    if len(entries) > MAX_ENTRIES:
        write_entries = MAX_ENTRIES
        write_next_block_offset = True

    for _ in range(write_entries):
        data, data_len, meta = build_entry(o_meta, o_data, entries.pop(0))

        meta_block = meta + meta_block
        o_meta -= ENTRY_SIZE

        data_block += data
        o_data += data_len

    for _ in range(MAX_ENTRIES - write_entries):
        meta = build_entry_meta(o_meta, False, 0, 0xFFFFFFFF, ('', ''))

        meta_block = meta + meta_block
        o_meta -= ENTRY_SIZE

    if write_next_block_offset:
        next_block = o_data

    finished_block = struct.pack("<II", o_start, next_block)
    finished_block += meta_block
    finished_block += b'\0' * (BLOCK_SIZE - (MAX_ENTRIES * ENTRY_SIZE) - 8)
    finished_block += hashlib.sha256(finished_block).digest()
    finished_block += data_block

    return (finished_block, next_block, entries)


def build_tokens(entries):
    tokens_data = b''
    header = TOKENS_VERSION.to_bytes(4, "little")

    o_next = 36
    entries_l = entries

    while o_next != 0:
        block, o_next, entries_l = build_entries_block(entries_l, o_next)
        tokens_data += block

    tokens_hash = hashlib.sha256(header + tokens_data).digest()

    finished_tokens = header
    finished_tokens += tokens_hash
    finished_tokens += tokens_data

    return finished_tokens


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print(f'Usage: {sys.argv[0]} source_tokens_file destination_tokens_file')
        exit(1)

    source = sys.argv[1]
    destination = sys.argv[2]

    if not os.path.isfile(source):
        print(f'Source {source} is not a file')
        exit(1)

    if os.path.isdir(destination):
        print(f'Source {source} is a directory')
        exit(1)

    with open(source, 'rb') as f:
        tokens = get_tokens(f)

    with open(destination, 'wb') as f:
        f.write(build_tokens(tokens))
