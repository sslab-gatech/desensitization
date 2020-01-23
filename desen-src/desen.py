#!/usr/bin/env python2

from __future__ import print_function

import argparse
from multiprocessing.pool import Pool
from corefile import Coredump
from minidumpfile import Minidump
from utils import NCPU, unpack, chkpn
from datatypes import MapType

DUMP = None

def __null_ptheap(s, ranges):
    """ Nullify ptheap maps w/ metadata

    Arguements:
        :class: `str, (int, int)`: (mstr, (sidx, eidx))
    """
    global DUMP
    ns = str()
    cap = DUMP.capsz
    mlen = len(s)
    (si, ei) = ranges

    # skip heapinfo and/or arena
    ns += s[:si]
    # keep all metadata of chunks till end of heap
    while si <= ei and si != mlen:
        # prev_size & size
        ns += s[si:si+cap*2]
        # clear size 3 LSB
        size = unpack(ns[-cap:], cap) & 0xFFFFFFFFFFFFFFF8

        # when size = 0 or bigger than rest of heap residue,
        # we know something is wrong...
        if not size or size > mlen - si:
            ns += ___iter_strcap(s[si+cap*2:])
            break
        ns += ___iter_strcap(s[si+cap*2:si+size])
        si += size
    return ns

def __null_jeheap(s, ranges):
    """ Nullify jeheap maps w/ metadata

    Arguments:
        :class: `str, [[int, int]]` : (mstr, [[sidx, eidx]])
    """
    i = 0
    ns = str()
    mlen = len(s)

    while i < mlen:
        # heap intervals are sorted, non-overlap
        if len(ranges):
            si, ei = ranges.pop(0)
            if i < si:
                ns += ___iter_strcap(s[i:si])
            # skip arenas or chunks
            ns += s[si:ei]
            i = ei
        else:
            ns += ___iter_strcap(s[i:mlen])
            i = mlen
    return ns

def ___iter_strcap(s):
    """ Nullify map string per capsize

    Arguements:
        :class: `str`: mstr
    """
    global DUMP
    ns = str()
    cap = DUMP.capsz

    # handle writable mapping per cap
    for i in range(0, len(s), cap):
        # zeros
        myset = set(s[i:i+cap])
        if '\x00' in myset and \
            len(myset) == 1:
                ns += '\x00' * cap
                continue
        v = unpack(s[i:i+cap], cap)
        # pointers
        if DUMP.is_ptr(v):
            # DEBUG
            #print("%s\t->\t%s" % (str(hex(v)), str(DUMP.to_map(v))))
            ns += s[i:i+cap]
        # non-pointer data
        else:
            ns += '\x00' * cap
    return ns

def _null_mapping(arg):
    """ Nullify non-pointer & non-metadata in maps

    Arguements:
        :class: `tuple(str, int, int, bool)`: (mid, iranges, mtype, writable)
    """
    global DUMP
    (mid, ranges, mtype, writable) = arg
    # mapping data
    m = DUMP.mappings[mid]
    s = m.data[:m.file_size]

    # ignore filesz 0 w/ empty map_str
    # can str unaligned?
    if not s or len(s) % DUMP.capsz:
        return mid, None

    # nullify all non-writable mapping
    if not writable:
        ns = '\x00' * len(s)
        return mid, ns

    # handle heaps
    if mtype == MapType.PTHEAP:
        return mid, __null_ptheap(s, ranges)
    elif mtype == MapType.JEHEAP:
        return mid, __null_jeheap(s, ranges)
    # handle non-heaps
    return mid, ___iter_strcap(s)

def cmd_null_coredump(pn):
    global DUMP
    print('Processing coredump:', pn)
    DUMP = Coredump(pn)

    # prepare args, i.e., (mstr, heap_idx_ranges, writable)
    args = list()
    for mid in range(DUMP.mapping_cnt):
        m = DUMP.mappings[mid]
        if not m.file_size:
            continue
        # ptmalloc
        if m in DUMP.ptheap.maps:
            ranges = DUMP.ptheap.maps[m]
            args.append((mid, ranges, MapType.PTHEAP, m.is_writable))
        # jemalloc
        elif m in DUMP.jeheap.maps:
            ranges = DUMP.jeheap.maps[m]
            args.append((mid, ranges, MapType.JEHEAP, m.is_writable))
        # non-heap
        else:
            args.append((mid, [], MapType.NONHEAP, m.is_writable))

    # multiprocessing for each mapping
    workers = Pool(NCPU)
    for (mid, s) in workers.imap_unordered(_null_mapping, args):
        m = DUMP.mappings[mid]
        if not s:
            continue
        for (va, sz) in list(DUMP.payloads):
            if va in m:
                s = s[:va-m.start] + DUMP.payloads[(va, sz)] + s[va-m.start+sz:]
                del DUMP.payloads[(va, sz)]
        DUMP.write(m.start, s)
    # patch sparsely
    DUMP.save(pn, sparse=True)
    print('Finished:', pn)

def cmd_null_minidump(pn):
    global DUMP
    print('Processing minidump:', pn)
    DUMP = Minidump(pn)

    # prepare args, i.e., mstr
    args = list()
    for mid in range(DUMP.mapping_cnt):
        m = DUMP.mappings[mid]
        args.append((mid, [], MapType.NONHEAP, m.is_writable))

    # multiprocessing for each mapping
    workers = Pool(NCPU)
    for (mid, s) in workers.imap_unordered(_null_mapping, args):
        m = DUMP.mappings[mid]
        if not s:
            continue
        for (va, sz) in list(DUMP.payloads):
            if va in m:
                s = s[:va-m.start] + DUMP.payloads[(va, sz)] + s[va-m.start+sz:]
                del DUMP.payloads[(va, sz)]
        DUMP.write(m.stack_addr, s)
    # patch sparsely
    DUMP.save(pn, sparse=True)
    print('Finished:', pn)

def process_dump(pn, mode):
    if mode == "core":
        cmd_null_coredump(pn)
    elif mode == "mini":
        cmd_null_minidump(pn)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-m", "--mode", action="store", required=True,
            choices=["core", "mini"],
            help="Crash format")
    parser.add_argument("-p", "--path", action="store", required=True,
            help="Crash path")
    cmd = parser.parse_args()

    chkpn(cmd.path)
    process_dump(cmd.path, cmd.mode)
