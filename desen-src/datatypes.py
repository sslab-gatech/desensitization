# -*- coding: utf-8 -*-
"""General datatypes about heaps, coredumps, etc.

"""
from __future__ import division

import ctypes

""" Coredump Miscs
"""
Elf32_Addr = ctypes.c_uint32
Elf64_Addr = ctypes.c_uint64

class MapType:
    NONHEAP   = 0
    PTHEAP    = 1
    JEHEAP    = 2

""" Ptmalloc Heaps
"""
# variables
NFASTBINS     = 10
NBINS         = 128
NSMALLBINS    = 64

BINMAPSHIFT   = 5
BITSPERMAP    = 1 << BINMAPSHIFT
BINMAPSIZE    = int(NBINS / BITSPERMAP)

HEAP_MIN_SIZE = 32 * 1024
HEAP_MAX_SIZE = 1024 ** 2

# structs
def generate_malloc_state(long):
    return [
        ("mutex",            ctypes.c_uint32),
        ("flags",            ctypes.c_uint32),
        ("fastbinsY",        long * NFASTBINS),
        ("top",              long),
        ("last_remainder",   long),
        ("bins",             long * (NBINS * 2 - 2)),
        ("binmap",           ctypes.c_uint32 * BINMAPSIZE),
        ("next",             long),
        ("next_free",        long),
        ("attached_threads", long),
        ("system_mem",       long),
        ("max_system_mem",   long)
    ]

def generate_heap_info(long, pad):
    return [
        ("ar_ptr",           long),
        ("prev",             long),
        ("size",             long),
        ("mprotect_size",    long),
        ("pad",              ctypes.c_char * pad)
    ]

class malloc_state_32(ctypes.Structure):
    _fields_ = generate_malloc_state(Elf32_Addr)

class malloc_state_64(ctypes.Structure):
    _fields_ = generate_malloc_state(Elf64_Addr)

class heap_info_32(ctypes.Structure):
    sz = ctypes.sizeof(Elf32_Addr)
    pad = (-6) * sz & (2 * sz - 1)
    _fields_ = generate_heap_info(Elf32_Addr, pad)

class heap_info_64(ctypes.Structure):
    sz = ctypes.sizeof(Elf64_Addr)
    pad = (-6) * sz & (2 * sz - 1)
    _fields_ = generate_heap_info(Elf64_Addr, pad)

heap_info_types = {
    'i386' : heap_info_32,
    'amd64': heap_info_64,
}

malloc_state_types = {
    'i386' : malloc_state_32,
    'amd64': malloc_state_64,
}


""" Jemalloc Heaps
"""
# variables
PAGESZ        = 0x1000          # 4k
CHUNKSZ       = 1024**2         # 1MB

# structs
def generate_ArenaCollection(long):
    return [
        ("mLock",                 ctypes.c_uint64 * 5),
        ("mDefaultArena",         long),
        ("mLastPublicArenaId",    long),
        ("mArenas",               long),
        ("mPrivateArenas",        long)
    ]

def generate_arena_t(long):
    return [
        ("mMagic",                long),
        ("mId",                   long),
        ("mLeft",                 long),
        ("mRightAndColor",        long),
        ("mLock",                 ctypes.c_uint64 * 5),
        ("mStats",                long * 4),
        ("mChunksDirty",          long),
        ("mSpare",                long),
        ("mNumDirty",             long),
        ("nMaxDirty",             long),
        ("mRunsAvail",            long)
    ]

def generate_arena_bin_t(long):
    return [
        ("mCurrentRun",           long),
        ("mNonFullRuns",          long),
        ("mSizeClass",            long),
        ("mRunSize",              long),
        ("mRunNumRegions",        ctypes.c_uint32),
        ("mRunNumRegionsMask",    ctypes.c_uint32),
        ("mRunFirstRegionOffset", long),
        ("mNumRuns",              long)
    ]

def generate_arena_chunk_t(long):
    return [
        ("arena",                 long),
        ("mLeft",                 long),
        ("mRightAndColor",        long),
        ("ndirty",                long)
    ]

def generate_arena_chunk_map_t(long):
    return [
        ("mLeft",                 long),
        ("mRightAndColor",        long),
        ("bits",                  long)
    ]

class ArenaCollection_32(ctypes.Structure):
    _fields_ = generate_ArenaCollection(Elf32_Addr)

class ArenaCollection_64(ctypes.Structure):
    _fields_ = generate_ArenaCollection(Elf64_Addr)

class arena_t_32(ctypes.Structure):
    _fields_ = generate_arena_t(Elf32_Addr)

class arena_t_64(ctypes.Structure):
    _fields_ = generate_arena_t(Elf64_Addr)

class arena_bin_t_32(ctypes.Structure):
    _fields_ = generate_arena_bin_t(Elf32_Addr)

class arena_bin_t_64(ctypes.Structure):
    _fields_ = generate_arena_bin_t(Elf64_Addr)

class arena_chunk_t_32(ctypes.Structure):
    _fields_ = generate_arena_chunk_t(Elf32_Addr)

class arena_chunk_t_64(ctypes.Structure):
    _fields_ = generate_arena_chunk_t(Elf64_Addr)

class arena_chunk_map_t_32(ctypes.Structure):
    _fields_ = generate_arena_chunk_map_t(Elf32_Addr)

class arena_chunk_map_t_64(ctypes.Structure):
    _fields_ = generate_arena_chunk_map_t(Elf64_Addr)

ArenaCollection_types = {
    'i386' : ArenaCollection_32,
    'amd64': ArenaCollection_64,
}

arena_t_types = {
    'i386' : arena_t_32,
    'amd64': arena_t_64,
}

arena_bin_t_types = {
    'i386' : arena_bin_t_32,
    'amd64': arena_bin_t_64,
}

arena_chunk_t_types = {
    'i386' : arena_chunk_t_32,
    'amd64': arena_chunk_t_64,
}

arena_chunk_map_t_types = {
    'i386' : arena_chunk_map_t_32,
    'amd64': arena_chunk_map_t_64,
}
