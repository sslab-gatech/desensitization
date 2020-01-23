# -*- coding: utf-8 -*-
"""Read information about firefox heaps from Core Dumps.

- modified jemalloc ver.
"""
from __future__ import absolute_import
from __future__ import division

import os
import math
import ctypes

from pwnlib.elf.elf import ELF

import config
logname = "pwnlib." + __name__
log = config.getLogger(logname)

from utils import unpack
from datatypes import *

class JEHeap(object):
    """Encapsulates information about a memory mapping in a :class:`Corefile`.
    """
    def __init__(self, core):
        self._core=core

        #: : class:`int`: misc info on bin size, etc.
        self.kMinTinyClass          = core.capsz
        self.kMaxTinyClass          = 8
        self.kMinQuantumClass       = self.kMaxTinyClass * 2
        self.kMaxQuantumClass       = 512
        self.kQuantum               = 16
        self.kNumTinyClasses        = int(math.log(self.kMinQuantumClass, 2) \
                                        - math.log(self.kMinTinyClass, 2))
        self.kNumQuantumClasses     = int(self.kMaxQuantumClass / self.kQuantum)
        self.gMaxSubPageClass       = int(PAGESZ / 2)
        self.gNumSubPageClasses     = int(math.log(self.gMaxSubPageClass, 2) \
                                        - math.log(self.kMaxQuantumClass, 2))
        #: : class:`int`: number of pages managed by each arena_chunk_t
        self.gChunkNumPages         = int(CHUNKSZ/PAGESZ)
        #: : class:`int`: number of bins managed by each arena_t
        self.gNumBins               = self.kNumTinyClasses \
                                        + self.kNumQuantumClasses \
                                        + self.gNumSubPageClasses

        #: : class:`int`: collection of arenas
        self.gArenas                = 0

        #: : class:`dict{ar_addr: arena_t}`: struct arena_t for multi-threaded application
        #: using jemalloc; seems only one arena for firefox?
        self.mArenas                = dict()

        #: : class:`dict{bin_start_addr: [arena_bin_t]}`: struct arena_bin_t as dynamically
        #: sized array right after arena
        self.mBins                  = dict()

        #: : class:`dict{ch_addr: arena_chunk_t}`: struct arena_chunk_t controls
        #: contiguous memory pages associated with arena
        self.mChunks                = dict()

        #: : class:`dict{chmap_start_addr: [arena_chunk_map_t]}`: struct arena_chunk_map_t
        #: are bitmaps of pages controlled by the chunk
        # TODO we are not parsing bitmaps for now
        self.mChunkMap              = dict()

        #: : class:`ditc{ar_addr: [ch_addr]}`: mapping of arena to chunks
        self.a2c                    = dict()

        #: : class`dict{map: [(start_idx, end_idx)]}`: validated heap maps per arena_t & arena_chunk_t
        # NOTE: unlike ptmalloc, jemalloc heaps might reside on the same map
        self.maps                   = dict()

        #: : class:`int`: size of arena_t
        self.ar_size                = 0
        #: : class:`int`: size of arena_bin_t
        self.bin_size               = 0
        #: : class:`int`: size of arena_chunk_t
        self.ch_size                = 0
        #: : class:`int`: size of arena_chunk_map_t
        self.chmap_size             = 0

        # check binary symbols
        elf = self.chk_dbin(core.exe.path)
        if not elf:
            log.warn("Cannot locate debug binary %s for <gArenas>" % core.exe.path)
            return

        ac_type = ArenaCollection_types.get(core.arch, None)
        ar_type = arena_t_types.get(core.arch, None)
        bin_type = arena_bin_t_types.get(core.arch, None)
        ch_type = arena_chunk_t_types.get(core.arch, None)
        chmap_type = arena_chunk_map_t_types.get(core.arch, None)
        self.ar_size = ctypes.sizeof(ar_type)
        self.bin_size = ctypes.sizeof(bin_type)
        self.ch_size = ctypes.sizeof(ch_type)
        self.chmap_size = ctypes.sizeof(chmap_type)

        # globals
        offset = self.get_symoff(elf, "gArenas")
        if not offset:
            log.warn("Cannot find gArenas symbol (no jemalloc heap)")
            return
        self.gArenas = offset

        # gArenas
        ar_addr = self._load_gArenas(ac_type)
        # mArenas
        self._load_mArenas(ar_type, ar_addr)
        # mBins
        self._load_mBins(bin_type)
        # mChunks
        for ar_addr, mArena in self.mArenas.iteritems():
            ch_addr = mArena.mChunksDirty
            self._load_mChunks(ch_type, ch_addr, ar_addr)
        # merge heap intervals
        self.merge_maps()
        # DEBUG
        #print(self)

    def chk_dbin(self, pn):
        """Given path name to locate the binary w/ debug symbol"""
        elf = None
        # try debug path as well
        bn = pn.split('/').pop(-1)
        dpn = os.path.join(config.DBIN, bn)
        if os.path.isfile(pn):
            elf = ELF(pn, checksec=False)
        elif os.path.isfile(dpn):
            elf = ELF(dpn, checksec=False)
        return elf

    def get_symoff(self, elf, s):
        """Given symbol name to find its offset"""
        offset = 0
        for sym in elf.symbols:
            if s in sym:
                offset = elf.symbols[sym]
                break
        return offset

    def valid_heap(self, m):
        """Heap maps normally rw-p"""
        if not m:
            return False
        return m.file_size \
                and m.is_readable \
                and m.is_writable \
                and not m.is_executable

    def merge_maps(self):
        """Sort and merge overlapping heap intervals"""
        for mp, ranges in self.maps.iteritems():
            out = []
            for s, e in sorted(ranges, key=lambda i: i[0]):
                if out and s <= out[-1][1]:
                    out[-1][1] = max(out[-1][1], e)
                else:
                    out.append([s, e])
            self.maps[mp] = out

    def _load_gArenas(self, ac_type):
        """Parsing gAreans"""
        # absolute offset for non-PIE
        gar_mp = self._core.to_map(self.gArenas)
        if not self.valid_heap(gar_mp):
            # relative for PIE
            self.gArenas += self.core.exe.start
            gar_mp = self._core.to_map(self.gArenas)
            if not self.valid_heap(gar_mp):
                log.warn("Corrupted gArenas?")
                return
        # mArenas field
        return ac_type.from_buffer_copy(gar_mp.data, self.gArenas - gar_mp.start).mArenas

    def _load_mArenas(self, ar_type, ar_addr):
        """Recursion to parse mArenas"""
        if not ar_addr:
            return
        ar_mp = self._core.to_map(ar_addr)
        if not self.valid_heap(ar_mp):
            log.warn("Corrupted mArenas?")
            return

        if ar_addr not in self.mArenas:
            mArena = ar_type.from_buffer_copy(ar_mp.data, ar_addr - ar_mp.start)
            if mArena.mMagic != 0x947d3d24:
                log.warn("Corrupted mArenas?")
                return

            self.mArenas[ar_addr] = mArena
            # left & right child
            self._load_mArenas(ar_type, mArena.mLeft & 0xFFFFFFFFFFFFFFFE)
            self._load_mArenas(ar_type, mArena.mRightAndColor & 0xFFFFFFFFFFFFFFFE)
            # store heap: arena & bins
            mbase, start, end = ar_mp.start, \
                                ar_addr, \
                                ar_addr+self.ar_size+self.bin_size*self.gNumBins
            si, ei = start-mbase, end-mbase
            if ar_mp not in self.maps:
                self.maps[ar_mp] = [(si, ei)]
            else:
                self.maps[ar_mp].append((si, ei))

    def _load_mBins(self, bin_type):
        """Parsing mBins right after mArena"""
        for ar_addr, mArena in self.mArenas.iteritems():
            ar_mp = self._core.to_map(ar_addr)
            bin_addr = ar_addr + self.ar_size
            end = bin_addr + self.bin_size * self.gNumBins
            while bin_addr < end:
                mBin = bin_type.from_buffer_copy(ar_mp.data, bin_addr - ar_mp.start)
                self.mBins[bin_addr] = mBin
                bin_addr += self.bin_size

    def _load_mChunks(self, ch_type, ch_addr, ar_addr):
        """Parsing mChunks pointed by mArena"""
        if not ch_addr:
            return
        ch_mp = self._core.to_map(ch_addr)
        if not self.valid_heap(ch_mp):
            log.warn("Corrupted mChunk?")
            return

        if ch_addr not in self.mChunks:
            mChunk = ch_type.from_buffer_copy(ch_mp.data, ch_addr - ch_mp.start)
            if mChunk.arena != ar_addr:
                log.warn("Corrupted mChunk?")
                return

            self.mChunks[ch_addr] = mChunk
            self.a2c[ar_addr] = ch_addr
            # left & right child
            self._load_mChunks(ch_type, mChunk.mLeft & 0xFFFFFFFFFFFFFFFE, ar_addr)
            self._load_mChunks(ch_type, mChunk.mRightAndColor & 0xFFFFFFFFFFFFFFFE, ar_addr)
            # store heap: chunk & bitmap
            mbase, start, end = ch_mp.start, \
                                ch_addr, \
                                ch_addr+self.ch_size+self.chmap_size*self.gChunkNumPages
            si, ei = start-mbase, end-mbase
            if ch_mp not in self.maps:
                self.maps[ch_mp] = [(si, ei)]
            else:
                self.maps[ch_mp].append((si, ei))

    def __str__(self):
        pass

    def __contains__(self, item):
        pass
