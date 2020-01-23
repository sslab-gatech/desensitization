# -*- coding: utf-8 -*-
"""Read information about glibc heaps from Core Dumps.

- ptmalloc
"""
from __future__ import absolute_import
from __future__ import division

import os
import ctypes

from pwnlib.elf.elf import ELF

import config
logname = "pwnlib." + __name__
log = config.getLogger(logname)

from utils import unpack
from datatypes import *

class PTHeap(object):
    """Encapsulates information about a memory mapping in a :class:`Corefile`.
    """
    def __init__(self, core):
        self._core=core

        #: : class:`int`: main arena
        self.main_arena = 0

        #: : class:`dict{ar_addr: malloc_state}`: struct malloc_state for multi-threaded application
        #: including main and non-main arenas
        self.arenas     = dict()

        #: : class:`dict{hi_addr: heap_info}`: struct heap_info for each heap region
        #: a non-main arena can have multiple heap_info
        self.heapinfos  = dict()

        #: : class:`ditc{ar_addr: [hi_addr]}`: mapping of arena to heap_info
        self.a2h        = dict()

        #: : class`dict{map: (start_idx, end_idx)}`: validated heap maps per main heap & heap_info;
        # NOTE: unlike jemalloc, ptmalloc heaps never reside on the same map
        self.maps = dict()

        #: : class:`int`: size of arena
        self.ar_size    = 0
        #: : class:`int`: size of heapinfo
        self.hi_size    = 0

        # debug libc
        dlibc_pn = config.DLIB + core.libc.path
        libc = self.chk_dlib(dlibc_pn)
        if not libc:
            log.warn("Cannot find debug libc for <main_arena>")
            return

        ar_type = malloc_state_types.get(core.arch, None)
        hi_type = heap_info_types.get(core.arch, None)
        self.ar_size = ctypes.sizeof(ar_type)
        self.hi_size = ctypes.sizeof(hi_type)

        # main arena
        self.main_arena = core.libc.start + self.get_symoff(libc, "main_arena")
        self._load_arenas(ar_type)
        # heapinfo
        self._load_heapinfos(hi_type)
        # DEBUG
        #print(self)

    def chk_dlib(self, pn):
        """Given library path name to find its debug version"""
        elf = None
        if os.path.isfile(pn):
            elf = ELF(pn, checksec=False)
        return elf

    def get_symoff(self, elf, sym):
        """Given symbol name to find its offset in debug library"""
        offset = 0
        if sym in elf.symbols:
            offset = elf.symbols[sym]
        else:
            log.warn("Cannot find symbol <%s>" % sym)
        return offset

    def valid_heap(self, m):
        """Heap maps normally rw-p"""
        if not m:
            return False
        return m.file_size \
                and m.is_readable \
                and m.is_writable \
                and not m.is_executable

    def _load_arenas(self, arena_type):
        """Parsing arenas"""
        ar_addr = self.main_arena
        while ar_addr not in self.arenas:
            ar_mp = self._core.to_map(ar_addr)
            if not ar_mp:
                log.warn("Corrupted arena ptrs?")
                return
            arena = arena_type.from_buffer_copy(ar_mp.data, ar_addr - ar_mp.start)
            self.arenas[ar_addr] = arena
            # next arena
            ar_addr = arena.next

    def _load_heapinfos(self, heapinfo_type):
        """Parsing heapinfos"""
        for ar_addr in self.arenas:
            self.a2h[ar_addr] = []
            arena = self.arenas[ar_addr]

            # main arena does not have heap_info
            if ar_addr == self.main_arena:
                # top = 0 means no main/thread heaps
                if not arena.top:
                    break
                # main arena always has only one heap region
                mhp_map = self._core.to_map(arena.top)
                if not self.valid_heap(mhp_map):
                    log.warn("Main arena top chunk corrupted?")
                    continue
                # store heap
                mbase, start, end = mhp_map.start, \
                                    mhp_map.start, \
                                    arena.top
                si, ei = start-mbase, end-mbase
                self.maps[mhp_map] = (si, ei)
                continue

            # thread arena always has heap_info aligned to a power-of-two address
            hi_addr = int(arena.top / HEAP_MAX_SIZE) * HEAP_MAX_SIZE
            while hi_addr:
                hp_map = self._core.to_map(hi_addr)
                # heap_info always resides at the start of heap region
                if not self.valid_heap(hp_map) \
                        or hi_addr != hp_map.start:
                    log.warn("Corrupted heap_info?")
                    break

                heapinfo = heapinfo_type.from_buffer_copy(hp_map.data)
                if heapinfo.ar_ptr != ar_addr:
                    log.warn("Heap_info with corrupted ar_ptr?")
                    break

                # [heapinfo || arena || chunks... || (top?) ]
                start = hi_addr + self.hi_size
                end = hi_addr + heapinfo.mprotect_size
                if hi_addr + self.hi_size == ar_addr:
                    start = ar_addr + self.ar_size
                if hi_addr < arena.top < hi_addr + heapinfo.mprotect_size:
                    end = arena.top
                if start not in hp_map \
                        or end not in hp_map:
                    log.warn("Heap addresses are wrong...")
                    continue

                self.heapinfos[hi_addr] = heapinfo
                self.a2h[ar_addr].append(hi_addr)
                # store heap
                mbase = hp_map.start
                si, ei = start-mbase, end-mbase
                self.maps[hp_map] = (si, ei)
                # next heap_info of arena
                hi_addr = heapinfo.prev

    def __str__(self):
        out = []
        ar_idx = 0
        # arenas
        for ar_addr in self.arenas:
            arena = self.arenas[ar_addr]
            out.append("Arena #%d = {" % ar_idx)
            out.append("\tmutex: 0x%x," % arena.mutex)
            out.append("\tflags: 0x%x," % arena.flags)
            out.append("\tfastbinsY: %s," % str([hex(x) for x in arena.fastbinsY]))
            out.append("\ttop: 0x%x," % arena.top)
            out.append("\tlast_remainder: 0x%x" % arena.last_remainder)
            out.append("\tbins: %s," % str([hex(x) for x in arena.bins]))
            out.append("\tbinmap: %s," % str([hex(x) for x in arena.binmap]))
            out.append("\tnext: 0x%x," % arena.next)
            out.append("\tnext_free: 0x%x," % arena.next_free)
            out.append("\tattached_threads: 0x%x," % arena.attached_threads)
            out.append("\tsystem_mem: 0x%x," % arena.system_mem)
            out.append("\tmax_system_mem: 0x%x\n}" % arena.max_system_mem)
            # heapinfos
            hi_idx = 0
            for hi_addr in self.a2h[ar_addr]:
                heapinfo = self.heapinfos[hi_addr]
                out.append("\tHeap_info #%d = {" % hi_idx)
                out.append("\t\tar_ptr: 0x%x," % heapinfo.ar_ptr)
                out.append("\t\tprev: 0x%x," % heapinfo.prev)
                out.append("\t\tsize: 0x%x," % heapinfo.size)
                out.append("\t\tmprotect_size: 0x%x," % heapinfo.mprotect_size)
                out.append("\t\tpad: %s\n\t}" % heapinfo.pad)
                hi_idx += 1
            ar_idx += 1
        return "\n".join(out)

    def __contains__(self, item):
        pass
