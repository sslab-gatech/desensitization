# -*- coding: utf-8 -*-
"""Read information from Minidumps.

- https://github.com/google/breakpad/blob/master/src/google_breakpad/common/minidump_format.h
"""
from __future__ import absolute_import
from __future__ import division

import os
import re
import mmap
import bisect
import ctypes

from minidump.common_structs import *
from minidump.streams import *

import config
logname =  "pwnlib." + __name__
log = config.getLogger(logname)

MinidumpStreamType = {
    0:          ("MD_UNUSED_STREAM",                None),
    1:          ("MD_RESERVED_STREAM_0",            None),
    2:          ("MD_RESERVED_STREAM_1",            None),
    3:          ("MD_THREAD_LIST_STREAM",           MinidumpThreadList),
    4:          ("MD_MODULE_LIST_STREAM",           None),
    5:          ("MD_MEMORY_LIST_STREAM",           None),
    6:          ("MD_EXCEPTION_STREAM",             None),
    7:          ("MD_SYSTEM_INFO_STREAM",           None),
    8:          ("MD_THREAD_EX_LIST_STREAM",        None),
    9:          ("MD_MEMORY_64_LIST_STREAM",        None),
    10:         ("MD_COMMENT_STREAM_A",             None),
    11:         ("MD_COMMENT_STREAM_W",             None),
    12:         ("MD_HANDLE_DATA_STREAM",           None),
    13:         ("MD_FUNCTION_TABLE_STREAM",        None),
    14:         ("MD_UNLOADED_MODULE_LIST_STREAM",  None),
    15:         ("MD_MISC_INFO_STREAM",             None),
    16:         ("MD_MEMORY_INFO_LIST_STREAM",      None),
    17:         ("MD_THREAD_INFO_LIST_STREAM",      None),
    18:         ("MD_HANDLE_OPERATION_LIST_STREAM", None),
    19:         ("MD_TOKEN_STREAM",                 None),
    20:         ("MD_JAVASCRIPT_DATA_STREAM",       None),
    21:         ("MD_SYSTEM_MEMORY_INFO_STREAM",    None),
    22:         ("MD_PROCESS_VM_COUNTERS_STREAM",   None),
    0x0000ffff: ("MD_LAST_RESERVED_STREAM",         None),

    # Breakpad extension types
    0x47670001: ("MD_BREAKPAD_INFO_STREAM",         None),
    0x47670002: ("MD_ASSERTION_INFO_STREAM",        None),
    # Stream values which are specific to linux breakpad implmentation
    0x47670003: ("MD_LINUX_CPU_INFO",               None),
    0x47670004: ("MD_LINUX_PROC_STATUS",            None),
    0x47670005: ("MD_LINUX_LSB_RELEASE",            None),
    0x47670006: ("MD_LINUX_CMD_LINE",               None),
    0x47670007: ("MD_LINUX_ENVIRON",                None),
    0x47670008: ("MD_LINUX_AUXV",                   None),
    0x47670009: ("MD_LINUX_MAPS",                   MinidumpLinuxMaps),
    0x4767000a: ("MD_LINUX_DSO_DEBUG",              None),

    # Crashpad extension types
    0x43500001: ("MD_CRASHPAD_INFO_STREAM",         None)
}

class MinidumpHeader(ctypes.Structure):
    _fields_ = [("signature",               ctypes.c_uint32),
                ("version",                 ctypes.c_uint32),
                ("stream_count",            ctypes.c_uint32),
                ("stream_directory_rva",    ctypes.c_uint32),
                ("checksum",                ctypes.c_uint32),
                ("time_date_stamp",         ctypes.c_uint32),
                ("flags",                   ctypes.c_uint64)]

    def __str__(self):
        s = "MDRawHeader\n \
            signature = 0x%x\n \
            version = 0x%x\n \
            stream_count = %d\n \
            stream_directory_rva = 0x%x\n \
            checksum = 0x%x\n \
            time_date_stamp = 0x%x\n \
            flags = 0x%x" % (
                self.signature,
                self.version,
                self.stream_count,
                self.stream_directory_rva,
                self.checksum,
                self.time_date_stamp,
                self.flags)
        return s

class MinidumpDirectory(ctypes.Structure):
    _fields_ = [("stream_type",             ctypes.c_uint32),
                ("location",                MinidumpLocationDescriptor)]

    def __str__(self):
        type_str = MinidumpStreamType[self.stream_type][0]
        s = "mDirectory\n \
            stream_type = 0x%x (%s)\n \
            location.data_size = %d\n \
            location.rva = 0x%x" % (
                self.stream_type,
                type_str,
                self.location.data_size,
                self.location.rva)
        return s

class Minidumpfile():
    """Enhances the information available about a minidump file by permitting
    extraction of information about the mapped data segments, and register state.
    """
    def __init__(self, pn):
        # We use the backing file for all reads, but permits writing to sync to
        # disk by mmap() the file.

        #: :class:`file`
        #: Open handle to the minidump file on disk
        self.file = open(pn, 'rb')

        #: :class:`mmap.mmap`
        #: Memory-mapped copy of the ELF file on disk
        self.mmap = mmap.mmap(self.file.fileno(), 0, access=mmap.ACCESS_COPY)

        #: :class:`str`: Path to the file
        self.path = os.path.abspath(pn)

        #: :class:`str`
        #: Architecture of the file (e.g. ``'i386'``, ``'arm'``).
        self.arch = None

        #: :class:`int`
        #: Capsize of the minidump file per CPUContext
        self.capsz = 0

        #: :class:`MinidumpHeader`
        #: The MDRawHeader, metainfo of the file
        self.header = None

        #: :class:`list(MinidumpDictionary)`
        #: The list of mDirectory for describing streams
        self.directories = list()

        #: :class:`list(MinidumpThread)`
        #: The list of MDRawThread for info of parsing threads
        self.threads = list()

        #: :class:`dict{tid: MinidumpCpuX86 | MinidumpCpuAMD64}`
        #: CPU context per thread
        self.registers = dict()

        #: :class:`list(MinidumpMemoryDescriptor)`
        #: memory segments about stacks
        self.stacks = list()

        #: :class:`list(Mapping)`
        #: The list of dictionary for memory mappings from ``address`` to ``name``
        self.mappings = list()
        self.mapping_cnt = 0

        #: :class:`list[int]`: Sorted mapping intervals that have permission
        #: NOTE every two numbers decides start and end of the interval
        self.intvls = []

        #: :class:`dict{(vaddr, sz): cstr}`: Suspicious patterns in the memory
        self.payloads = {}

        self.__parse_header()
        self.__parse_directories()

        # extract format string
        for (addr, sz, cstr) in self.search_cstrings(
                re.compile(config.fmtstr_regex),
                lookup=50, limit=50, writable=True):
            if sz > self.capsz:
                log.debug(repr("[fmtstr] 0x%x(%d): %s" % (addr, sz, cstr)))
                self.payloads[(addr, sz)] = cstr

        # extract shellcode payload
        for shcode_regex in config.shcode_db:
            for (addr, sz, cstr) in self.search_cstrings(
                    re.compile(shcode_regex),
                    lookup=100, limit=100, writable=True):
                if sz > self.capsz:
                    log.debug(repr("[shcode] 0x%x(%d): %s" % (addr, sz, cstr)))
                    self.payloads[(addr, sz)] = cstr

    def __parse_header(self):
        hdr_sz = ctypes.sizeof(MinidumpHeader)
        header = MinidumpHeader.from_buffer_copy(self.file.read(hdr_sz))
        # PMDM
        if header.signature != 0x504d444d:
            log.warn("Minidump header signature mismatch!")
            return
        self.header = header
        #print(self.header)

    def __parse_directories(self):
        dir_sz = ctypes.sizeof(MinidumpDirectory)
        if not self.header:
            return
        for i in range(0, self.header.stream_count):
            self.file.seek(self.header.stream_directory_rva + i * dir_sz, 0)
            directory = MinidumpDirectory.from_buffer_copy(self.file.read(dir_sz))
            self.directories.append(directory)
            #print(directory)

            s, handler = MinidumpStreamType[directory.stream_type]
            if not handler:
                #log.info("Stream type %s not handled" % s)
                continue
            handler(self, directory)

    @property
    def data(self):
        """:class:`str`: Raw data of the ELF file."""
        return self.mmap[:]

    def search_cstrings(self, pattern, lookup=100, limit=1024, writable=True):
        """search_cstrings(size=5, writable=True) -> generator

        Convert data sections to [c strings]

        Arguments:
            writable(bool): Search only writable sections.

        Yields:
            (virtual addr, size, cstring)
        """
        for mp in self.mappings:
            if writable and not mp.is_writable:
                continue

            # collect hints fmt strings
            matches = []
            for found in pattern.finditer(mp.data):
                matches.append(found.start())

            # convert them to cstrings
            cstrs = []
            for m in matches:
                if len(cstrs) != 0 and m < cstrs[-1][-1]:
                    continue
                # determin the end
                end = m + limit
                for e in range(m, min(len(mp.data), end)):
                    if mp.data[e] == "\x00":
                        end = e
                        break
                # determin the beg
                beg = m - lookup
                for b in range(m, max(0, beg), -1):
                    if mp.data[b] == "\x00":
                        beg = b+1
                        break
                cstrs.append((beg, end))

            for (b, e) in cstrs:
                # yielding (addr, size, cstr)
                yield (mp.start+b, e-b, mp.data[b:e])

    def read(self, address, count):
        """Read data from the specified virtual address, if exists in minidump (i.e., stack)"""
        s = ''
        if count == 0:
            return s

        for stack in self.stacks:
            start = stack.start_of_memory_range
            size = stack.memory.data_size
            end = start + size
            if start <= address < end:
                # file offset for stack data in minidump
                offset = stack.memory.rva + address - start
                length = min(count, end-address)
                s += self.mmap[offset:offset+length]
                break
        return s

    def write(self, address, data):
        """Writes data to the specified virtual address, if exists in minidump (i.e., stack)"""
        count = len(data)
        if not count:
            return None

        for stack in self.stacks:
            start = stack.start_of_memory_range
            size = stack.memory.data_size
            end = start + size
            if start <= address < end:
                # file offset for stack data in minidump
                offset = stack.memory.rva + address - start
                length = min(count, end-address)
                self.mmap[offset:offset+length] = data[:length]
                break
        return None

    def save(self, path=None, sparse=False):
        if path is None:
            path = self.path
        # tmpfile
        tmpfile = "./tfile"
        with open(tmpfile, 'w') as f:
            f.write(self.data)
        # saving sparse file
        if sparse:
            os.system("cp %s %s --sparse=always" % (tmpfile, path))
        else:
            os.system("cp %s %s" % (tmpfile, path))
        os.system("rm %s" % tmpfile)
        return

    # TODO better algorithm?
    def is_ptr(self, addr):
        lower = self.intvls[0]
        upper = self.intvls[-1]
        if addr < lower or addr > upper:
            return False

        # binary search to find intervals
        # s <= addr < e
        i = bisect.bisect(self.intvls, addr)
        # odd index means within range
        if i % 2:
            return True
        else:
            return False

    # TODO binary search instead
    def to_map(self, addr):
        for m in self.mappings:
            if addr in m:
                return m
        return None

    def is_executable(self, addr):
        m = self.to_map(addr)
        if m:
            return m.is_executable
        return False

    def is_writable(self, addr):
        m = self.to_map(addr)
        if m:
            return m.is_writable
        return False

    def is_readable(self, addr):
        m = self.to_map(addr)
        if m:
            return m.is_readable
        return False

class Minidump(Minidumpfile):
    """Alias for :class:`.Minidumpfile`"""
