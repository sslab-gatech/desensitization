# -*- coding: utf-8 -*-
"""Read information from Core Dumps.

- extended from pwnlib/elf/corefile.py
- see LICENSE for pwnlib
"""
from __future__ import absolute_import
from __future__ import division

import collections
import bisect
import ctypes
import glob
import gzip
import re
import os
import socket
import string
import StringIO
import subprocess
import tempfile
import struct

import elftools
from elftools.common.py3compat import bytes2str
from elftools.common.utils import roundup
from elftools.common.utils import struct_parse
from elftools.construct import CString

from pwnlib import atexit
from pwnlib.context import context
from pwnlib.elf.datatypes import *
from pwnlib.elf.elf import ELF
from pwnlib.log import getLogger
from pwnlib.tubes.process import process
from pwnlib.tubes.ssh import ssh_channel
from pwnlib.tubes.tube import tube
from pwnlib.util import packing
from pwnlib.util.fiddling import b64d
from pwnlib.util.fiddling import enhex
from pwnlib.util.fiddling import unhex
from pwnlib.util.misc import read
from pwnlib.util.misc import write
from pwnlib.util.packing import pack
from pwnlib.util.packing import unpack_many

from ptmalloc import PTHeap
from jemalloc import JEHeap

import config
logname =  "pwnlib." + __name__
log = config.getLogger(logname)

prstatus_types = {
    'i386'    : elf_prstatus_i386,
    'amd64'   : elf_prstatus_amd64,
    'arm'     : elf_prstatus_arm,
    'aarch64' : elf_prstatus_aarch64
}

prpsinfo_types = {
    32: elf_prpsinfo_32,
    64: elf_prpsinfo_64,
}

siginfo_types = {
    32: elf_siginfo_32,
    64: elf_siginfo_64,
}

fpregset_types = {
    32: elf_fpregset_32,
    64: elf_fpregset_64,
}

# Slightly modified copy of the pyelftools version of the same function,
# until they fix this issue:
# https://github.com/eliben/pyelftools/issues/93
def iter_notes(self):
    """ Iterates the list of notes in the segment.
    """
    offset = self['p_offset']
    end = self['p_offset'] + self['p_filesz']
    while offset < end:
        note = struct_parse(
            self.elffile.structs.Elf_Nhdr,
            self.stream,
            stream_pos=offset)
        note['n_offset'] = offset
        offset += self.elffile.structs.Elf_Nhdr.sizeof()
        self.stream.seek(offset)
        # n_namesz is 4-byte aligned.
        disk_namesz = roundup(note['n_namesz'], 2)
        note['n_name'] = bytes2str(
            CString('').parse(self.stream.read(disk_namesz)))
        offset += disk_namesz

        desc_data = bytes2str(self.stream.read(note['n_descsz']))
        note['n_desc'] = desc_data
        offset += roundup(note['n_descsz'], 2)
        note['n_size'] = offset - note['n_offset']
        yield note

class Mapping(object):
    """Encapsulates information about a memory mapping in a :class:`Corefile`.
    """
    def __init__(self, core, name, start, stop, flags, page_offset, file_offset, file_size):
        self._core=core

        #: :class:`str`: Name of the mapping, e.g. ``'/bin/bash'`` or ``'[vdso]'``.
        self.name = name or ''

        #: :class:`int`: First mapped byte in the mapping
        self.start = start

        #: :class:`int`: First byte after the end of the mapping
        self.stop = stop

        #: :class:`int`: Size of the mapping, in bytes
        self.size = stop-start

        #: :class:`int`: Offset in pages in the mapped file
        self.page_offset = page_offset or 0

        #: :class:`int`: Mapping flags, using e.g. ``PROT_READ`` and so on.
        self.flags = flags

        #: :class:`int`: Offset in the core dump file for current mapping data
        self.file_offset = file_offset

        #: : class:`int`: Data size in the core dump file (from the offset) for current mapping data
        self.file_size = file_size

        # alias
        self.beg = start
        self.end = stop

    @property
    def path(self):
        """:class:`str`: Alias for :attr:`.Mapping.name`"""
        return self.name

    @property
    def address(self):
        """:class:`int`: Alias for :data:`Mapping.start`."""
        return self.start

    @property
    def permstr(self):
        """:class:`str`: Human-readable memory permission string, e.g. ``r-xp``."""
        flags = self.flags
        return ''.join(['r' if flags & 4 else '-',
                        'w' if flags & 2 else '-',
                        'x' if flags & 1 else '-',
                        'p'])
    def __str__(self):
        return '%x-%x %s %x %s' % (self.start,self.stop,self.permstr,self.size,self.name)

    def __repr__(self):
        return '%s(%r, start=%#x, stop=%#x, size=%#x, flags=%#x, page_offset=%#x)' \
            % (self.__class__.__name__,
               self.name,
               self.start,
               self.stop,
               self.size,
               self.page_offset,
               self.flags)

    def __int__(self):
        return self.start

    @property
    def is_executable(self):
        return self.flags & 1

    @property
    def is_writable(self):
        return self.flags & 2

    @property
    def is_readable(self):
        return self.flags & 4

    @property
    def has_permission(self):
        return self.flags & 7

    @property
    def data(self):
        """:class:`str`: Memory of the mapping."""
        return self._core.read(self.start, self.size)

    def __getitem__(self, item):
        if isinstance(item, slice):
            start = int(item.start or self.start)
            stop  = int(item.stop or self.stop)

            # Negative slices...
            if start < 0:
                start += self.stop
            if stop < 0:
                stop += self.stop

            if not (self.start <= start <= stop <= self.stop):
                log.error("Byte range [%#x:%#x] not within range [%#x:%#x]" \
                    % (start, stop, self.start, self.stop))

            data = self._core.read(start, stop-start)

            if item.step == 1:
                return data
            return data[::item.step]

        return self._core.read(item, 1)

    def __contains__(self, item):
        if isinstance(item, Mapping):
            return (self.start <= item.start) and (item.stop <= self.stop)
        return self.start <= item < self.stop

    def find(self, sub, start=None, end=None):
        """Similar to str.find() but works on our address space"""
        if start is None:
            start = self.start
        if end is None:
            end = self.stop

        result = self.data.find(sub, start-self.address, end-self.address)

        if result == -1:
            return result

        return result + self.address

    def rfind(self, sub, start=None, end=None):
        """Similar to str.rfind() but works on our address space"""
        if start is None:
            start = self.start
        if end is None:
            end = self.stop

        result = self.data.rfind(sub, start-self.address, end-self.address)

        if result == -1:
            return result

        return result + self.address

class Corefile(ELF):
    r"""Enhances the information available about a corefile (which is an extension
    of the ELF format) by permitting extraction of information about the mapped
    data segments, and register state.

    Registers can be accessed directly, e.g. via ``core_obj.eax`` and enumerated
    via :data:`Corefile.registers`.

    Arguments:
        core: Path to the core file.  Alternately, may be a :class:`.process` instance,
              and the core file will be located automatically.

    ::

        >>> c = Corefile('./core')
        >>> hex(c.eax)
        '0xfff5f2e0'
        >>> c.registers
        {'eax': 4294308576,
         'ebp': 1633771891,
         'ebx': 4151132160,
         'ecx': 4294311760,
         'edi': 0,
         'edx': 4294308700,
         'eflags': 66050,
         'eip': 1633771892,
         'esi': 0,
         'esp': 4294308656,
         'orig_eax': 4294967295,
         'xcs': 35,
         'xds': 43,
         'xes': 43,
         'xfs': 0,
         'xgs': 99,
         'xss': 43}

    Mappings can be iterated in order via :attr:`Corefile.mappings`.

    ::

        >>> Corefile('./core').mappings
        [Mapping('/home/user/pwntools/crash', start=0x8048000, stop=0x8049000, size=0x1000, flags=0x5, page_offset=0x0),
         Mapping('/home/user/pwntools/crash', start=0x8049000, stop=0x804a000, size=0x1000, flags=0x4, page_offset=0x1),
         Mapping('/home/user/pwntools/crash', start=0x804a000, stop=0x804b000, size=0x1000, flags=0x6, page_offset=0x2),
         Mapping(None, start=0xf7528000, stop=0xf7529000, size=0x1000, flags=0x6, page_offset=0x0),
         Mapping('/lib/i386-linux-gnu/libc-2.19.so', start=0xf7529000, stop=0xf76d1000, size=0x1a8000, flags=0x5, page_offset=0x0),
         Mapping('/lib/i386-linux-gnu/libc-2.19.so', start=0xf76d1000, stop=0xf76d2000, size=0x1000, flags=0x0, page_offset=0x1a8),
         Mapping('/lib/i386-linux-gnu/libc-2.19.so', start=0xf76d2000, stop=0xf76d4000, size=0x2000, flags=0x4, page_offset=0x1a9),
         Mapping('/lib/i386-linux-gnu/libc-2.19.so', start=0xf76d4000, stop=0xf76d5000, size=0x1000, flags=0x6, page_offset=0x1aa),
         Mapping(None, start=0xf76d5000, stop=0xf76d8000, size=0x3000, flags=0x6, page_offset=0x0),
         Mapping(None, start=0xf76ef000, stop=0xf76f1000, size=0x2000, flags=0x6, page_offset=0x0),
         Mapping('[vdso]', start=0xf76f1000, stop=0xf76f2000, size=0x1000, flags=0x5, page_offset=0x0),
         Mapping('/lib/i386-linux-gnu/ld-2.19.so', start=0xf76f2000, stop=0xf7712000, size=0x20000, flags=0x5, page_offset=0x0),
         Mapping('/lib/i386-linux-gnu/ld-2.19.so', start=0xf7712000, stop=0xf7713000, size=0x1000, flags=0x4, page_offset=0x20),
         Mapping('/lib/i386-linux-gnu/ld-2.19.so', start=0xf7713000, stop=0xf7714000, size=0x1000, flags=0x6, page_offset=0x21),
         Mapping('[stack]', start=0xfff3e000, stop=0xfff61000, size=0x23000, flags=0x6, page_offset=0x0)]
    """

    _fill_gaps = False

    def __init__(self, *a, **kw):
        #: The PT_NOTE segments
        #: A coredump file can have multiple note segments for multithreaded program
        #: crashes. Each PT_NOTE stands for a single thread context.
        self.core_segments = []

        #: The NT_PRSTATUS object
        #: A coredump file can have single PT_NOTE segment but multiple NT_PRSTATUS object
        #: due to multithreaded program crashes.
        self.prstatus      = []

        #: The NT_PRPSINFO object
        self.prpsinfo      = None

        #: The NT_SIGINFO object
        #: Same as NT_PRSTATUS
        self.siginfo       = []

        #: :class:`dict`: Dictionary of memory mappings from ``address`` to ``name``
        self.mappings      = []
        self.mapping_cnt   = 0

        #: :class:`int`: Address of the stack base
        self.stack         = None

        #: :class`PTHeap`: Ptmalloc heap information
        self.ptheap        = None

        #: :class`JEHeap`: Jemalloc heap information
        self.jeheap        = None

        #: :class:`dict`: Environment variables read from the stack.  Keys are
        #: the environment variable name, values are the memory address of the
        #: variable.
        #:
        #: Note: Use with the :meth:`.ELF.string` method to extract them.
        #:
        #: Note: If FOO=BAR is in the environment, self.env['FOO'] is the
        #:       address of the string "BAR\x00".
        self.env           = {}

        #: :class:`int`: Pointer to envp on the stack
        self.envp_address  = 0

        #: :class:`list`: List of addresses of arguments on the stack.
        self.argv          = []

        #: :class:`int`: Pointer to argv on the stack
        self.argv_address  = 0

        #: :class:`int`: Number of arguments passed
        self.argc          = 0

        #: :class:`int`: Pointer to argc on the stack
        self.argc_address  = 0

        # Pointer to the executable filename on the stack
        self.at_execfn     = 0

        # Pointer to the entry point
        self.at_entry      = 0

        #: :class:`list[int]`: Sorted mapping intervals that have permission
        #: NOTE every two numbers decides start and end of the interval
        self.intvls        = []

        #: :class:`dict{(vaddr, sz): cstr}`: Suspicious patterns in the memory
        self.payloads      = {}

        try:
            super(Corefile, self).__init__(*a, **kw)
        except IOError:
            log.warning("No corefile.  Have you set /proc/sys/kernel/core_pattern?")
            raise

        self.load_addr = 0
        self._address  = 0

        if not self.elftype == 'CORE':
            log.error("%s is not a valid corefile" % self.file.name)

        if not self.arch in prstatus_types.keys():
            log.warn_once("%s does not use a supported corefile architecture, registers are unavailable" % self.file.name)

        prstatus_type = prstatus_types.get(self.arch, None)
        prpsinfo_type = prpsinfo_types.get(self.bits, None)
        siginfo_type = siginfo_types.get(self.bits, None)
        fpregset_type = fpregset_types.get(self.bits, None)

        with log.waitfor("Parsing corefile...") as w:
            self._load_mappings()

            for segment in self.segments:
                if not isinstance(segment, elftools.elf.segments.NoteSegment):
                    continue

                # store all PT_NOTE segments
                self.core_segments.append(segment)

                for note in iter_notes(segment):
                    # Try to find NT_PRSTATUS.
                    if prstatus_type and \
                       note.n_descsz == ctypes.sizeof(prstatus_type) and \
                       note.n_type == 'NT_PRSTATUS':
                        self.prstatus.append(prstatus_type.from_buffer_copy(note.n_desc))

                    # Try to find NT_PRPSINFO
                    elif prpsinfo_type and \
                       note.n_descsz == ctypes.sizeof(prpsinfo_type) and \
                       note.n_type == 'NT_PRPSINFO':
                        self.prpsinfo = prpsinfo_type.from_buffer_copy(note.n_desc)

                    # Try to find NT_SIGINFO so we can see the fault
                    elif note.n_type == 'NT_SIGINFO':
                        self.siginfo.append(siginfo_type.from_buffer_copy(note.n_desc))

                    # Try to find the list of mapped files
                    elif note.n_type == 'NT_FILE':
                        with context.local(bytes=self.bytes):
                            self._parse_nt_file(note)

                    # Try to find the auxiliary vector, which will tell us
                    # where the top of the stack is.
                    elif note.n_type == 'NT_AUXV':
                        with context.local(bytes=self.bytes):
                            self._parse_auxv(note)

                    ''' RD: no need for now
                    if note.n_type in (constants.NT_PRFPREG, "NT_PRFPREG"):
                        self.pregset = fpregset_type.from_buffer_copy(note.n_desc)

                    if note.n_type in (constants.NT_PRXFPREG, "NT_PRXFPREG"):
                        assert(self.bits == 32)
                        self.prxfpreg = elf_fxsr_32.from_buffer_copy(note.n_desc)

                    # RD: fix parsing in pwnlib/elf/datatypes.py
                    if note.n_type in (constants.NT_X86_XSTATE, "NT_X86_XSTATE"):
                        self.x86_xstate = elf_xstateregs.from_buffer_copy(note.n_desc)

                    if note.n_type in (constants.NT_386_TLS, "NT_386_TLS"):
                        self._parse_x86_386_tls(note.n_desc)
                    '''

            if not self.stack and self.mappings:
                self.stack = self.mappings[-1]

            if self.stack and self.mappings:
                for mapping in self.mappings:
                    if self.stack in mapping or self.stack == mapping.stop:
                        mapping.name = '[stack]'
                        self.stack   = mapping
                        break
                else:
                    log.warn('Could not find the stack!')
                    self.stack = None

            with context.local(bytes=self.bytes, log_level='warn'):
                try:
                    self._parse_stack()
                except ValueError:
                    # If there are no environment variables, we die by running
                    # off the end of the stack.
                    pass

            # parse heap information
            self.ptheap = PTHeap(self)
            self.jeheap = JEHeap(self)

            # extract format string
            for (addr, sz, cstr) in self.search_cstrings(
                    re.compile(config.fmtstr_regex_n),
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

    def _parse_nt_file(self, note):
        t = tube()
        t.unrecv(note.n_desc)

        count = t.unpack()
        page_size = t.unpack()

        starts = []
        addresses = {}

        for i in range(count):
            start = t.unpack()
            end = t.unpack()
            offset = t.unpack()
            starts.append((start, offset))

        for i in range(count):
            filename = t.recvuntil('\x00', drop=True)
            (start, offset) = starts[i]

            for mapping in self.mappings:
                if mapping.start == start:
                    mapping.name = filename
                    mapping.page_offset = offset

        self.mappings = sorted(self.mappings, key=lambda m: m.start)

        vvar = vdso = vsyscall = False
        for mapping in reversed(self.mappings):
            if mapping.name:
                continue

            if not vsyscall and mapping.start == 0xffffffffff600000:
                mapping.name = '[vsyscall]'
                vsyscall = True
                continue

            if mapping.start == self.at_sysinfo_ehdr \
            or (not vdso and mapping.size in [0x1000, 0x2000] \
                and mapping.flags == 5 \
                and self.read(mapping.start, 4) == '\x7fELF'):
                mapping.name = '[vdso]'
                vdso = True
                continue

            if not vvar and mapping.size == 0x2000 and mapping.flags == 4:
                mapping.name = '[vvar]'
                vvar = True
                continue

    def _parse_x86_386_tls(self, data):
        def _bit(p):
            return (self.x86_386_tls.flag >> p) & 0x1

        self.x86_386_tls = elf_386_tls.from_buffer_copy(data)
        self.x86_386_tls.seg_32bit       = _bit(0)
        self.x86_386_tls.contents        = (_bit(1)<<1) | _bit(2)
        self.x86_386_tls.read_exec_only  = _bit(3)
        self.x86_386_tls.limit_in_pages  = _bit(4)
        self.x86_386_tls.seg_not_present = _bit(5)
        self.x86_386_tls.useable         = _bit(6)
        self.x86_386_tls.lm              = _bit(7)

    def search_cstrings(self, pattern, lookup=100, limit=1024, writable=True):
        """search_cstrings(size=5, writable=True) -> generator

        Convert data sections to [c strings]

        Arguments:
            writable(bool): Search only writable sections.

        Yields:
            (virtual addr, size, cstring)
        """
        load_address_fixup = (self.address - self.load_addr)

        if writable:
            segments = self.writable_segments
        else:
            segments = self.segments

        for seg in segments:
            addr   = seg.header.p_vaddr
            memsz  = seg.header.p_memsz
            zeroed = memsz - seg.header.p_filesz
            offset = seg.header.p_offset
            data   = self.mmap[offset:offset+memsz]
            data   += '\x00' * zeroed
            offset = 0

            # collect hints fmt strings
            matches = []
            for found in pattern.finditer(data):
                matches.append(found.start())

            # convert them to cstrings
            cstrs = []
            for m in matches:
                if len(cstrs) != 0 and m < cstrs[-1][-1]:
                    continue
                # determin the end
                end = m + limit
                for e in range(m, min(len(data), end)):
                    if data[e] == "\x00":
                        end = e
                        break
                # determin the beg
                beg = m - lookup
                for b in range(m, max(0, beg), -1):
                    if data[b] == "\x00":
                        beg = b+1
                        break
                cstrs.append((beg, end))

            for (b, e) in cstrs:
                # yielding (addr, size, cstr)
                yield (addr+b+load_address_fixup, e-b, data[b:e])

    @property
    def vvar(self):
        """:class:`Mapping`: Mapping for the vvar section"""
        for m in self.mappings:
            if m.name == '[vvar]':
                return m

    @property
    def vdso(self):
        """:class:`Mapping`: Mapping for the vdso section"""
        for m in self.mappings:
            if m.name == '[vdso]':
                return m

    @property
    def vsyscall(self):
        """:class:`Mapping`: Mapping for the vsyscall section"""
        for m in self.mappings:
            if m.name == '[vsyscall]':
                return m

    @property
    def libc(self):
        """:class:`Mapping`: First mapping for ``libc.so``"""
        expr = r'libc\b.*so$'

        for m in self.mappings:
            if not m.name:
                continue

            basename = os.path.basename(m.name)

            if re.match(expr, basename):
                return m

    @property
    def exe(self):
        """:class:`Mapping`: First mapping for the executable file."""
        for m in self.mappings:
            if self.at_entry and m.start <= self.at_entry <= m.stop:

                if not m.name and self.at_execfn:
                    m.name = self.string(self.at_execfn)

                return m

    @property
    def pid(self):
        """:class:`int`: PIDs of the process which created the core dump."""
        pids = []
        for prstatus in self.prstatus:
            pids.append(int(prstatus.pr_pid))
        return pids

    @property
    def ppid(self):
        """:class:`int`: Parent PIDs of the process which created the core dump."""
        ppids = []
        for prstatus in self.prstatus:
            ppids.append(int(prstatus.pr_ppid))
        return ppids

    @property
    def signal(self):
        """:class:`int`: Signal which caused the core to be dumped.

        Example:

            >>> elf = ELF.from_assembly(shellcraft.trap())
            >>> io = elf.process()
            >>> io.wait()
            >>> io.corefile.signal == signal.SIGTRAP
            True

            >>> elf = ELF.from_assembly(shellcraft.crash())
            >>> io = elf.process()
            >>> io.wait()
            >>> io.corefile.signal == signal.SIGSEGV
            True
        """
        sigs = []
        for siginfo in self.siginfo.si_signo:
            sigs.append(int(siginfo.si_signo))
            return sigs
        for prstatus in self.prstatus:
            sigs.append(int(prstatus.pr_cursig))
            return sigs

    @property
    def fault_addr(self):
        """:class:`int`: Address which generated the fault, for the signals
            SIGILL, SIGFPE, SIGSEGV, SIGBUS.  This is only available in native
            core dumps created by the kernel.  If the information is unavailable,
            this returns the address of the instruction pointer.


        Example:

            >>> elf = ELF.from_assembly('mov eax, 0xdeadbeef; jmp eax', arch='i386')
            >>> io = elf.process()
            >>> io.wait()
            >>> io.corefile.fault_addr == io.corefile.eax == 0xdeadbeef
            True
        """
        if not self.siginfo:
            return getattr(self, 'pc', 0)

        fault_addr = int(self.siginfo.sigfault_addr)

        # The fault_addr is zero if the crash occurs due to a
        # "protection fault", e.g. a dereference of 0x4141414141414141
        # because this is technically a kernel address.
        #
        # A protection fault does not set "fault_addr" in the siginfo.
        # (http://elixir.free-electrons.com/linux/v4.14-rc8/source/kernel/signal.c#L1052)
        #
        # Since a common use for corefiles is to spray the stack with a
        # cyclic pattern to find the offset to get control of $PC,
        # check for a "ret" instruction ("\xc3").
        #
        # If we find a RET at $PC, extract the "return address" from the
        # top of the stack.
        if fault_addr == 0 and self.siginfo.si_code == 0x80:
            try:
                code = self.read(self.pc, 1)
                RET = '\xc3'
                if code == RET:
                    fault_addr = self.unpack(self.sp)
            except Exception:
                # Could not read $rsp or $rip
                pass

        return fault_addr

        # No embedded siginfo structure, so just return the
        # current instruction pointer.

    @property
    def _pc_register(self):
        name = {
            'i386': 'eip',
            'amd64': 'rip',
        }.get(self.arch, 'pc')
        return name

    @property
    def pc(self):
        """:class:[`int`]: The program counter for the Corefile

        This is a cross-platform way to get e.g. ``core.eip``, ``core.rip``, etc.
        """
        pcs = []
        for registers in self.registers:
            pcs.append(registers.get(self._pc_register, None))
        return pcs

    @property
    def _sp_register(self):
        name = {
            'i386': 'esp',
            'amd64': 'rsp',
        }.get(self.arch, 'sp')
        return name

    @property
    def sp(self):
        """:class:[`int`]: The program counter for the Corefile

        This is a cross-platform way to get e.g. ``core.esp``, ``core.rsp``, etc.
        """
        sps = []
        for registers in self.registers:
            sps.append(registers.get(self._sp_register, None))
        return sps

    @property
    def _bp_register(self):
        name = {
            'i386': 'ebp',
            'amd64': 'rbp',
        }.get(self.arch, 'bp')
        return name

    @property
    def bp(self):
        """:class:[`int`]: The program counter for the Corefile

        This is a cross-platform way to get e.g. ``core.ebp``, ``core.rbp``, etc.
        """
        bps = []
        for registers in self.registers:
            bps.append(registers.get(self._bp_register, None))
        return bps

    def _load_mappings(self):
        # NOTE the mappings are sorted initially
        for s in self.segments:
            if s.header.p_type != 'PT_LOAD':
                continue

            mapping = Mapping(self,
                              None,
                              s.header.p_vaddr,
                              s.header.p_vaddr + s.header.p_memsz,
                              s.header.p_flags,
                              None,
                              s.header.p_offset,
                              s.header.p_filesz)
            self.mappings.append(mapping)

            # update merged intervals of valid mappings
            if mapping.has_permission:
                if not len(self.intvls) \
                    or mapping.beg !=  self.intvls[-1]:
                        self.intvls.append(mapping.beg)
                        self.intvls.append(mapping.end)
                elif mapping.beg == self.intvls[-1]:
                    self.intvls[-1] = mapping.end
            self.mapping_cnt = len(self.mappings)

    def _parse_auxv(self, note):
        t = tube()
        t.unrecv(note.n_desc)

        self.auxv = {}
        for i in range(0, note.n_descsz, context.bytes * 2):
            key = t.unpack()
            value = t.unpack()

            self.auxv[AT_CONSTANTS[key]] = value
            # The AT_EXECFN entry is a pointer to the executable's filename
            # at the very top of the stack, followed by a word's with of
            # NULL bytes.  For example, on a 64-bit system...
            #
            # 0x7fffffffefe8  53 3d 31 34  33 00 2f 62  69 6e 2f 62  61 73 68 00  |S=14|3./b|in/b|ash.|
            # 0x7fffffffeff8  00 00 00 00  00 00 00 00                            |....|....|    |    |

            if key == constants.AT_EXECFN:
                self.at_execfn = value
                value = value & ~0xfff
                value += 0x1000
                self.stack = value

            if key == constants.AT_ENTRY:
                self.at_entry = value

            if key == constants.AT_PHDR:
                self.at_phdr = value

            if key == constants.AT_BASE:
                self.at_base = value

            if key == constants.AT_SYSINFO_EHDR:
                self.at_sysinfo_ehdr = value

    def _parse_stack(self):
        # Get a copy of the stack mapping
        stack = self.stack

        if not stack:
            return

        # If the stack does not end with zeroes, something is very wrong.
        if not stack.data.endswith('\x00' * 8):
            log.warn_once("End of the stack is corrupted, skipping stack parsing (got: %s)",
                          enhex(self.data[-8:]))
            return

        # AT_EXECFN is the start of the filename, e.g. '/bin/sh'
        # Immediately preceding is a NULL-terminated environment variable string.
        # We want to find the beginning of it
        if not self.at_execfn:
            address = stack.stop
            address -= 2*self.bytes
            address -= 1
            address = stack.rfind('\x00', None, address)
            address += 1
            self.at_execfn = address

        address = self.at_execfn-1


        # Sanity check!
        try:
            assert stack[address] == '\x00'
        except AssertionError:
            # Something weird is happening.  Just don't touch it.
            log.debug("Something is weird")
            return
        except ValueError:
            # If the stack is not actually present in the coredump, we can't
            # read from the stack.  This will fail as:
            # ValueError: 'seek out of range'
            log.debug("ValueError")
            return

        # address is currently set to the NULL terminator of the last
        # environment variable.
        address = stack.rfind('\x00', None, address)

        # We've found the beginning of the last environment variable.
        # We should be able to search up the stack for the envp[] array to
        # find a pointer to this address, followed by a NULL.
        last_env_addr = address + 1
        p_last_env_addr = stack.find(pack(last_env_addr), None, last_env_addr)
        if p_last_env_addr < 0:
            # Something weird is happening.  Just don't touch it.
            log.warn_once("Found bad environment at %#x", last_env_addr)
            return

        # Sanity check that we did correctly find the envp NULL terminator.
        envp_nullterm = p_last_env_addr+context.bytes
        #assert self.unpack(envp_nullterm) == 0

        # We've successfully located the end of the envp[] array.
        #
        # It comes immediately after the argv[] array, which itself
        # is NULL-terminated.
        #
        # Now let's find the end of argv
        p_end_of_argv = stack.rfind(pack(0), None, p_last_env_addr)

        self.envp_address = p_end_of_argv + self.bytes

        # Temp sanity checks for corrupted stack
        if not (stack.start <= self.envp_address <= p_last_env_addr + self.bytes <= stack.stop):
            log.debug("Something is weird")
            return

        # Now we can fill in the environment
        env_pointer_data = stack[self.envp_address:p_last_env_addr+self.bytes]
        for pointer in unpack_many(env_pointer_data):

            # If the stack is corrupted, the pointer will be outside of
            # the stack.
            if pointer not in stack:
                continue

            try:
                name_value = self.string(pointer)
            except Exception:
                continue

            name, value = name_value.split('=', 1)

            # "end" points at the byte after the null terminator
            end = pointer + len(name_value) + 1

            # Do not mark things as environment variables if they point
            # outside of the stack itself, or we had to cross into a different
            # mapping (after the stack) to read it.
            # This may occur when the entire stack is filled with non-NUL bytes,
            # and we NULL-terminate on a read failure in .string().
            if end not in stack:
                continue

            self.env[name] = pointer + len(name) + len('=')

        # May as well grab the arguments off the stack as well.
        # argc comes immediately before argv[0] on the stack, but
        # we don't know what argc is.
        #
        # It is unlikely that argc is a valid stack address.
        address = p_end_of_argv - self.bytes
        while self.unpack(address) in stack:
            address -= self.bytes

        # address now points at argc
        self.argc_address = address
        self.argc = self.unpack(self.argc_address)

        # we can extract all of the arguments as well
        self.argv_address = self.argc_address + self.bytes
        self.argv = unpack_many(stack[self.argv_address: p_end_of_argv])

    @property
    def maps(self):
        """:class:`str`: A printable string which is similar to /proc/xx/maps.

        ::

            >>> print Corefile('./core').maps
            8048000-8049000 r-xp 1000 /home/user/pwntools/crash
            8049000-804a000 r--p 1000 /home/user/pwntools/crash
            804a000-804b000 rw-p 1000 /home/user/pwntools/crash
            f7528000-f7529000 rw-p 1000 None
            f7529000-f76d1000 r-xp 1a8000 /lib/i386-linux-gnu/libc-2.19.so
            f76d1000-f76d2000 ---p 1000 /lib/i386-linux-gnu/libc-2.19.so
            f76d2000-f76d4000 r--p 2000 /lib/i386-linux-gnu/libc-2.19.so
            f76d4000-f76d5000 rw-p 1000 /lib/i386-linux-gnu/libc-2.19.so
            f76d5000-f76d8000 rw-p 3000 None
            f76ef000-f76f1000 rw-p 2000 None
            f76f1000-f76f2000 r-xp 1000 [vdso]
            f76f2000-f7712000 r-xp 20000 /lib/i386-linux-gnu/ld-2.19.so
            f7712000-f7713000 r--p 1000 /lib/i386-linux-gnu/ld-2.19.so
            f7713000-f7714000 rw-p 1000 /lib/i386-linux-gnu/ld-2.19.so
            fff3e000-fff61000 rw-p 23000 [stack]
        """
        return '\n'.join(map(str, self.mappings))

    def getenv(self, name):
        """getenv(name) -> int

        Read an environment variable off the stack, and return its contents.

        Arguments:
            name(str): Name of the environment variable to read.

        Returns:
            :class:`str`: The contents of the environment variable.

        Example:

            >>> elf = ELF.from_assembly(shellcraft.trap())
            >>> io = elf.process(env={'GREETING': 'Hello!'})
            >>> io.wait()
            >>> io.corefile.getenv('GREETING')
            'Hello!'
        """
        if name not in self.env:
            log.error("Environment variable %r not set" % name)

        return self.string(self.env[name])

    @property
    def registers(self):
        """:class:[`dict`]: All available registers in the coredump.

        Example:

            >>> elf = ELF.from_assembly('mov eax, 0xdeadbeef;' + shellcraft.trap(), arch='i386')
            >>> io = elf.process()
            >>> io.wait()
            >>> io.corefile.registers['eax'] == 0xdeadbeef
            True
        """
        if not len(self.prstatus):
            return []

        rvs = []

        for prstatus in self.prstatus:
            rv = {}
            for k in dir(prstatus.pr_reg):
                if k.startswith('_'):
                    continue

                try:
                    rv[k] = int(getattr(prstatus.pr_reg, k))
                except Exception:
                    pass
            rvs.append(rv)

        return rvs

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

    def get_stack_frames(self, parseall=False):
        if not self.stack:
            return None

        # w/ parseall, parse all residue as it is from the entire stack data,
        # not just from the rsp

        # 
        # frames = [frame]
        # 
        # parse stack frames
        # frame {
        #  beg <- top
        #  end <- bottom
        #  fp
        #  size
        #  args[]
        #  locals[]
        #  stack = stack
        #  next() -> frame
        #  prev() -> frame
        # }

        print(self.stack)
        for cur in range(self.sp, self.stack.end, 4):
            print("%x: %s" % (cur, self._telescope(cur)))

    # XXX. faster version by using unicorn
    # pwnlib seems to invoke objdump!!
    def _disasm(self, addr, ninst):
        out = []
        for i, l in enumerate(self.disasm(addr, 32, offset=0, byte=0).splitlines()):
            asm = " ".join(l.split())
            # XXX. what's this?
            if asm == "...":
                asm = "???"
            out.append(asm)
            if i >= ninst:
                break
        return ";".join(out)

    def _telescope(self, addr):
        m = self.to_map(addr)
        if m is None:
            return None

        # code
        if m.is_executable:
            return "%s" % self._disasm(addr, 3)
        # data
        else:
            data = self.read(addr, self.bytes)
            word = packing.unpack(data)
            if 0<= word <= 4096:
                return str(word)
            elif all(c in string.printable for c in data):
                return self.string(addr, 32) + "..."
            else:
                child = self._telescope(word)
                if child is None:
                    return "0x%08x" % word
                else:
                    return "0x%08x -> %s" % (word, child)

    def telescope(self, ptr, raw=False):
        pass

    def debug(self, *a, **kw):
        """Open the corefile under a debugger."""
        if a or kw:
            log.error("Arguments are not supported for %s.debug()" % self.__class__.__name__)

        import pwnlib.gdb
        pwnlib.gdb.attach(self, exe=self.exe.path)

    def read_ulong(self, addr):
        if self.arch == "amd64":
            val = struct.unpack("<Q", self.read(addr, 8))[0]
        elif self.arch == "i386":
            val = struct.unpack("<L", self.read(addr, 4))[0]
        else:
            raise Exception("Unkonwn architecture")
        return val

    def read_cstring(self, addr, limit = 1024):
        s = []
        for c in self.read(addr, limit):
            if len(c) == 0 \
               or c[0] == "\x00":
                break
            s.append(c[0])
        return "".join(s)

    def progname(self):
        if len(self.argv) == 0:
            # get progname from pr_fname instead argv
            return getattr(self.prpsinfo, "pr_fname")
        pn = self.read_cstring(self.argv[0])
        return os.path.basename(os.path.normpath(pn))

    def __getattr__(self, attribute):
        # FIXME prstatus now becomes list rather than single value
        if self.prstatus:
            if hasattr(self.prstatus, attribute):
                return getattr(self.prstatus, attribute)

            if hasattr(self.prstatus.pr_reg, attribute):
                return getattr(self.prstatus.pr_reg, attribute)

        return super(Corefile, self).__getattribute__(attribute)

    # Override routines which don't make sense for Corefiles
    def _populate_got(*a): pass
    def _populate_plt(*a): pass

class Coredump(Corefile):
    """Alias for :class:`.Corefile`"""
