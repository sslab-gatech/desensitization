#!/usr/bin/env python2

from __future__ import print_function

import optparse
import os
import sys
import utils

from readelf import ReadElf
from elftools.common.exceptions import ELFError

from corefile import Coredump

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

def _dump_nt_prstatus(core):
    out = []
    prstatus = core.prstatus.pop(0)

    def _p(key, val):
        if type(val) in (int, long) and val > 4096:
            val = "0x%x" % val
        out.append("%-20s: %s" % (key, val))
    def _pe(m):
        return _p(m, getattr(prstatus, m))
    def _pt(tv):
        t = getattr(prstatus, tv)
        return _p(tv, "%.6f" % (t.tv_sec + t.tv_usec*10**-6))
    def _pm(p, c):
        return _p("%s->%s" % (p, c), getattr(getattr(prstatus, p), c))

    _pm("pr_info", "si_signo")
    _pm("pr_info", "si_code")
    _pm("pr_info", "si_errno")
    _pe("pr_cursig")
    _pe("pr_sigpend")
    _pe("pr_sighold")
    _pe("pr_pid")
    _pe("pr_ppid")
    _pe("pr_pgrp")
    _pe("pr_sid")
    _pt("pr_utime")
    _pt("pr_stime")
    _pt("pr_cutime")
    _pt("pr_cstime")

    for k in sorted(dir(prstatus.pr_reg)):
        if k.startswith("_"):
           continue
        _pm("pr_reg", k)

    _pe("pr_fpvalid")
    
    return "\n".join(out)

def _dump_nt_prpsinfo(core):
    out = []
    def _p(key, val):
        if type(val) in (int, long) and val > 4096:
            val = "0x%x" % val
        out.append("%-20s: %s" % (key, val))
    def _pe(m):
        return _p(m, getattr(core.prpsinfo, m))
    
    _pe("pr_state")
    _pe("pr_sname")
    _pe("pr_zomb")
    _pe("pr_nice")
    _pe("pr_flag")
    _pe("pr_uid")
    _pe("pr_gid")
    _pe("pr_pid")
    _pe("pr_ppid")
    _pe("pr_pgrp")
    _pe("pr_sid")
    _pe("pr_sid")
    _pe("pr_fname")
    _pe("pr_psargs")

    return "\n".join(out)

def _dump_nt_siginfo(core):
    out = []
    siginfo = core.siginfo.pop(0)

    def _p(key, val):
        if type(val) in (int, long) and val > 4096:
            val = "0x%x" % val
        out.append("%-20s: %s" % (key, val))
    def _pe(m):
        return _p(m, getattr(siginfo, m))

    _pe('si_signo')
    _pe('si_code')
    _pe('si_errno')
    _pe('sigfault_addr')
    _pe('sigfault_trapno')

    return "\n".join(out)

def _dump_nt_auxv(core):
    out = []
    def _p(key, val):
        if type(val) in (int, long) and val > 4096:
            val = "0x%x" % val
        out.append("%-20s: %s" % (key, val))

    for t, v in core.auxv.iteritems():
        _p(t, v)
        
    return "\n".join(out)

def _dump_nt_file(core):
    out = []
    for m in core.mappings:
        out.append("0x%08x - 0x%08x: %s" \
                    % (m.start, m.start + m.size, m.name))
        # DEBUG
        #print(hex(len(m.data)))
    return "\n".join(out)

def _dump_note_segment(core, seg):
    _to = {"NT_PRSTATUS"   : _dump_nt_prstatus,
           "NT_PRPSINFO"   : _dump_nt_prpsinfo,
           "NT_SIGINFO"    : _dump_nt_siginfo,
           "NT_AUXV"       : _dump_nt_auxv,
           "NT_FILE"       : _dump_nt_file}
    
    out = []
    # PT_NOTE -> NT_xxx
    for i, note in enumerate(seg.iter_notes()):
        out.append('[%d] entry' % i)
        out.append('    Name: %s' % note['n_name'])
        out.append('    Type: %s' % note['n_type'])

        conv = _to.get(note['n_type'], None)
        # unhandled, raw data in note['n_desc']
        if conv:
            o = conv(core)
            out.append(utils.indent(o, 8))
    return "\n".join(out)
    
def cmd_dump_core(pn):
    core = Coredump(pn)
    # PT_NOTE
    for note_seg in core.core_segments:
        print(_dump_note_segment(core, note_seg))

def cmd_readelf_all(pn):
    with open(pn, 'rb') as fd:
        try:
            readelf = ReadElf(fd, sys.stdout)
            readelf.display_file_header()
            readelf.display_section_headers(show_heading=True)
            readelf.display_program_headers(show_heading=True)
            readelf.display_dynamic_tags()
            readelf.display_symbol_tables()
            readelf.display_notes()
            readelf.display_relocations()
            readelf.display_version_info()
            readelf.display_hex_dump(True)
            readelf.display_string_dump(True)
            readelf.display_debug_dump(True)
        except ELFError as e:
            sys.stderr.write('ELF error: %s\n' % e)
            exit(1)

def cmd_run_gdb(pn):
    os.system("gdb -c '%s' -q -x %s" % (pn, os.path.join(ROOT, "lib/peda/peda.py")))

def process_core(pn, opts):
    print('Processing file:', pn)

    if opts.elf:
        cmd_readelf_all(pn)

    cmd_dump_core(pn)

    if opts.gdb:
        cmd_run_gdb(pn)


if __name__ == '__main__':
    parser = optparse.OptionParser(usage="%prog [-g] [-e] core+")
    parser.add_option("-g", "--gdb", help="run gdb-peda for examining core file",
                      action="store_true", default=False)
    parser.add_option("-e", "--elf", help="readelf -a",
                      action="store_true", default=False)
    (opts, args) = parser.parse_args()
    
    for pn in args:
        process_core(pn, opts)
