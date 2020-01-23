# -*- coding: utf-8 -*-
""" Parsing CPU context of minidump file

- MDRawContextX86
- MDRawContextAMD64

- https://github.com/google/breakpad/blob/master/src/google_breakpad/common/minidump_cpu_x86.h
- https://github.com/google/breakpad/blob/master/src/google_breakpad/common/minidump_cpu_amd64.h
"""

import ctypes

MD_FLOATINGSAVEAREA_X86_REGISTERAREA_SIZE = 80

class MinidumpFloatingSaveAreaX86(ctypes.Structure):
    _fields_ = [("control_word",            ctypes.c_uint32),
                ("status_word",             ctypes.c_uint32),
                ("tag_word",                ctypes.c_uint32),
                ("error_offset",            ctypes.c_uint32),
                ("error_selector",          ctypes.c_uint32),
                ("data_offset",             ctypes.c_uint32),
                ("data_selector",           ctypes.c_uint32),
                ("register_area",           ctypes.c_uint8 * MD_FLOATINGSAVEAREA_X86_REGISTERAREA_SIZE),
                ("cr0_npx_state",           ctypes.c_uint32)]

class MinidumpCpuX86(ctypes.Structure):
    _fields_ = [("dr0",                     ctypes.c_uint32),
                ("dr1",                     ctypes.c_uint32),
                ("dr2",                     ctypes.c_uint32),
                ("dr3",                     ctypes.c_uint32),
                ("dr6",                     ctypes.c_uint32),
                ("dr7",                     ctypes.c_uint32),
                ("float_save",              MinidumpFloatingSaveAreaX86),
                ("gs",                      ctypes.c_uint32),
                ("fs",                      ctypes.c_uint32),
                ("es",                      ctypes.c_uint32),
                ("ds",                      ctypes.c_uint32),
                ("edi",                     ctypes.c_uint32),
                ("esi",                     ctypes.c_uint32),
                ("ebx",                     ctypes.c_uint32),
                ("edx",                     ctypes.c_uint32),
                ("ecx",                     ctypes.c_uint32),
                ("eax",                     ctypes.c_uint32),
                ("ebp",                     ctypes.c_uint32),
                ("eip",                     ctypes.c_uint32),
                ("cs",                      ctypes.c_uint32),
                ("eflags",                  ctypes.c_uint32),
                ("esp",                     ctypes.c_uint32),
                ("ss",                      ctypes.c_uint32)]

    def __str__(self):
        s = "MDRawContextX86\n \
            dr0 = 0x%x\n \
            dr1 = 0x%x\n \
            dr2 = 0x%x\n \
            dr3 = 0x%x\n \
            dr6 = 0x%x\n \
            dr7 = 0x%x\n \
            gs = 0x%x\n \
            fs = 0x%x\n \
            es = 0x%x\n \
            ds = 0x%x\n \
            edi = 0x%x\n \
            esi = 0x%x\n \
            ebx = 0x%x\n \
            edx = 0x%x\n \
            ecx = 0x%x\n \
            eax = 0x%x\n \
            ebp = 0x%x\n \
            eip = 0x%x\n \
            cs = 0x%x\n \
            eflags = 0x%x\n \
            ss = 0x%x" % (
                self.dr0,
                self.dr1,
                self.dr2,
                self.dr3,
                self.dr6,
                self.dr7,
                self.gs,
                self.fs,
                self.es,
                self.ds,
                self.edi,
                self.esi,
                self.ebx,
                self.edx,
                self.ecx,
                self.eax,
                self.ebp,
                self.eip,
                self.cs,
                self.eflags,
                self.ss)
        return s

class MinidumpCpuAMD64(ctypes.Structure):
    _fields_ = [("p1_home",                 ctypes.c_uint64),
                ("p2_home",                 ctypes.c_uint64),
                ("p3_home",                 ctypes.c_uint64),
                ("p4_home",                 ctypes.c_uint64),
                ("p5_home",                 ctypes.c_uint64),
                ("p6_home",                 ctypes.c_uint64),
                ("context_flags",           ctypes.c_uint32),
                ("mx_csr",                  ctypes.c_uint32),
                ("cs",                      ctypes.c_uint16),
                ("ds",                      ctypes.c_uint16),
                ("es",                      ctypes.c_uint16),
                ("fs",                      ctypes.c_uint16),
                ("gs",                      ctypes.c_uint16),
                ("ss",                      ctypes.c_uint16),
                ("eflags",                  ctypes.c_uint32),
                ("dr0",                     ctypes.c_uint64),
                ("dr1",                     ctypes.c_uint64),
                ("dr2",                     ctypes.c_uint64),
                ("dr3",                     ctypes.c_uint64),
                ("dr6",                     ctypes.c_uint64),
                ("dr7",                     ctypes.c_uint64),
                ("rax",                     ctypes.c_uint64),
                ("rcx",                     ctypes.c_uint64),
                ("rdx",                     ctypes.c_uint64),
                ("rbx",                     ctypes.c_uint64),
                ("rsp",                     ctypes.c_uint64),
                ("rbp",                     ctypes.c_uint64),
                ("rsi",                     ctypes.c_uint64),
                ("rdi",                     ctypes.c_uint64),
                ("r8",                      ctypes.c_uint64),
                ("r9",                      ctypes.c_uint64),
                ("r10",                     ctypes.c_uint64),
                ("r11",                     ctypes.c_uint64),
                ("r12",                     ctypes.c_uint64),
                ("r13",                     ctypes.c_uint64),
                ("r14",                     ctypes.c_uint64),
                ("r15",                     ctypes.c_uint64),
                ("rip",                     ctypes.c_uint64)]

    def __str__(self):
        s = "MDRawContextADM64\n \
            p1_home = 0x%x\n \
            p2_home = 0x%x\n \
            p3_home = 0x%x\n \
            p4_home = 0x%x\n \
            p5_home = 0x%x\n \
            p6_home = 0x%x\n \
            context_flags = 0x%x\n \
            mx_csr = 0x%x\n \
            cs = 0x%x\n \
            ds = 0x%x\n \
            es = 0x%x\n \
            fs = 0x%x\n \
            gs = 0x%x\n \
            ss = 0x%x\n \
            eflags = 0x%x\n \
            dr0 = 0x%x\n \
            dr1 = 0x%x\n \
            dr2 = 0x%x\n \
            dr3 = 0x%x\n \
            dr6 = 0x%x\n \
            dr7 = 0x%x\n \
            rax = 0x%x\n \
            rcx = 0x%x\n \
            rdx = 0x%x\n \
            rbx = 0x%x\n \
            rsp = 0x%x\n \
            rbp = 0x%x\n \
            rsi = 0x%x\n \
            rdi = 0x%x\n \
            r8 = 0x%x\n \
            r9 = 0x%x\n \
            r10 = 0x%x\n \
            r11 = 0x%x\n \
            r12 = 0x%x\n \
            r13 = 0x%x\n \
            r14 = 0x%x\n \
            r15 = 0x%x\n \
            rip = 0x%x" % (
                self.p1_home,
                self.p2_home,
                self.p3_home,
                self.p4_home,
                self.p5_home,
                self.p6_home,
                self.context_flags,
                self.mx_csr,
                self.cs,
                self.ds,
                self.es,
                self.fs,
                self.gs,
                self.ss,
                self.eflags,
                self.dr0,
                self.dr1,
                self.dr2,
                self.dr3,
                self.dr6,
                self.dr7,
                self.rax,
                self.rcx,
                self.rdx,
                self.rbx,
                self.rsp,
                self.rbp,
                self.rsi,
                self.rdi,
                self.r8,
                self.r9,
                self.r10,
                self.r11,
                self.r12,
                self.r13,
                self.r14,
                self.r15,
                self.rip)
        return s
