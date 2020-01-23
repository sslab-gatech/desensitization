# -*- coding: utf-8 -*-
""" Parsing MD_THREAD_LIST_STREAM

- MDRawThreadList
- MDRawThread

- https://github.com/google/breakpad/blob/master/src/google_breakpad/common/minidump_format.h
"""

import ctypes
from minidump.common_structs import *
from .CPUContext import MinidumpCpuX86, MinidumpCpuAMD64

class MinidumpThread(ctypes.Structure):
    _fields_ = [("thread_id",               ctypes.c_uint32),
                ("suspend_count",           ctypes.c_uint32),
                ("priority_class",          ctypes.c_uint32),
                ("priority",                ctypes.c_uint32),
                ("teb",                     ctypes.c_uint64),
                ("stack",                   MinidumpMemoryDescriptor),
                ("thread_context",          MinidumpLocationDescriptor)]

    def __str__(self):
        s = "MDRawThread\n \
            thread_id = 0x%x\n \
            suspend_count = %d\n \
            priority_class = 0x%x\n \
            priority = 0x%x\n \
            teb = 0x%x\n \
            stack.start_of_memory_range = 0x%x\n \
            stack.memory.data_size = 0x%x\n \
            stack.memory.rva = 0x%x\n \
            thread_context.data_size = 0x%x\n \
            thread_context.rva = 0x%x" % (
                self.thread_id,
                self.suspend_count,
                self.priority_class,
                self.priority,
                self.teb,
                self.stack.start_of_memory_range,
                self.stack.memory.data_size,
                self.stack.memory.rva,
                self.thread_context.data_size,
                self.thread_context.rva)
        return s

class MinidumpThreadList(ctypes.Structure):
    _fields_ = [("number_of_threads",       ctypes.c_uint32)]

    def __init__(self, minidumpfile, mdirectory):
        fd = minidumpfile.file
        offset = mdirectory.location.rva
        size = mdirectory.location.data_size

        # thread list
        fd.seek(offset, 0)
        tl_size = ctypes.sizeof(MinidumpThreadList)
        thread_list = MinidumpThreadList.from_buffer_copy(fd.read(tl_size))
        #print(thread_list)

        t_size = ctypes.sizeof(MinidumpThread)
        if tl_size + t_size * thread_list.number_of_threads != size:
            print("Parsing size mismatched for ThreadList!")
            return

        for i in range(0, thread_list.number_of_threads):
            # threads
            fd.seek(offset + tl_size + i * t_size, 0)
            thread = MinidumpThread.from_buffer_copy(fd.read(t_size))
            minidumpfile.threads.append(thread)
            #print(thread)

            # CPU context
            ctx_offset = thread.thread_context.rva
            ctx_size = thread.thread_context.data_size
            cpu_x86_size = ctypes.sizeof(MinidumpCpuX86)
            cpu_amd64_size = ctypes.sizeof(MinidumpCpuAMD64)
            fd.seek(ctx_offset, 0)
            # NOTE only handle x86/x86-64 for now
            if ctx_size == cpu_x86_size:
                regs = MinidumpCpuX86.from_buffer_copy(fd.read(cpu_x86_size))
                minidumpfile.arch = 'i386'
                minidumpfile.capsz = 4
                #print(regs)
            else:
                regs = MinidumpCpuAMD64.from_buffer_copy(fd.read(cpu_amd64_size))
                minidumpfile.arch = 'amd64'
                minidumpfile.capsz = 8
                #print(regs)
            minidumpfile.registers[thread.thread_id] = regs

            # stacks
            minidumpfile.stacks.append(thread.stack)

    def __str__(self):
        s = "MinidumpThreadList\n \
            thread_count = %d" % (
                self.number_of_threads)
        return s
