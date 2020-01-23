#!/usr/bin/env python2

import io
from minidump.common_structs import *
from minidump.helper import unpack

# https://msdn.microsoft.com/en-us/library/windows/desktop/ms680387(v=vs.85).aspx
class MINIDUMP_MEMORY_LIST:
    def __init__(self):
        self.NumberOfMemoryRanges = None
        self.MemoryRanges = []

    @staticmethod
    def parse(buff):
        mml = MINIDUMP_MEMORY_LIST()
        mml.NumberOfModules = unpack(buff.read(4))
        for i in range(mml.NumberOfModules):
            mml.MemoryRanges.append(MINIDUMP_MEMORY_DESCRIPTOR.parse(buff))
        return mml

# https://msdn.microsoft.com/en-us/library/windows/desktop/ms680384(v=vs.85).aspx		
class MINIDUMP_MEMORY_DESCRIPTOR:
    def __init__(self):
        self.StartOfMemoryRange = None
        self.Memory = None

    @staticmethod
    def parse(buff):
        md = MINIDUMP_MEMORY_DESCRIPTOR()
        md.StartOfMemoryRange = unpack(buff.read(8))
        if md.StartOfMemoryRange < 0x100000000:
            md.Memory = MINIDUMP_LOCATION_DESCRIPTOR.parse(buff)
        else:
            md.Memory = MINIDUMP_LOCATION_DESCRIPTOR64.parse(buff)
        return md

class MinidumpMemoryList:
    def __init__(self):
        self.memory_segments = []

    @staticmethod
    def parse(dir, buff):
        t = MinidumpMemoryList()
        buff.seek(dir.Location.Rva)
        chunk = io.BytesIO(buff.read(dir.Location.DataSize))
        mtl = MINIDUMP_MEMORY_LIST.parse(chunk)
        for mod in mtl.MemoryRanges:
            t.memory_segments.append(MinidumpMemorySegment.parse_mini(mod, buff))
        return t

    def __str__(self):
        t  = '== MinidumpMemoryList ==\n'
        for mod in self.memory_segments:
            t+= str(mod) + '\n'
        return t
