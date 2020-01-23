#!/usr/bin/env python2

import sys
import enum
import logging

from .exceptions import *
from .minidumpreader import *
from .common_structs import *
from .streams import *
from helper import unpack

class MINIDUMP_STREAM_TYPE:
    UnusedStream			    = 0
    ReservedStream0			    = 1
    ReservedStream1			    = 2
    ThreadListStream		            = 3     # MDRawThreadList
    ModuleListStream		            = 4     # MDRawModuleList
    MemoryListStream		            = 5     # MDRawMemoryList
    ExceptionStream			    = 6     # MDRawExceptionStream
    SystemInfoStream		            = 7     # MDRawSystemInfo
    ThreadExListStream		            = 8
    Memory64ListStream		            = 9
    CommentStreamA			    = 10
    CommentStreamW			    = 11
    HandleDataStream		            = 12
    FunctionTableStream		            = 13
    UnloadedModuleListStream                = 14
    MiscInfoStream			    = 15
    MemoryInfoListStream	            = 16
    ThreadInfoListStream	            = 17
    HandleOperationListStream               = 18
    TokenStream                             = 19
    JavaScriptDataStream                    = 20
    SystemMemoryInfoStream                  = 21
    ProcessVmCountersStream                 = 22
    ThreadNamesStream                       = 24
    ceStreamNull                            = 25
    ceStreamSystemInfo                      = 26
    ceStreamException                       = 27
    ceStreamModuleList                      = 28
    ceStreamProcessList                     = 29
    ceStreamThreadList                      = 30
    ceStreamThreadContextList               = 31
    ceStreamThreadCallStackList             = 32
    ceStreamMemoryVirtualList               = 33
    ceStreamMemoryPhysicalList              = 34
    ceStreamBucketParameters                = 35
    ceStreamProcessModuleMap                = 36
    ceStreamDiagnosisList                   = 37
    LastReservedStream		            = 0x0000ffff

    # Breakpad extension types
    BreakpadInfoStream                      = 0x47670001
    AssertionInfoStream                     = 0x47670002
    # Stream values which are specific to linux breakpad implmentation
    LinuxCpuInfo                            = 0x47670003
    LinuxProcStatus                         = 0x47670004
    LinuxLsbRelease                         = 0x47670005
    LinuxCmdLine                            = 0x47670006
    LinuxEnviron                            = 0x47670007
    LinuxAuxv                               = 0x47670008
    LinuxMaps                               = 0x47670009
    LinuxDsoDebug                           = 0x4767000A

    # Crashpad extension types
    CrashpadInfoStream                      = 0x43500001

class MINIDUMP_TYPE:
    MiniDumpNormal			    = 0x00000000
    MiniDumpWithDataSegs		    = 0x00000001
    MiniDumpWithFullMemory		    = 0x00000002
    MiniDumpWithHandleData		    = 0x00000004
    MiniDumpFilterMemory		    = 0x00000008
    MiniDumpScanMemory			    = 0x00000010
    MiniDumpWithUnloadedModules		    = 0x00000020
    MiniDumpWithIndirectlyReferencedMemory  = 0x00000040
    MiniDumpFilterModulePaths	            = 0x00000080
    MiniDumpWithProcessThreadData	    = 0x00000100
    MiniDumpWithPrivateReadWriteMemory	    = 0x00000200
    MiniDumpWithoutOptionalData		    = 0x00000400
    MiniDumpWithFullMemoryInfo		    = 0x00000800
    MiniDumpWithThreadInfo		    = 0x00001000
    MiniDumpWithCodeSegs		    = 0x00002000
    MiniDumpWithoutAuxiliaryState	    = 0x00004000
    MiniDumpWithFullAuxiliaryState	    = 0x00008000
    MiniDumpWithPrivateWriteCopyMemory	    = 0x00010000
    MiniDumpIgnoreInaccessibleMemory	    = 0x00020000
    MiniDumpWithTokenInformation	    = 0x00040000
    MiniDumpWithModuleHeaders		    = 0x00080000
    MiniDumpFilterTriage		    = 0x00100000
    MiniDumpValidTypeFlags		    = 0x001fffff

class MINIDUMP_DIRECTORY:
    def __init__(self):
        self.StreamType = None
        self.Location = None

    @staticmethod
    def parse(buff):
        md = MINIDUMP_DIRECTORY()
	md.StreamType = unpack(buff.read(4))
	md.Location = MINIDUMP_LOCATION_DESCRIPTOR.parse(buff)
        return md

    def __str__(self):
        t = "MDRawDirectory\n"
        t += '\tStreamType: 0x%x\n%s' % (self.StreamType, self.Location)
	return t

# https://msdn.microsoft.com/en-us/library/windows/desktop/ms680378(v=vs.85).aspx
class MinidumpHeader:
    def __init__(self):
        self.Signature = None
        self.Version = None
        self.ImplementationVersion = None
        self.NumberOfStreams = None
        self.StreamDirectoryRva = None
        self.CheckSum = None
        self.Reserved = None
        self.TimeDateStamp = None
        self.Flags = None

    @staticmethod
    def parse(buff):
        mh = MinidumpHeader()
        mh.Signature = buff.read(4).decode()[::-1]
        if mh.Signature != 'PMDM':
            raise MinidumpHeaderSignatureMismatchException(mh.Signature)
        mh.Version = unpack(buff.read(4))
        mh.NumberOfStreams = unpack(buff.read(4))
        mh.StreamDirectoryRva = unpack(buff.read(4))
        mh.CheckSum = unpack(buff.read(4))
        mh.TimeDateStamp = unpack(buff.read(4))
        try:
            mh.Flags = unpack(buff.read(8))
        except Exception as e:
            raise MinidumpHeaderFlagsException('Could not parse header flags!')
        return mh

    def __str__(self):
        t = 'MDRawHeader\n'
        t+= '\tSignature: %s\n' % self.Signature
        t+= '\tVersion: 0x%x\n' % self.Version
        t+= '\tNumberOfStreams: %d\n' % self.NumberOfStreams
        t+= '\tStreamDirectoryRva: 0x%x\n' % self.StreamDirectoryRva
        t+= '\tCheckSum: 0x%x\n' % self.CheckSum
        t+= '\tTimeDateStamp: 0x%x\n' % self.TimeDateStamp
        t+= '\tFlags: 0x%x\n' % self.Flags
        return t

class MinidumpFile:
    def __init__(self):
        self.filename = None
        self.file_handle = None
        self.header = None
        self.directories = []

        self.threads_ex = None
        self.threads = None
        self.modules = None
        self.memory_segments = None
        self.memory_segments_64 = None
        self.sysinfo = None
        self.comment_a = None
        self.comment_w = None
        self.handles = None
        self.unloaded_modules = None
        self.misc_info = None
        self.memory_info = None
        self.thread_info = None

    @staticmethod
    def parse(filename):
        mf = MinidumpFile()
        mf.filename = filename
        mf.file_handle = open(filename, 'rb')
        mf._parse()
        return mf

    def get_reader(self):
        return MinidumpFileReader(self)

    def _parse(self):
        self.__parse_header()
        self.__parse_directories()

    def __parse_header(self):
        self.header = MinidumpHeader.parse(self.file_handle)
        for i in range(0, self.header.NumberOfStreams):
            self.file_handle.seek(self.header.StreamDirectoryRva + i * 12, 0 )
            self.directories.append(MINIDUMP_DIRECTORY.parse(self.file_handle))

    def __parse_directories(self):
        for dir in self.directories:
            if dir.StreamType == MINIDUMP_STREAM_TYPE.UnusedStream:
                continue # Reserved. Do not use this enumeration value.
            elif dir.StreamType == MINIDUMP_STREAM_TYPE.ReservedStream0:
                continue # Reserved. Do not use this enumeration value.
            elif dir.StreamType == MINIDUMP_STREAM_TYPE.ReservedStream1:
                continue # Reserved. Do not use this enumeration value.
            elif dir.StreamType == MINIDUMP_STREAM_TYPE.ThreadListStream:
                self.threads = MinidumpThreadList.parse(dir, self.file_handle)
                continue
            elif dir.StreamType == MINIDUMP_STREAM_TYPE.ModuleListStream:
                self.modules = MinidumpModuleList.parse(dir, self.file_handle)
                continue
            elif dir.StreamType == MINIDUMP_STREAM_TYPE.MemoryListStream:
                self.memory_segments = MinidumpMemoryList.parse(dir, self.file_handle)
                continue
            elif dir.StreamType == MINIDUMP_STREAM_TYPE.SystemInfoStream:
                self.sysinfo = MinidumpSystemInfo.parse(dir, self.file_handle)
                continue
            elif dir.StreamType == MINIDUMP_STREAM_TYPE.ThreadExListStream:
                self.threads_ex = MinidumpThreadExList.parse(dir, self.file_handle)
                continue
            elif dir.StreamType == MINIDUMP_STREAM_TYPE.Memory64ListStream:
                self.memory_segments_64 = MinidumpMemory64List.parse(dir, self.file_handle)
                continue
            elif dir.StreamType == MINIDUMP_STREAM_TYPE.CommentStreamA:
                self.comment_a = CommentStreamA.parse(dir, self.file_handle)
                continue
            elif dir.StreamType == MINIDUMP_STREAM_TYPE.CommentStreamW:
                self.comment_w = CommentStreamW.parse(dir, self.file_handle)
                continue
            elif dir.StreamType == MINIDUMP_STREAM_TYPE.HandleDataStream:
                self.handles = MinidumpHandleDataStream.parse(dir, self.file_handle)
                continue
            elif dir.StreamType == MINIDUMP_STREAM_TYPE.FunctionTableStream:
                logging.debug('Parsing of this stream type is not yet implemented!')
                continue
            elif dir.StreamType == MINIDUMP_STREAM_TYPE.UnloadedModuleListStream:
                self.unloaded_modules = MinidumpUnloadedModuleList.parse(dir, self.file_handle)
                continue
            elif dir.StreamType == MINIDUMP_STREAM_TYPE.MiscInfoStream:
                self.misc_info = MinidumpMiscInfo.parse(dir, self.file_handle)
                continue
            elif dir.StreamType == MINIDUMP_STREAM_TYPE.MemoryInfoListStream:
                self.memory_info = MinidumpMemoryInfoList.parse(dir, self.file_handle)
                continue
            elif dir.StreamType == MINIDUMP_STREAM_TYPE.ThreadInfoListStream:
                self.thread_info = MinidumpThreadInfoList.parse(dir, self.file_handle)
                continue
            elif dir.StreamType == MINIDUMP_STREAM_TYPE.SystemMemoryInfoStream:
                logging.debug('SystemMemoryInfoStream parsing is not implemented (Missing documentation)')
                continue
            elif dir.StreamType == MINIDUMP_STREAM_TYPE.JavaScriptDataStream:
                logging.debug('JavaScriptDataStream parsing is not implemented (Missing documentation)')
            elif dir.StreamType == MINIDUMP_STREAM_TYPE.ProcessVmCountersStream:
                logging.debug('ProcessVmCountersStream parsing is not implemented (Missing documentation)')
            elif dir.StreamType == MINIDUMP_STREAM_TYPE.TokenStream:
                logging.debug('TokenStream parsing is not implemented (Missing documentation)')
            else:
                logging.debug('Found Unknown Stream! Type: %d @0x%x Size: %d' % (dir.StreamType, dir.Location.Rva, dir.Location.DataSize))
            """
            elif dir.StreamType == MINIDUMP_STREAM_TYPE.HandleOperationListStream:
            elif dir.StreamType == MINIDUMP_STREAM_TYPE.LastReservedStream:
            elif dir.StreamType == MINIDUMP_STREAM_TYPE.ExceptionStream:
            """

    def __str__(self):
        t = '== Minidump File ==\n'
        t += str(self.header)
        t += str(self.sysinfo)
        for dir in self.directories:
            t += str(dir) + '\n'
        for mod in self.modules:
            t += str(mod) + '\n'
        for segment in self.memorysegments:
            t+= str(segment) + '\n'
        return t
