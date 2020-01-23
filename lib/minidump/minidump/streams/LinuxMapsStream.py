# -*- coding: utf-8 -*-
""" Parsing MD_LINUX_MAPS

- (no struct, pure string parser)
"""

class Mapping(object):
    """Encapsulates information about a memory mapping in a :class:`Minidumpfile`.
    """
    def __init__(self, minidumpfile, name, start, stop, flags):
        self._minidumpfile = minidumpfile

        #: :class:`str`: Name of the mapping, e.g. ``'/bin/bash'`` or ``'[vdso]'``.
        self.name = name or ''

        #: :class:`int`: First mapped byte in the mapping
        self.start = start

        #: :class:`int`: First byte after the end of the mapping
        self.stop = stop

        #: :class:`int`: Size of the mapping, in bytes
        self.size = stop-start

        #: :class:`int`: Mapping flags, using e.g. ``PROT_READ`` and so on.
        self.flags = flags

        #: :class:`int`: Offset in the minidump file for current mapping data, if stack
        self.file_offset = 0

        #: :class:`int`: Data size in the minidump file (from the offset) for current mapping data, if stack
        self.file_size = 0

        #: :class:`int`: Stack mapping might have inconsistent start & end
        self.stack_addr = 0

        # alias
        self.beg = start
        self.end = stop

        # only stack contains data in minidump file
        stack = self.is_stack()
        if stack:
            self.file_offset = stack.memory.rva
            self.file_size = stack.memory.data_size
            self.stack_addr = stack.start_of_memory_range

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

    def is_stack(self):
        for stack in self._minidumpfile.stacks:
            start = stack.start_of_memory_range
            size = stack.memory.data_size
            end = start + size
            # check if it is stack mapping
            if self.start <= start and \
                    end <= self.end:
                return stack
        return None

    @property
    def data(self):
        """:class:`str`: Memory of the mapping."""
        # only stack
        return self._minidumpfile.read(self.stack_addr, self.file_size)

    def __contains__(self, item):
        if isinstance(item, Mapping):
            return (self.start <= item.start) and (item.stop <= self.stop)
        return self.start <= item < self.stop

class MinidumpLinuxMaps():
    """ String parser for MD_LINUX_MAPS
    """
    def __init__(self, minidumpfile, mdirectory):
        fd = minidumpfile.file
        offset = mdirectory.location.rva
        size = mdirectory.location.data_size

        # linux map string, e.g., /proc/$x/maps
        fd.seek(offset, 0)
        maps = fd.read(size).splitlines()
        
        for m in maps:
            # i.e., start-end perm offset device inode name
            attrs = m.split()
            start, end = self.__parse_addresses(attrs[0])
            flags = self.__parse_perm(attrs[1])
            pathname = None if len(attrs) < 6 else attrs[5]

            mapping = Mapping(minidumpfile,
                                pathname,
                                start,
                                end,
                                flags)
            minidumpfile.mappings.append(mapping)

            # update merged intervals of valid mappings
            if mapping.has_permission:
                if not len(minidumpfile.intvls) \
                    or mapping.beg !=  minidumpfile.intvls[-1]:
                        minidumpfile.intvls.append(mapping.beg)
                        minidumpfile.intvls.append(mapping.end)
                elif mapping.beg == minidumpfile.intvls[-1]:
                    minidumpfile.intvls[-1] = mapping.end
            minidumpfile.mapping_cnt = len(minidumpfile.mappings)

    def __parse_addresses(self, attr):
        ss, es = attr.split('-')
        start = int(ss, 16)
        end = int(es, 16)
        return start, end

    def __parse_perm(self, attr):
        perm = 0
        if 'x' in attr:
            perm += 1
        if 'w' in attr:
            perm += 2
        if 'r' in attr:
            perm += 4
        return perm
