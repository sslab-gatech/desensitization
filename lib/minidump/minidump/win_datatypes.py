#!/usr/bin/env python2

from helper import unpack

# https://msdn.microsoft.com/en-us/library/windows/desktop/aa383751(v=vs.85).aspx

class POINTER:
	def __init__(self, reader, finaltype):
		self.location = reader.tell()
		self.value = reader.read_uint()
		self.finaltype = finaltype
		
	def read(self, reader, override_finaltype = None):
		if self.value == 0:
			return None
		pos = reader.tell()
		reader.move(self.value)
		if override_finaltype:
			data = override_finaltype(reader)
		else:
			data = self.finaltype(reader)
		reader.move(pos)
		return data
	
	def read_raw(self, reader, size ):
		#we do not know the finaltype, just want the data
		if self.value == 0:
			return None
		pos = reader.tell()
		reader.move(self.value)
		data = reader.read(size)
		reader.move(pos)
		return data
		
class PVOID(POINTER):
	def __init__(self, reader):
		super().__init__(reader, None) #with void we cannot determine the final type
		
class BOOL:
	def __init__(self, reader):
		self.value = bool(reader.read_uint())
		
class BOOLEAN:
	def __init__(self, reader):
		self.value = reader.read(1)
		
class BYTE:
	def __init__(self, reader):
		self.value = reader.read(1)
		
class PBYTE(POINTER):
	def __init__(self, reader):
		super().__init__(reader, BYTE)

class CCHAR:
	def __init__(self, reader):
		self.value = reader.read(1).decode('ascii')
		
class CHAR:
	def __init__(self, reader):
		self.value = reader.read(1).decode('ascii')
		
class UCHAR:
	def __init__(self, reader):
		self.value = unpack(reader.read(1))

class WORD:
	def __init__(self, reader):
		self.value = unpack(reader.read(2))

class DWORD:
	def __init__(self, reader):
		self.value = unpack(reader.read(4))

class DWORDLONG:
	def __init__(self, reader):
		self.value = unpack(reader.read(8))

class DWORD_PTR(POINTER):
	def __init__(self, reader):
		super().__init__(reader, DWORD)
		
class DWORD32:
	def __init__(self, reader):
		self.value = unpack(reader.read(4))

class DWORD64:
	def __init__(self, reader):
		self.value = unpack(reader.read(8))
	
class HANDLE:
	def __init__(self, reader):
		self.value = reader.read_uint()
		
class HFILE:
	def __init__(self, reader):
		self.value = unpack(reader.read(4))

class HINSTANCE:
	def __init__(self, reader):
		self.value = reader.read_uint()		
		

class HKEY:
	def __init__(self, reader):
		self.value = reader.read_uint()


class HKL:
	def __init__(self, reader):
		self.value = reader.read_uint()
		
class HLOCAL:
	def __init__(self, reader):
		self.value = reader.read_uint()

class INT:
	def __init__(self, reader):
		self.value = reader.read_int()

class INT_PTR(POINTER):
	def __init__(self, reader):
		super().__init__(reader, INT)

class UINT8:
	def __init__(self, reader):
		self.value = unpack(reader.read(1))

class INT8:
	def __init__(self, reader):
		self.value = unpack(reader.read(1))

class INT16:
	def __init__(self, reader):
		self.value = unpack(reader.read(2))

class INT32:
	def __init__(self, reader):
		self.value = unpack(reader.read(4))

class INT64:
	def __init__(self, reader):
		self.value = unpack(reader.read(8))

class LONG:
	def __init__(self, reader):
		self.value = unpack(reader.read(4))

class LONGLONG:
	def __init__(self, reader):
		self.value = unpack(reader.read(8))

class LONG_PTR(POINTER):
	def __init__(self, reader):
		super().__init__(reader, LONG)

class LONG32:
	def __init__(self, reader):
		self.value = unpack(reader.read(8))

class LONG64():
	def __init__(self, reader):
		self.value = unpack(reader.read(8))

class LPARAM(POINTER):
	def __init__(self, reader):
		super().__init__(reader, LONG)

class LPBOOL(POINTER):
	def __init__(self, reader):
		super().__init__(reader, BOOL)

class LPBYTE(POINTER):
	def __init__(self, reader):
		super().__init__(reader, BYTE)

class ULONG:
	def __init__(self, reader):
		self.value = unpack(reader.read(4))

class ULONGLONG:
	def __init__(self, reader):
		self.value = unpack(reader.read(8))

class ULONG32:
	def __init__(self, reader):
		self.value = unpack(reader.read(4))

class ULONG64:
	def __init__(self, reader):
		self.value = unpack(reader.read(8))

class PWSTR(POINTER):
	def __init__(self, reader):
		super().__init__(reader, None)
		
class PCHAR(POINTER):
	def __init__(self, reader):
		super().__init__(reader, CHAR)
		
class USHORT:
	def __init__(self, reader):
		self.value = unpack(reader.read(2))

class SHORT:
	def __init__(self, reader):
		self.value = unpack(reader.read(2))

#https://msdn.microsoft.com/en-us/library/windows/hardware/ff554296(v=vs.85).aspx
class LIST_ENTRY:
	def __init__(self, reader, finaltype = None):
		self.Flink = POINTER(reader, finaltype)
		self.Blink = POINTER(reader, finaltype)
		
class FILETIME:
	def __init__(self, reader):
		self.dwLowDateTime = DWORD(reader)
		self.dwHighDateTime = DWORD(reader)
		self.value = (self.dwHighDateTime.value << 32) + self.dwLowDateTime.value
		
class PUCHAR(POINTER):
	def __init__(self, reader):
		super().__init__(reader, UCHAR)
		
class PCWSTR(POINTER):
	def __init__(self, reader):
		super().__init__(reader, None)
		
class SIZE_T:
	def __init__(self, reader):
		self.value = reader.read_uint()
