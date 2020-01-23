from pwn import u32, u64, p32, p64

def unpack(s):
    if 0 < len(s) <= 4:
        return u32(s.ljust(4, '\x00'))
    elif len(s) <= 8:
        return u64(s.ljust(8, '\x00'))

def pack(n):
    if 0 < n <= 0xffffffff:
        return p32(n)
    elif n <= 0xffffffffffffffff:
        return p64(n)
