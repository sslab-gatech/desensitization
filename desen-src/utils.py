import os
import struct
import binascii
import multiprocessing

HERE = os.path.abspath(os.path.dirname(__file__))
ROOT = os.path.abspath(os.path.join(HERE, ".."))

NCPU = 4

def indent(text, prefix):
    pre = " " * prefix
    out = []
    for l in text.splitlines():
        out.append(pre + l + "\n")
    return "".join(out).rstrip()

def hd(blob):
    print(type(blob))
    if type(blob):
        pass
    return binascii.hexlify(blob)

def size_arch(info):
    if "amd64" in info:
        return 8
    elif "i386" in info:
        return 4
    raise Exception("unknown architecture")

# simple check
def chkpn(pn):
    assert os.path.exists(pn),"Need valid crash path!"

def check_args(func):
    import sys
    
    for pn in sys.argv[1:]:
        chkcore(pn, func)

def unpack(s, capsz):
    if capsz == 8:
        return struct.unpack("<Q", s)[0]
    else:
        return struct.unpack("<I", s)[0]

def pack(n, capsz):
    if capsz == 8:
        return struct.pack("<Q", n)
    else:
        return struct.pack("<I", n)
