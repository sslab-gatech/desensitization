#!/usr/bin/env python2

import os
import glob

import pwnlib
import pwnlib.term
import pwnlib.log

pwnlib.term.init()
pwnlib.log.install_default_handler()

# system-wide logger
log = pwnlib.log.rootlogger

# populate logger with a common theme
getLogger = pwnlib.log.getLogger

HERE = os.path.abspath(os.path.dirname(__file__))
ROOT = os.path.abspath(os.path.join(HERE, ".."))
DLIB = os.path.abspath(os.path.join(HERE, "debug"))
DBIN = os.path.abspath(os.path.join(DLIB, "bin"))

# match all possible fmtstr
fmtstr_regex = "%(\d+\$)?(\d+)?(((hh|h)?n)|[udopsfxc])"
# match only attack-related fmtstr (i.e. %n)
fmtstr_regex_n = "%(\d+\$)?(\d+)?(((hh|h)?n))"
rop_thresh = 5
shcode_thresh = 200
# int80 vs. syscall
shcode_db = ['\xcd\x80', '\x0f\x05']

# aux functions
def _get_all_core(excludes, root):
    if excludes is None:
        excludes = []

    rtn = []
    for p in glob.glob(os.path.join(root, "*", "*.core")):
        if any(e in p for e in excludes):
            continue
        rtn.append(p)
    return rtn
    
def get_all_core32(excludes=None):
    return _get_all_core(excludes, PATH_CORE32)

def get_all_core64(excludes=None):
    return _get_all_core(excludes, PATH_CORE64)

def get_all_cores(excludes=None):
    return get_all_core32(excludes) + get_all_core64(excludes)

def _get_core(root, pn):
    core = os.path.join(root, pn)
    assert os.path.exists(core)
    return core

def get_core32(pn):
    return _get_core(PATH_CORE32, pn)

def get_core64(pn):
    return _get_core(PATH_CORE64, pn)

# check whether corepath contains seclab challenge name
def contain_keyword(filename, lab):
    out = False
    labname = ""
    problem = ""
    for item in lab.keys():
        if item in filename:
            out = True
            labname = lab[item]
            problem = item
    return out, labname, problem

# if there is no file, look up the pre-defined dir
def lookup_file(pn):
    normpath = pn
    if pn.startswith("/"):
        normpath = pn[1:]

    db = os.path.join(PATH_FILE_DB, normpath)
    if os.path.exists(db):
        return db
    
    return pn

# look for debug version of lib for more symbols
def lookup_dlib(pn):
    normpath = pn
    if pn.startswith("/"):
        normpath = pn[1:]
    
    dlib = os.path.join(PATH_DLIB, normpath)
    if os.path.exists(dlib):
        return dlib

    return pn

if __name__ == '__main__':
    assert(len(get_all_cores()) \
           == len(get_all_core32() + get_all_core64()))
