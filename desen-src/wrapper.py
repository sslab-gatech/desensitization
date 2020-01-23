#!/usr/bin/env python2
import os
import sys
import time
import glob
import subprocess as sp
import numpy as np

bn = str(sys.argv[1])
ht = {
        "ffmpeg": ("ffmpeg", 1667), \
        "php": ("php", 1313), \
        "chakra": ("chakra", 1497), \
        "ff-core": ("firefox", 1503), 
        "ff-mini": ("firefox", 1503), \
        "defcon": ("defcon", 5133)
     }
dirname = ht[bn][0]
cnt = ht[bn][1]

core_dir = "../crashes/%s/core/" % dirname
mini_dir = "../crashes/%s/mini/" % dirname
core_backup_dir = "../crashes/%s/core.bak/" % dirname
mini_backup_dir = "../crashes/%s/mini.bak/" % dirname

mprof_cmd = "mprof run --multiprocess --include-children "
times = []
mems = []
lsizes = []

def mprof_parse(fn):
    mem = 0.0
    with open(fn, 'r') as f:
        lines = f.readlines()
        for ln in lines:
            if "MEM" in ln:
                attrs = ln.split()
                mem = max(mem, float(attrs[1]))
    return mem

def testrun(i):
    start = time.time()

    cid = "core.%d" % i
    crash_dir = core_dir
    if bn == "ff-mini":
        cid = "%d.dmp" % i
        crash_dir = mini_dir
    pn = os.path.join(crash_dir, cid)

    if bn == "ff-mini":
        ret = sp.call([mprof_cmd + "./desen.py -m mini -p %s" % (pn)], shell=True)
    else:
        ret = sp.call([mprof_cmd + "./desen.py -m core -p %s" % (pn)], shell=True)
    if ret:
        print("[ERR] %s" % pn)

    try:
        out = sp.check_output(["ls", "-l", pn], stderr=sp.STDOUT)
    except:
        print("[ERR] ls failed %s" % pn)
    lsz = out.split()[4]
    # MB
    lsizes.append(float(lsz)/1000/1000)

    end = time.time()
    times.append(end-start)

    files = glob.glob("mprofile_??????????????.dat")
    if len(files) != 1:
        print("[ERR] mprof failed %s" % pn)
    else:
        fn = files.pop(0)
        mem_usage = mprof_parse(fn)
        mems.append(mem_usage)
        os.system("rm %s" % fn)

def diffcore(i):
    cid = "core.%d" % i
    crash_dir = core_dir
    crash_backup_dir = core_backup_dir
    if bn == "ff-mini":
        cid = "%d.dmp" % i
        crash_dir = mini_dir
        crash_backup_dir = mini_backup_dir
    pn = os.path.join(crash_dir, cid)
    pn_backup = os.path.join(crash_backup_dir, cid)

    try:
        out = sp.check_output(["diff", pn, pn_backup], stderr=sp.STDOUT)
    except:
        print("[ERR] diff %s && %s" % (pn, pn_backup))

def stats(l):
    if len(l):
        print("-"*20 + "# %d" % len(l) + "-"*20)
        print(l)
        print("Max: %.2f" % max(l))
        print("Min: %.2f" % min(l))
        print("Q1: %.2f" % np.quantile(l, .25))
        print("Q2: %.2f" % np.quantile(l, .50))
        print("Q3: %.2f" % np.quantile(l, .75))
        print("Mean: %.2f" % (float(sum(l)) / len(l)))

if __name__ == "__main__":
    for i in range(cnt):
        testrun(i)
        diffcore(i)
    stats(times)
    stats(mems)
    stats(lsizes)
