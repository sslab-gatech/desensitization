#!/usr/bin/env python2

import os
import sys
import subprocess
sys.path.insert(0, '../src/')
import config
import butils

FNAME = "backtrace"
CUR = os.path.dirname(os.path.realpath(__file__))
FOUT = os.path.join(CUR, butils.RESULT, "%s.txt" % FNAME) 
buckets = {}
buckets_detailed = {}

log = config.log

def bucket(pn, ffmpeg_pn, cid):
    # generate backtrace report
    err = True
    log.info("Checking %s" % pn)
    my_env = os.environ.copy()
    my_env['PATH'] = "/opt/backtrace/bin:" + my_env['PATH']
    p1 = subprocess.Popen(['ptrace', '--kv=coredump:ffmpeg', '--core', '%s' % (pn), '%s' % (ffmpeg_pn),  '--load='], env=my_env, stdout=subprocess.PIPE)
    dirp = p1.communicate()[0]
    if ".btt" in dirp:
        err = False
    if err:
        return err
    
    # read report
    err = True
    log.info("Reading %s" % dirp[:-1])
    p2 = subprocess.Popen(['ptrace', '-b', '%s' % (dirp[:-1])], env=my_env, stdout=subprocess.PIPE)
    report = p2.communicate()[0]
    if "Group:" in report:
        s = report.find("Group:") + 7
        e = report.find('\n', s)
        sig = report[s:e]
        if sig not in buckets.keys():
            buckets[sig] = 1
            buckets_detailed[sig] = [cid]
        else:
            buckets[sig] += 1
            buckets_detailed[sig].append(cid)
        err = False
    # remove report
    if not err:
        os.remove(dirp[:-1])
    return err

if __name__ == '__main__':
    ''' ffmpeg malicious cores
    for n in range(0, 100):
        core_pn = "cve/ffmpeg/malicious/heap/core.%s" % n
        pn = os.path.join(config.PATH_CORE64, core_pn)
        ffmpeg_pn = os.path.abspath(os.path.join(pn, "..", "..", "..", "ffmpeg"))
        cid = "hcore.%s" % n
        err = bucket(pn, ffmpeg_pn, cid)
        if err:
            print buckets_detailed
            log.warn("[ERR] %s" % pn)
            exit(0)
    for n in range(0, 100):
        core_pn = "cve/ffmpeg/malicious/pltgot/core.%s" % n
        pn = os.path.join(config.PATH_CORE64, core_pn)
        ffmpeg_pn = os.path.abspath(os.path.join(pn, "..", "..", "..", "ffmpeg"))
        cid = "pcore.%s" % n
        err = bucket(pn, ffmpeg_pn, cid)
        if err:
            print buckets_detailed
            log.warn("[ERR] %s" % pn)
            exit(0)
    for n in range(0, 100):
        core_pn = "cve/ffmpeg/malicious/rop/core.%s" % n
        pn = os.path.join(config.PATH_CORE64, core_pn)
        ffmpeg_pn = os.path.abspath(os.path.join(pn, "..", "..", "..", "ffmpeg"))
        cid = "rcore.%s" % n
        err = bucket(pn, ffmpeg_pn, cid)
        if err:
            print buckets_detailed
            log.warn("[ERR] %s" % pn)
            exit(0)
    for n in range(0, 100):
        core_pn = "cve/ffmpeg/malicious/shellcode/core.%s" % n
        pn = os.path.join(config.PATH_CORE64, core_pn)
        ffmpeg_pn = os.path.abspath(os.path.join(pn, "..", "..", "..", "ffmpeg"))
        cid = "score.%s" % n
        err = bucket(pn, ffmpeg_pn, cid)
        if err:
            print buckets_detailed
            log.warn("[ERR] %s" % pn)
            exit(0)
    # ffmpeg benign cores
    for n in range(0, 1667):
        core_pn = "cve/ffmpeg/benign/core.%s" % n
        pn = os.path.join(config.PATH_CORE64, core_pn)
        ffmpeg_pn = os.path.abspath(os.path.join(pn, "..", "..", "ffmpeg"))
        cid = "core.%s" % (n + 100)
        err = bucket(pn, ffmpeg_pn, cid)
        if err:
            print buckets_detailed
            log.warn("[ERR] %s" % pn)
            exit(0)
    '''
    #''' chakra malicious cores
    for n in range(0, 50):
        core_pn = "cve/chakra/malicious/rop/core.%s" % n
        pn = os.path.join(config.PATH_CORE64, core_pn)
        chakra_pn = os.path.abspath(os.path.join(pn, "..", "..", "..", "ch"))
        cid = "rcore.%s" % n
        err = bucket(pn, chakra_pn, cid)
        if err:
            print buckets_detailed
            log.warn("[ERR] %s" % pn)
            exit(0)
    for n in range(50, 100):
        core_pn = "cve/chakra/malicious/pltgot/core.%s" % n
        pn = os.path.join(config.PATH_CORE64, core_pn)
        chakra_pn = os.path.abspath(os.path.join(pn, "..", "..", "..", "ch"))
        cid = "pcore.%s" % n
        err = bucket(pn, chakra_pn, cid)
        if err:
            print buckets_detailed
            log.warn("[ERR] %s" % pn)
            exit(0)
    # chakra benign cores
    for n in range(0, 1497):
        core_pn = "cve/chakra/benign/core.%s" % n
        pn = os.path.join(config.PATH_CORE64, core_pn)
        chakra_pn = os.path.abspath(os.path.join(pn, "..", "..", "ch"))
        cid = "core.%s" % (n + 100)
        err = bucket(pn, chakra_pn, cid)
        if err:
            print buckets_detailed
            log.warn("[ERR] %s" % pn)
            exit(0)
    #'''
    with open(FOUT, "a+") as f:
        f.write("%s\n" % str(buckets))
        f.write("%s\n" % str(buckets_detailed))
