# DESENSITIZATION: A privacy-aware and attack-preserving crash-reporting framework


## Paper

* [DESENSITIZATION: Privacy-Aware and Attack-Preserving Crash Report (NDSS 2020)]
(https://gts3.org/pages/publications.html#/)


## Overview

DESENSITIZATION aims to generate privacy-aware and attack-preserving crash reports
from crashed executions. It adopts lightweight methods for practicality to extract
bug-related and attack-related data from the memory, and removes other data to
protect users’ privacy. Besides, it also offers the benefits of bandwidth saving as
procssed crash reports are stored as sparse files. The framework is extensible, and
is independent of the target programs. It supports both the format of both coredumps
and minidumps.


## Contents

* Code base:
	- desen-src/elftools | desen-src/pwnlib: parsing coredumps
	- desen-src/minidump: parsing minidumps

* Crashes:
	- All the evaluated crashes are shared through the [link](http://128.61.240.170/desen-crashes.tar.gz)
		due to size limit
	- desen-crashes/[benchmark]/: benign/malicious crashes used to evaluate, including
		those from ffmpeg, php, chakra, firefox and tachikoma. Please refer to the paper
		for more details.


## Run for testing
```
# setup
$ export PATH=[pn_to_repo]/bin:$PATH

# coredumps
$ desen -c/--core [pn_to_coredump]

# minidumps
$ desen -m/--minidump [pn_to_minidump]
```


## Contacts
* Ren Ding (rding@gatech.edu)
* Hong Hu (hh86@gatech.edu)
* Wen Xu (wen.xu@gatech.edu)
* Taesoo Kim (taesoo@gatech.edu)
