#!/bin/bash

#
# Copyright (c) 2016-2018, mzet
#
# linux-exploit-suggester.sh comes with ABSOLUTELY NO WARRANTY.
# This is free software, and you are welcome to redistribute it
# under the terms of the GNU General Public License. See LICENSE
# file for usage of this software.
#

VERSION=v0.9

# bash colors
#txtred="\e[0;31m"
txtred="\e[91;1m"
txtgrn="\e[1;32m"
txtgray="\e[1;30m"
txtblu="\e[0;36m"
txtrst="\e[0m"
bldwht='\e[1;37m'
bldblu='\e[1;34m'
yellow='\e[1;93m'
lightyellow='\e[0;93m'

# input data
UNAME_A=""

# parsed data for current OS
KERNEL=""
OS=""
DISTRO=""
ARCH=""
PKG_LIST=""

# kernel config
KCONFIG=""

CVELIST_FILE=""

opt_fetch_bins=false
opt_fetch_srcs=false
opt_kernel_version=false
opt_uname_string=false
opt_pkglist_file=false
opt_cvelist_file=false
opt_checksec_mode=false
opt_full=false
opt_summary=false
opt_kernel_only=false
opt_userspace_only=false
opt_show_dos=false
opt_skip_more_checks=false
opt_skip_pkg_versions=false

ARGS=
SHORTOPTS="hVfbsu:k:dp:g"
LONGOPTS="help,version,full,fetch-binaries,fetch-sources,uname:,kernel:,show-dos,pkglist-file:,short,kernelspace-only,userspace-only,skip-more-checks,skip-pkg-versions,cvelist-file:,checksec"

## exploits database
declare -a EXPLOITS
declare -a EXPLOITS_USERSPACE

############ LINUX KERNELSPACE EXPLOITS ####################
n=0

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2004-1235]${txtrst} elflbl
Reqs: pkg=linux-kernel,ver=2.4.29
Tags:
analysis-url: http://isec.pl/vulnerabilities/isec-0021-uselib.txt
bin-url: https://web.archive.org/web/20111103042904/http://tarantula.by.ru/localroot/2.6.x/elflbl
exploit-db: 744
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2004-1235]${txtrst} uselib()
Reqs: pkg=linux-kernel,ver=2.4.29
Tags:
analysis-url: http://isec.pl/vulnerabilities/isec-0021-uselib.txt
exploit-db: 778
Comments: Known to work only for 2.4 series (even though 2.6 is also vulnerable)
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2004-1235]${txtrst} krad3
Reqs: pkg=linux-kernel,ver>=2.6.5,ver<=2.6.11
Tags:
exploit-db: 1397
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2004-0077]${txtrst} mremap_pte
Reqs: pkg=linux-kernel,ver>=2.6.0,ver<=2.6.2
Tags:
exploit-db: 160
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2006-2451]${txtrst} raptor_prctl
Reqs: pkg=linux-kernel,ver>=2.6.13,ver<=2.6.17
Tags:
exploit-db: 2031
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2006-2451]${txtrst} prctl
Reqs: pkg=linux-kernel,ver>=2.6.13,ver<=2.6.17
Tags:
exploit-db: 2004
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2006-2451]${txtrst} prctl2
Reqs: pkg=linux-kernel,ver>=2.6.13,ver<=2.6.17
Tags:
exploit-db: 2005
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2006-2451]${txtrst} prctl3
Reqs: pkg=linux-kernel,ver>=2.6.13,ver<=2.6.17
Tags:
exploit-db: 2006
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2006-2451]${txtrst} prctl4
Reqs: pkg=linux-kernel,ver>=2.6.13,ver<=2.6.17
Tags:
exploit-db: 2011
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2006-3626]${txtrst} h00lyshit
Reqs: pkg=linux-kernel,ver>=2.6.8,ver<=2.6.16
Tags:
bin-url: https://web.archive.org/web/20111103042904/http://tarantula.by.ru/localroot/2.6.x/h00lyshit
exploit-db: 2013
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2008-0600]${txtrst} vmsplice1
Reqs: pkg=linux-kernel,ver>=2.6.17,ver<=2.6.24
Tags:
exploit-db: 5092
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2008-0600]${txtrst} vmsplice2
Reqs: pkg=linux-kernel,ver>=2.6.23,ver<=2.6.24
Tags:
exploit-db: 5093
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2008-4210]${txtrst} ftrex
Reqs: pkg=linux-kernel,ver>=2.6.11,ver<=2.6.22
Tags:
exploit-db: 6851
Comments: world-writable sgid directory and shell that does not drop sgid privs upon exec (ash/sash) are required
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2008-4210]${txtrst} exit_notify
Reqs: pkg=linux-kernel,ver>=2.6.25,ver<=2.6.29
Tags:
exploit-db: 8369
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2009-2692]${txtrst} sock_sendpage (simple version)
Reqs: pkg=linux-kernel,ver>=2.6.0,ver<=2.6.30
Tags: ubuntu=7.10,RHEL=4,fedora=4|5|6|7|8|9|10|11
exploit-db: 9479
Comments: Works for systems with /proc/sys/vm/mmap_min_addr equal to 0
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2009-2692,CVE-2009-1895]${txtrst} sock_sendpage
Reqs: pkg=linux-kernel,ver>=2.6.0,ver<=2.6.30
Tags: ubuntu=9.04
analysis-url: https://xorl.wordpress.com/2009/07/16/cve-2009-1895-linux-kernel-per_clear_on_setid-personality-bypass/
src-url: https://github.com/offensive-security/exploit-database-bin-sploits/raw/master/bin-sploits/9435.tgz
exploit-db: 9435
Comments: /proc/sys/vm/mmap_min_addr needs to equal 0 OR pulseaudio needs to be installed
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2009-2692,CVE-2009-1895]${txtrst} sock_sendpage2
Reqs: pkg=linux-kernel,ver>=2.6.0,ver<=2.6.30
Tags: 
src-url: https://github.com/offensive-security/exploit-database-bin-sploits/raw/master/bin-sploits/9436.tgz
exploit-db: 9436
Comments: Works for systems with /proc/sys/vm/mmap_min_addr equal to 0
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2009-2692,CVE-2009-1895]${txtrst} sock_sendpage3
Reqs: pkg=linux-kernel,ver>=2.6.0,ver<=2.6.30
Tags: 
src-url: https://github.com/offensive-security/exploit-database-bin-sploits/raw/master/bin-sploits/9641.tar.gz
exploit-db: 9641
Comments: /proc/sys/vm/mmap_min_addr needs to equal 0 OR pulseaudio needs to be installed
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2009-2692,CVE-2009-1895]${txtrst} sock_sendpage (ppc)
Reqs: pkg=linux-kernel,ver>=2.6.0,ver<=2.6.30
Tags: ubuntu=8.10,RHEL=4|5
exploit-db: 9545
Comments: /proc/sys/vm/mmap_min_addr needs to equal 0
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2009-2698]${txtrst} udp_sendmsg (by spender)
Reqs: pkg=linux-kernel,ver>=2.6.1,ver<=2.6.19
Tags:
src-url: https://github.com/offensive-security/exploit-database-bin-sploits/raw/master/bin-sploits/9574.tgz
exploit-db: 9574
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2009-2698]${txtrst} udp_sendmsg
Reqs: pkg=linux-kernel,ver>=2.6.1,ver<=2.6.19
Tags: debian=4
exploit-db: 9575
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2009-2698]${txtrst} ip_append_data
Reqs: pkg=linux-kernel,ver>=2.6.1,ver<=2.6.19,x86
Tags: fedora=4|5|6,RHEL=4
exploit-db: 9542
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2009-3547]${txtrst} pipe.c 1
Reqs: pkg=linux-kernel,ver>=2.6.0,ver<=2.6.31
Tags:
exploit-db: 33321
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2009-3547]${txtrst} pipe.c 2
Reqs: pkg=linux-kernel,ver>=2.6.0,ver<=2.6.31
Tags:
exploit-db: 33322
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2009-3547]${txtrst} pipe.c 3
Reqs: pkg=linux-kernel,ver>=2.6.0,ver<=2.6.31
Tags:
exploit-db: 10018
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2010-3301]${txtrst} ptrace_kmod2
Reqs: pkg=linux-kernel,ver>=2.6.26,ver<=2.6.34
Tags: debian=6,ubuntu=10.04|10.10
bin-url: https://web.archive.org/web/20111103042904/http://tarantula.by.ru/localroot/2.6.x/kmod2
bin-url: https://web.archive.org/web/20111103042904/http://tarantula.by.ru/localroot/2.6.x/ptrace-kmod
bin-url: https://web.archive.org/web/20160602192641/https://www.kernel-exploits.com/media/ptrace_kmod2-64
exploit-db: 15023
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2010-1146]${txtrst} reiserfs
Reqs: pkg=linux-kernel,ver>=2.6.18,ver<=2.6.34
Tags: ubuntu=9.10
exploit-db: 12130
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2010-2959]${txtrst} can_bcm
Reqs: pkg=linux-kernel,ver>=2.6.18,ver<=2.6.36
Tags: ubuntu=10.04
bin-url: https://web.archive.org/web/20160602192641/https://www.kernel-exploits.com/media/can_bcm
exploit-db: 14814
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2010-3904]${txtrst} rds
Reqs: pkg=linux-kernel,ver>=2.6.30,ver<2.6.37
Tags: debian=6,ubuntu=10.10|9.10,fedora=13{kernel:2.6.33.3-85.fc13.i686.PAE},ubuntu=10.04{kernel:2.6.32-21-generic}
analysis-url: http://www.securityfocus.com/archive/1/514379
src-url: http://web.archive.org/web/20101020044048/http://www.vsecurity.com/download/tools/linux-rds-exploit.c
bin-url: https://web.archive.org/web/20160602192641/https://www.kernel-exploits.com/media/rds
bin-url: https://web.archive.org/web/20160602192641/https://www.kernel-exploits.com/media/rds64
exploit-db: 15285
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2010-3848,CVE-2010-3850,CVE-2010-4073]${txtrst} half_nelson
Reqs: pkg=linux-kernel,ver>=2.6.0,ver<=2.6.36
Tags: ubuntu=10.04|9.10
bin-url: http://web.archive.org/web/20160602192631/https://www.kernel-exploits.com/media/half-nelson3
exploit-db: 17787
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[N/A]${txtrst} caps_to_root
Reqs: pkg=linux-kernel,ver>=2.6.34,ver<=2.6.36,x86
Tags: ubuntu=10.10
exploit-db: 15916
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[N/A]${txtrst} caps_to_root 2
Reqs: pkg=linux-kernel,ver>=2.6.34,ver<=2.6.36
Tags: ubuntu=10.10
exploit-db: 15944
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2010-4347]${txtrst} american-sign-language
Reqs: pkg=linux-kernel,ver>=2.6.0,ver<=2.6.36
Tags:
exploit-db: 15774
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2010-3437]${txtrst} pktcdvd
Reqs: pkg=linux-kernel,ver>=2.6.0,ver<=2.6.36
Tags: ubuntu=10.04
exploit-db: 15150
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2010-3081]${txtrst} video4linux
Reqs: pkg=linux-kernel,ver>=2.6.0,ver<=2.6.33
Tags: RHEL=5
exploit-db: 15024
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2012-0056]${txtrst} memodipper
Reqs: pkg=linux-kernel,ver>=3.0.0,ver<=3.1.0
Tags: ubuntu=10.04|11.10
analysis-url: https://git.zx2c4.com/CVE-2012-0056/about/
src-url: https://git.zx2c4.com/CVE-2012-0056/plain/mempodipper.c
bin-url: https://web.archive.org/web/20160602192631/https://www.kernel-exploits.com/media/memodipper
bin-url: https://web.archive.org/web/20160602192631/https://www.kernel-exploits.com/media/memodipper64
exploit-db: 18411
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2012-0056,CVE-2010-3849,CVE-2010-3850]${txtrst} full-nelson
Reqs: pkg=linux-kernel,ver>=2.6.0,ver<=2.6.36
Tags: ubuntu=9.10|10.04|10.10,ubuntu=10.04.1
src-url: http://vulnfactory.org/exploits/full-nelson.c
bin-url: https://web.archive.org/web/20160602192631/https://www.kernel-exploits.com/media/full-nelson
bin-url: https://web.archive.org/web/20160602192631/https://www.kernel-exploits.com/media/full-nelson64
exploit-db: 15704
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2013-1858]${txtrst} CLONE_NEWUSER|CLONE_FS
Reqs: pkg=linux-kernel,ver=3.8,CONFIG_USER_NS=y
Tags: 
src-url: http://stealth.openwall.net/xSports/clown-newuser.c
analysis-url: https://lwn.net/Articles/543273/
exploit-db: 38390
author: Sebastian Krahmer
Comments: CONFIG_USER_NS needs to be enabled 
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2013-2094]${txtrst} perf_swevent
Reqs: pkg=linux-kernel,ver>=2.6.32,ver<3.8.9
Tags: RHEL=6,ubuntu=12.04
analysis-url: http://timetobleed.com/a-closer-look-at-a-recent-privilege-escalation-bug-in-linux-cve-2013-2094/
bin-url: https://web.archive.org/web/20160602192631/https://www.kernel-exploits.com/media/perf_swevent
bin-url: https://web.archive.org/web/20160602192631/https://www.kernel-exploits.com/media/perf_swevent64
exploit-db: 26131
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2013-2094]${txtrst} perf_swevent 2
Reqs: pkg=linux-kernel,ver>=2.6.32,ver<3.8.9,x86_64
Tags: ubuntu=12.04
analysis-url: http://timetobleed.com/a-closer-look-at-a-recent-privilege-escalation-bug-in-linux-cve-2013-2094/
src-url: https://cyseclabs.com/exploits/vnik_v1.c
exploit-db: 33589
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2013-0268]${txtrst} msr
Reqs: pkg=linux-kernel,ver>=2.6.18,ver<3.7.6
Tags: 
exploit-db: 27297
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2013-1959]${txtrst} userns_root_sploit
Reqs: pkg=linux-kernel,ver>=3.0.1,ver<3.8.9
Tags: 
analysis-url: http://www.openwall.com/lists/oss-security/2013/04/29/1
exploit-db: 25450
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2013-2094]${txtrst} semtex
Reqs: pkg=linux-kernel,ver>=2.6.32,ver<3.8.9
Tags: RHEL=6
analysis-url: http://timetobleed.com/a-closer-look-at-a-recent-privilege-escalation-bug-in-linux-cve-2013-2094/
exploit-db: 25444
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2014-0038]${txtrst} timeoutpwn
Reqs: pkg=linux-kernel,ver>=3.4.0,ver<=3.13.1,CONFIG_X86_X32=y
Tags: ubuntu=13.10
analysis-url: http://blog.includesecurity.com/2014/03/exploit-CVE-2014-0038-x32-recvmmsg-kernel-vulnerablity.html
bin-url: https://web.archive.org/web/20160602192631/https://www.kernel-exploits.com/media/timeoutpwn64
exploit-db: 31346
Comments: CONFIG_X86_X32 needs to be enabled
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2014-0038]${txtrst} timeoutpwn 2
Reqs: pkg=linux-kernel,ver>=3.4.0,ver<=3.13.1,CONFIG_X86_X32=y
Tags: ubuntu=13.10|13.04
analysis-url: http://blog.includesecurity.com/2014/03/exploit-CVE-2014-0038-x32-recvmmsg-kernel-vulnerablity.html
exploit-db: 31347
Comments: CONFIG_X86_X32 needs to be enabled
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2014-0196]${txtrst} rawmodePTY
Reqs: pkg=linux-kernel,ver>=2.6.31,ver<=3.14.3
Tags:
analysis-url: http://blog.includesecurity.com/2014/06/exploit-walkthrough-cve-2014-0196-pty-kernel-race-condition.html
exploit-db: 33516
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2014-2851]${txtrst} use-after-free in ping_init_sock() ${bldblu}(DoS)${txtrst}
Reqs: pkg=linux-kernel,ver>=3.0.1,ver<=3.14
Tags: 
analysis-url: https://cyseclabs.com/page?n=02012016
exploit-db: 32926
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2014-4014]${txtrst} inode_capable
Reqs: pkg=linux-kernel,ver>=3.0.1,ver<=3.13
Tags: ubuntu=12.04
analysis-url: http://www.openwall.com/lists/oss-security/2014/06/10/4
exploit-db: 33824
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2014-4699]${txtrst} ptrace/sysret
Reqs: pkg=linux-kernel,ver>=3.0.1,ver<=3.8
Tags: ubuntu=12.04
analysis-url: http://www.openwall.com/lists/oss-security/2014/07/08/16
exploit-db: 34134
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2014-4943]${txtrst} PPPoL2TP ${bldblu}(DoS)${txtrst}
Reqs: pkg=linux-kernel,ver>=3.2,ver<=3.15.6
Tags: 
analysis-url: https://cyseclabs.com/page?n=01102015
exploit-db: 36267
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2014-5207]${txtrst} fuse_suid
Reqs: pkg=linux-kernel,ver>=3.0.1,ver<=3.16.1
Tags: 
exploit-db: 34923
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2015-9322]${txtrst} BadIRET
Reqs: pkg=linux-kernel,ver>=3.0.1,ver<3.17.5,x86_64
Tags: RHEL<=7,fedora=20
analysis-url: http://labs.bromium.com/2015/02/02/exploiting-badiret-vulnerability-cve-2014-9322-linux-kernel-privilege-escalation/
src-url: http://site.pi3.com.pl/exp/p_cve-2014-9322.tar.gz
exploit-db:
author: Rafal 'n3rgal' Wojtczuk & Adam 'pi3' Zabrocki
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2015-3290]${txtrst} espfix64_NMI
Reqs: pkg=linux-kernel,ver>=3.13,ver<4.1.6,x86_64
Tags: 
analysis-url: http://www.openwall.com/lists/oss-security/2015/08/04/8
exploit-db: 37722
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[N/A]${txtrst} bluetooth
Reqs: pkg=linux-kernel,ver<=2.6.11
Tags:
exploit-db: 4756
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2015-1328]${txtrst} overlayfs
Reqs: pkg=linux-kernel,ver>=3.13.0,ver<=3.19.0
Tags: ubuntu=12.04|14.04|14.10|15.04
analysis-url: http://seclists.org/oss-sec/2015/q2/717
bin-url: https://web.archive.org/web/20160602192631/https://www.kernel-exploits.com/media/ofs_32
bin-url: https://web.archive.org/web/20160602192631/https://www.kernel-exploits.com/media/ofs_64
exploit-db: 37292
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2015-8660]${txtrst} overlayfs (ovl_setattr)
Reqs: pkg=linux-kernel,ver>=3.0.0,ver<=4.3.3
Tags:
analysis-url: http://www.halfdog.net/Security/2015/UserNamespaceOverlayfsSetuidWriteExec/
exploit-db: 39230
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2015-8660]${txtrst} overlayfs (ovl_setattr)
Reqs: pkg=linux-kernel,ver>=3.0.0,ver<=4.3.3
Tags: ubuntu=14.04|15.10
analysis-url: http://www.halfdog.net/Security/2015/UserNamespaceOverlayfsSetuidWriteExec/
exploit-db: 39166
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2016-0728]${txtrst} keyring
Reqs: pkg=linux-kernel,ver>=3.10,ver<4.4.1
Tags:
analysis-url: http://perception-point.io/2016/01/14/analysis-and-exploitation-of-a-linux-kernel-vulnerability-cve-2016-0728/
exploit-db: 40003
Comments: Exploit takes about ~30 minutes to run. Exploit is not reliable, see: https://cyseclabs.com/blog/cve-2016-0728-poc-not-working
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2016-2384]${txtrst} usb-midi
Reqs: pkg=linux-kernel,ver>=3.0.0,ver<=4.4.8
Tags: ubuntu=14.04,fedora=22
analysis-url: https://xairy.github.io/blog/2016/cve-2016-2384
src-url: https://raw.githubusercontent.com/xairy/kernel-exploits/master/CVE-2016-2384/poc.c
exploit-db: 41999
Comments: Requires ability to plug in a malicious USB device and to execute a malicious binary as a non-privileged user
author: Andrey 'xairy' Konovalov
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[N/A]${txtrst} target_offset
Reqs: pkg=linux-kernel,ver>=4.4.0,ver<=4.4.0,cmd:grep -qi ip_tables /proc/modules
Tags: ubuntu=16.04{kernel:4.4.0-21}
src-url: https://github.com/offensive-security/exploit-database-bin-sploits/raw/master/bin-sploits/40053.zip
Comments: ip_tables.ko needs to be loaded
exploit-db: 40049
author: Vitaly Nikolenko (vnik)
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2016-4557]${txtrst} double-fdput()
Reqs: pkg=linux-kernel,ver>=4.4,ver<4.5.5,CONFIG_BPF_SYSCALL=y,sysctl:kernel.unprivileged_bpf_disabled!=1
Tags: ubuntu=16.04{kernel:4.4.0-21-generic}
analysis-url: https://bugs.chromium.org/p/project-zero/issues/detail?id=808
src-url: https://github.com/offensive-security/exploit-database-bin-sploits/raw/master/bin-sploits/39772.zip
Comments: CONFIG_BPF_SYSCALL needs to be set && kernel.unprivileged_bpf_disabled != 1
exploit-db: 40759
author: Jann Horn
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2016-5195]${txtrst} dirtycow
Reqs: pkg=linux-kernel,ver>=2.6.22,ver<=4.8.3
Tags: debian=7|8,RHEL=5{kernel:2.6.(18|24|33)-*},RHEL=6{kernel:2.6.32-*|3.(0|2|6|8|10).*|2.6.33.9-rt31},RHEL=7{kernel:3.10.0-*|4.2.0-0.21.el7},ubuntu=16.04|14.04|12.04
analysis-url: https://github.com/dirtycow/dirtycow.github.io/wiki/VulnerabilityDetails
Comments: For RHEL/CentOS see exact vulnerable versions here: https://access.redhat.com/sites/default/files/rh-cve-2016-5195_5.sh
exploit-db: 40611
author: Phil Oester
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2016-5195]${txtrst} dirtycow 2
Reqs: pkg=linux-kernel,ver>=2.6.22,ver<=4.8.3
Tags: debian=7|8,RHEL=5|6|7,ubuntu=14.04|12.04,ubuntu=10.04{kernel:2.6.32-21-generic},ubuntu=16.04{kernel:4.4.0-21-generic}
analysis-url: https://github.com/dirtycow/dirtycow.github.io/wiki/VulnerabilityDetails
ext-url: https://www.exploit-db.com/download/40847.cpp
Comments: For RHEL/CentOS see exact vulnerable versions here: https://access.redhat.com/sites/default/files/rh-cve-2016-5195_5.sh
exploit-db: 40839
author: FireFart (author of exploit at EDB 40839); Gabriele Bonacini (author of exploit at 'ext-url')
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2016-8655]${txtrst} chocobo_root
Reqs: pkg=linux-kernel,ver>=4.4.0,ver<4.9,CONFIG_USER_NS=y,sysctl:kernel.unprivileged_userns_clone==1
Tags: ubuntu=(14.04|16.04){kernel:4.4.0-(21|22|24|28|31|34|36|38|42|43|45|47|51)-generic}
analysis-url: http://www.openwall.com/lists/oss-security/2016/12/06/1
Comments: CAP_NET_RAW capability is needed OR CONFIG_USER_NS=y needs to be enabled
bin-url: https://raw.githubusercontent.com/rapid7/metasploit-framework/master/data/exploits/CVE-2016-8655/chocobo_root
exploit-db: 40871
author: rebel
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2016-9793]${txtrst} SO_{SND|RCV}BUFFORCE
Reqs: pkg=linux-kernel,ver>=3.11,ver<4.8.14,CONFIG_USER_NS=y,sysctl:kernel.unprivileged_userns_clone==1
Tags:
analysis-url: https://github.com/xairy/kernel-exploits/tree/master/CVE-2016-9793
src-url: https://raw.githubusercontent.com/xairy/kernel-exploits/master/CVE-2016-9793/poc.c
Comments: CAP_NET_ADMIN caps OR CONFIG_USER_NS=y needed. No SMEP/SMAP/KASLR bypass included. Tested in QEMU only
exploit-db: 41995
author: Andrey 'xairy' Konovalov
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2017-6074]${txtrst} dccp
Reqs: pkg=linux-kernel,ver>=2.6.18,ver<=4.9.11,CONFIG_IP_DCCP=[my]
Tags: ubuntu=(14.04|16.04){kernel:4.4.0-62-generic}
analysis-url: http://www.openwall.com/lists/oss-security/2017/02/22/3
Comments: Requires Kernel be built with CONFIG_IP_DCCP enabled. Includes partial SMEP/SMAP bypass
exploit-db: 41458
author: Andrey 'xairy' Konovalov
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2017-7308]${txtrst} af_packet
Reqs: pkg=linux-kernel,ver>=3.2,ver<=4.10.6,CONFIG_USER_NS=y,sysctl:kernel.unprivileged_userns_clone==1
Tags: ubuntu=16.04{kernel:4.8.0-(34|36|39|41|42|44|45)-generic}
analysis-url: https://googleprojectzero.blogspot.com/2017/05/exploiting-linux-kernel-via-packet.html
src-url: https://raw.githubusercontent.com/xairy/kernel-exploits/master/CVE-2017-7308/poc.c
ext-url: https://raw.githubusercontent.com/bcoles/kernel-exploits/cve-2017-7308/CVE-2017-7308/poc.c
Comments: CAP_NET_RAW cap or CONFIG_USER_NS=y needed. Modified version at 'ext-url' adds support for additional kernels
bin-url: https://raw.githubusercontent.com/rapid7/metasploit-framework/master/data/exploits/cve-2017-7308/exploit
exploit-db: 41994
author: Andrey 'xairy' Konovalov (orginal exploit author); Brendan Coles (author of exploit update at 'ext-url')
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2017-16995]${txtrst} eBPF_verifier
Reqs: pkg=linux-kernel,ver>=4.4,ver<=4.14.8,CONFIG_BPF_SYSCALL=y,sysctl:kernel.unprivileged_bpf_disabled!=1
Tags: debian=9,fedora=25|26|27,ubuntu=14.04|16.04|17.04
analysis-url: https://ricklarabee.blogspot.com/2018/07/ebpf-and-analysis-of-get-rekt-linux.html
Comments: CONFIG_BPF_SYSCALL needs to be set && kernel.unprivileged_bpf_disabled != 1
bin-url: https://raw.githubusercontent.com/rapid7/metasploit-framework/master/data/exploits/cve-2017-16995/exploit.out
exploit-db: 45010
author: Rick Larabee
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2017-1000112]${txtrst} NETIF_F_UFO
Reqs: pkg=linux-kernel,ver>=4.4,ver<=4.13,CONFIG_USER_NS=y,sysctl:kernel.unprivileged_userns_clone==1
Tags: ubuntu=14.04{kernel:4.4.0-*},ubuntu=16.04{kernel:4.8.0-*}
analysis-url: http://www.openwall.com/lists/oss-security/2017/08/13/1
src-url: https://raw.githubusercontent.com/xairy/kernel-exploits/master/CVE-2017-1000112/poc.c
ext-url: https://raw.githubusercontent.com/bcoles/kernel-exploits/cve-2017-1000112/CVE-2017-1000112/poc.c
Comments: CAP_NET_ADMIN cap or CONFIG_USER_NS=y needed. SMEP/KASLR bypass included. Modified version at 'ext-url' adds support for additional distros/kernels
bin-url: https://raw.githubusercontent.com/rapid7/metasploit-framework/master/data/exploits/cve-2017-1000112/exploit.out
exploit-db:
author: Andrey 'xairy' Konovalov (orginal exploit author); Brendan Coles (author of exploit update at 'ext-url')
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2017-1000253]${txtrst} PIE_stack_corruption
Reqs: pkg=linux-kernel,ver>=3.2,ver<=4.13,x86_64
Tags: RHEL=6,RHEL=7{kernel:3.10.0-514.21.2|3.10.0-514.26.1}
analysis-url: https://www.qualys.com/2017/09/26/linux-pie-cve-2017-1000253/cve-2017-1000253.txt
src-url: https://www.qualys.com/2017/09/26/linux-pie-cve-2017-1000253/cve-2017-1000253.c
exploit-db: 42887
author: Qualys
Comments:
EOF
)

############ USERSPACE EXPLOITS ###########################
n=0

EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2004-0186]${txtrst} samba
Reqs: pkg=samba,ver<=2.2.8
Tags: 
exploit-db: 23674
EOF
)

EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2009-1185]${txtrst} udev
Reqs: pkg=udev,cmd:[[ -f /etc/udev/rules.d/95-udev-late.rules || -f /lib/udev/rules.d/95-udev-late.rules ]]
Tags: ubuntu=8.10|9.04
exploit-db: 8572
Comments: Version<1.4.1 vulnerable but distros use own versioning scheme. Manual verification needed 
EOF
)

EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2009-1185]${txtrst} udev 2
Reqs: pkg=udev
Tags:
exploit-db: 8478
Comments: SSH access to non privileged user is needed. Version<1.4.1 vulnerable but distros use own versioning scheme. Manual verification needed
EOF
)

EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2010-0832]${txtrst} PAM MOTD
Reqs: pkg=libpam-modules,ver<=1.1.1
Tags: ubuntu=9.10|10.04
exploit-db: 14339
Comments: SSH access to non privileged user is needed
EOF
)

EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2011-1485]${txtrst} pkexec
Reqs: pkg=polkit,ver=0.96
Tags: RHEL=6,ubuntu=10.04|10.10
exploit-db: 17942
EOF
)

EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2012-0809]${txtrst} death_star (sudo)
Reqs: pkg=sudo,ver>=1.8.0,ver<=1.8.3
Tags: fedora=16 
analysis-url: http://seclists.org/fulldisclosure/2012/Jan/att-590/advisory_sudo.txt
exploit-db: 18436
EOF
)

EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2014-0476]${txtrst} chkrootkit
Reqs: pkg=chkrootkit,ver<0.50
Tags: 
analysis-url: http://seclists.org/oss-sec/2014/q2/430
exploit-db: 33899
Comments: Rooting depends on the crontab (up to one day of dealy)
EOF
)

EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2014-5119]${txtrst} __gconv_translit_find
Reqs: pkg=glibc|libc6,x86
Tags: debian=6
analysis-url: http://googleprojectzero.blogspot.com/2014/08/the-poisoned-nul-byte-2014-edition.html
src-url: https://github.com/offensive-security/exploit-database-bin-sploits/raw/master/bin-sploits/34421.tar.gz
exploit-db: 34421
EOF
)

EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2015-1862]${txtrst} newpid (abrt)
Reqs: pkg=abrt,cmd:grep -qi abrt /proc/sys/kernel/core_pattern
Tags: fedora=20
analysis-url: http://openwall.com/lists/oss-security/2015/04/14/4
src-url: https://gist.githubusercontent.com/taviso/0f02c255c13c5c113406/raw/eafac78dce51329b03bea7167f1271718bee4dcc/newpid.c
exploit-db: 36746
EOF
)

EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2015-3315]${txtrst} raceabrt
Reqs: pkg=abrt,cmd:grep -qi abrt /proc/sys/kernel/core_pattern
Tags: fedora=19|20|21,RHEL=7
analysis-url: http://seclists.org/oss-sec/2015/q2/130
src-url: https://gist.githubusercontent.com/taviso/fe359006836d6cd1091e/raw/32fe8481c434f8cad5bcf8529789231627e5074c/raceabrt.c
exploit-db: 36747
EOF
)

EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2015-1318]${txtrst} newpid (apport)
Reqs: pkg=apport,ver>=2.13,ver<=2.17,cmd:grep -qi apport /proc/sys/kernel/core_pattern
Tags: ubuntu=14.04
analysis-url: http://openwall.com/lists/oss-security/2015/04/14/4
src-url: https://gist.githubusercontent.com/taviso/0f02c255c13c5c113406/raw/eafac78dce51329b03bea7167f1271718bee4dcc/newpid.c
exploit-db: 36746
EOF
)

EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2015-1318]${txtrst} newpid (apport) 2
Reqs: pkg=apport,ver>=2.13,ver<=2.17,cmd:grep -qi apport /proc/sys/kernel/core_pattern
Tags: ubuntu=14.04.2
analysis-url: http://openwall.com/lists/oss-security/2015/04/14/4
exploit-db: 36782
EOF
)

EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2015-3202]${txtrst} fuse (fusermount)
Reqs: pkg=fuse,ver<2.9.3
Tags: debian=7.0|8.0,ubuntu=*
analysis-url: http://seclists.org/oss-sec/2015/q2/520
exploit-db: 37089
Comments: Needs cron or system admin interaction
EOF
)

EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2015-1815]${txtrst} setroubleshoot
Reqs: pkg=setroubleshoot,ver<3.2.22
Tags: fedora=21
exploit-db: 36564
EOF
)

EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2015-3246]${txtrst} userhelper
Reqs: pkg=libuser,ver<=0.60
Tags: RHEL<=7,centos<=7,fedora<=22
analysis-url: https://www.qualys.com/2015/07/23/cve-2015-3245-cve-2015-3246/cve-2015-3245-cve-2015-3246.txt 
exploit-db: 37706
EOF
)

EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2015-6565]${txtrst} not_an_sshnuke
Reqs: pkg=openssh-server,ver>=6.8,ver<=6.9
Tags:
analysis-url: http://www.openwall.com/lists/oss-security/2017/01/26/2
exploit-db: 41173
author: Federico Bento
Comments: Needs admin interaction (root user needs to login via ssh to trigger exploitation)
EOF
)

EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2016-1240]${txtrst} tomcat-rootprivesc-deb.sh
Reqs: pkg=tomcat
Tags: debian=8,ubuntu=16.04
analysis-url: https://legalhackers.com/advisories/Tomcat-DebPkgs-Root-Privilege-Escalation-Exploit-CVE-2016-1240.html
src-url: http://legalhackers.com/exploits/tomcat-rootprivesc-deb.sh
exploit-db: 40450
author: Dawid Golunski
Comments: Affects only Debian-based distros
EOF
)

EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2016-1247]${txtrst} nginxed-root.sh
Reqs: pkg=nginx|nginx-full
Tags: debian=8,ubuntu=14.04|16.04|16.10
analysis-url: https://legalhackers.com/advisories/Nginx-Exploit-Deb-Root-PrivEsc-CVE-2016-1247.html
src-url: https://legalhackers.com/exploits/CVE-2016-1247/nginxed-root.sh
exploit-db: 40768
author: Dawid Golunski
Comments: Rooting depends on cron.daily (up to 24h of dealy). Affected: deb8: <1.6.2; 14.04: <1.4.6; 16.04: 1.10.0
EOF
)

EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2016-1531]${txtrst} perl_startup (exim)
Reqs: pkg=exim,ver<4.86.2
Tags: 
analysis-url: http://www.exim.org/static/doc/CVE-2016-1531.txt
exploit-db: 39549
EOF
)

EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2016-1531]${txtrst} perl_startup (exim) 2
Reqs: pkg=exim,ver<4.86.2
Tags: 
analysis-url: http://www.exim.org/static/doc/CVE-2016-1531.txt
exploit-db: 39535
EOF
)

EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2016-4989]${txtrst} setroubleshoot 2
Reqs: pkg=setroubleshoot
Tags: RHEL=6|7
analysis-url: https://c-skills.blogspot.com/2016/06/lets-feed-attacker-input-to-sh-c-to-see.html
src-url: https://github.com/stealth/troubleshooter/raw/master/straight-shooter.c
exploit-db:
EOF
)

EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2016-5425]${txtrst} tomcat-RH-root.sh
Reqs: pkg=tomcat
Tags: RHEL=7
analysis-url: http://legalhackers.com/advisories/Tomcat-RedHat-Pkgs-Root-PrivEsc-Exploit-CVE-2016-5425.html
src-url: http://legalhackers.com/exploits/tomcat-RH-root.sh
exploit-db: 40488
author: Dawid Golunski
Comments: Affects only RedHat-based distros
EOF
)

EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2016-6663,CVE-2016-6664|CVE-2016-6662]${txtrst} mysql-exploit-chain
Reqs: pkg=mysql-server|mariadb-server,ver<5.5.52
Tags: ubuntu=16.04.1
analysis-url: https://legalhackers.com/advisories/MySQL-Maria-Percona-PrivEscRace-CVE-2016-6663-5616-Exploit.html
src-url: http://legalhackers.com/exploits/CVE-2016-6663/mysql-privesc-race.c
exploit-db: 40678
author: Dawid Golunski
Comments: Also MariaDB ver<10.1.18 and ver<10.0.28 affected
EOF
)

EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2016-9566]${txtrst} nagios-root-privesc
Reqs: pkg=nagios,ver<4.2.4
Tags:
analysis-url: https://legalhackers.com/advisories/Nagios-Exploit-Root-PrivEsc-CVE-2016-9566.html
src-url: https://legalhackers.com/exploits/CVE-2016-9566/nagios-root-privesc.sh
exploit-db: 40921
author: Dawid Golunski
Comments: Allows priv escalation from nagios user or nagios group
EOF
)

EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2017-0358]${txtrst} ntfs-3g-modprobe
Reqs: pkg=ntfs-3g
Tags: ubuntu=16.04|16.10,debian=7|8
analysis-url: https://bugs.chromium.org/p/project-zero/issues/detail?id=1072
src-url: https://github.com/offensive-security/exploit-database-bin-sploits/raw/master/bin-sploits/41356.zip
exploit-db: 41356
author: Jann Horn
Comments: Distros use own versioning scheme. Manual verification needed. Linux headers must be installed. System must have at least two CPU cores.
EOF
)

EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2017-1000367]${txtrst} Sudoer-to-root
Reqs: pkg=sudo,ver<=1.8.20,cmd:[ -f /usr/sbin/getenforce ]
Tags: RHEL=7{sudo:1.8.6p7}
analysis-url: https://www.sudo.ws/alerts/linux_tty.html
src-url: https://www.qualys.com/2017/05/30/cve-2017-1000367/linux_sudo_cve-2017-1000367.c
exploit-db: 42183
author: Qualys
Comments: Needs to be sudoer. Works only on SELinux enabled systems
EOF
)

EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2017-1000367]${txtrst} sudopwn
Reqs: pkg=sudo,ver<=1.8.20,cmd:[ -f /usr/sbin/getenforce ]
Tags:
analysis-url: https://www.sudo.ws/alerts/linux_tty.html
src-url: https://raw.githubusercontent.com/c0d3z3r0/sudo-CVE-2017-1000367/master/sudopwn.c
exploit-db:
author: c0d3z3r0
Comments: Needs to be sudoer. Works only on SELinux enabled systems
EOF
)

EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2017-1000366,CVE-2017-1000370]${txtrst} linux_ldso_hwcap
Reqs: pkg=glibc|libc6,ver<=2.25,x86
Tags:
analysis-url: https://www.qualys.com/2017/06/19/stack-clash/stack-clash.txt
src-url: https://www.qualys.com/2017/06/19/stack-clash/linux_ldso_hwcap.c
exploit-db: 42274
author: Qualys
Comments: Uses "Stack Clash" technique, works against most SUID-root binaries
EOF
)

EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2017-1000366,CVE-2017-1000371]${txtrst} linux_ldso_dynamic
Reqs: pkg=glibc|libc6,ver<=2.25,x86
Tags: debian=9|10,ubuntu=14.04.5|16.04.2|17.04,fedora=23|24|25
analysis-url: https://www.qualys.com/2017/06/19/stack-clash/stack-clash.txt
src-url: https://www.qualys.com/2017/06/19/stack-clash/linux_ldso_dynamic.c
exploit-db: 42276
author: Qualys
Comments: Uses "Stack Clash" technique, works against most SUID-root PIEs
EOF
)

EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2017-1000366,CVE-2017-1000379]${txtrst} linux_ldso_hwcap_64
Reqs: pkg=glibc|libc6,ver<=2.25,x86_64
Tags: debian=7.7|8.5|9.0,ubuntu=14.04.2|16.04.2|17.04,fedora=22|25,centos=7.3.1611
analysis-url: https://www.qualys.com/2017/06/19/stack-clash/stack-clash.txt
src-url: https://www.qualys.com/2017/06/19/stack-clash/linux_ldso_hwcap_64.c
exploit-db: 42275
author: Qualys
Comments: Uses "Stack Clash" technique, works against most SUID-root binaries
EOF
)

EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2017-1000370,CVE-2017-1000371]${txtrst} linux_offset2lib
Reqs: pkg=glibc|libc6,ver<=2.25,x86
Tags:
analysis-url: https://www.qualys.com/2017/06/19/stack-clash/stack-clash.txt
src-url: https://www.qualys.com/2017/06/19/stack-clash/linux_offset2lib.c
exploit-db: 42273
author: Qualys
Comments: Uses "Stack Clash" technique
EOF
)

EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2018-1000001]${txtrst} RationalLove
Reqs: pkg=glibc|libc6,ver<2.27,CONFIG_USER_NS=y,sysctl:kernel.unprivileged_userns_clone==1,x86_64
Tags: debian=9{glibc:2.24-11+deb9u1},ubuntu=16.04.3{glibc:2.23-0ubuntu9}
analysis-url: https://www.halfdog.net/Security/2017/LibcRealpathBufferUnderflow/
src-url: https://www.halfdog.net/Security/2017/LibcRealpathBufferUnderflow/RationalLove.c
Comments: kernel.unprivileged_userns_clone=1 required
bin-url: https://raw.githubusercontent.com/rapid7/metasploit-framework/master/data/exploits/cve-2018-1000001/RationalLove
exploit-db: 43775
author: halfdog
EOF
)

EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2018-10900]${txtrst} vpnc_privesc.py
Reqs: pkg=networkmanager-vpnc|network-manager-vpnc,ver<1.2.6
Tags: ubuntu=16.04,debian=9,manjaro=17
analysis-url: https://pulsesecurity.co.nz/advisories/NM-VPNC-Privesc
src-url: https://bugzilla.novell.com/attachment.cgi?id=779110
exploit-db: 45313
author: Denis Andzakovic
Comments: Distros use own versioning scheme. Manual verification needed.
EOF
)

EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2018-14665]${txtrst} centos-xorg-logfile-lpe-cve-2018-14665.sh
Reqs: pkg=xorg-x11-server-Xorg,cmd:[ -u /usr/bin/Xorg ]
Tags: centos=7.4
analysis-url: https://www.securepatterns.com/2018/10/cve-2018-14665-xorg-x-server.html
src-url: https://gist.github.com/bcoles/9892387d1a65f27853ab0dbbbcb49d84/raw/7c29ec0964247ed89f20897fb26a5f36e5cccffd/centos-xorg-logfile-lpe-cve-2018-14665.sh
author: Hacker Fantastic
Comments: Overwrites /etc/shadow. X.Org Server 1.19 is vulnerable. Distros use own versioning scheme. Manual verification needed.
EOF
)

###########################################################
## security related HW/kernel features
###########################################################
n=0

FEATURES[((n++))]=$(cat <<EOF
section: Kernel protection mechanisms:
EOF
)

FEATURES[((n++))]=$(cat <<EOF
feature: GCC stack protector support
available: CONFIG_CC_STACKPROTECTOR=y
analysis-url: https://github.com/mzet-/les-res/blob/master/features/stackprotector-regular.md
EOF
)

FEATURES[((n++))]=$(cat <<EOF
feature: GCC stack protector STRONG support
available: CONFIG_CC_STACKPROTECTOR_STRONG=y,ver>=3.14
analysis-url: https://github.com/mzet-/les-res/blob/master/features/stackprotector-strong.md
EOF
)

FEATURES[((n++))]=$(cat <<EOF
feature: Low address space to protect from user allocation
available: CONFIG_DEFAULT_MMAP_MIN_ADDR=[0-9]+
enabled: sysctl:vm.mmap_min_addr!=0
analysis-url: https://github.com/mzet-/les-res/blob/master/features/mmap_min_addr.md
EOF
)

FEATURES[((n++))]=$(cat <<EOF
feature: Hiding kernel pointers in /proc/kallsyms
available: ver>=2.6.28
enabled: sysctl:kernel.kptr_restrict!=0
analysis-url: https://github.com/mzet-/les-res/blob/master/features/kptr_restrict.md
EOF
)

FEATURES[((n++))]=$(cat <<EOF
feature: Restrict unprivileged access to kernel syslog
available: ver>=2.6.37
enabled: sysctl:kernel.dmesg_restrict!=0
analysis-url: https://github.com/mzet-/les-res/blob/master/features/dmesg_restrict.md
EOF
)

FEATURES[((n++))]=$(cat <<EOF
feature: Supervisor Mode Execution Protection (SMEP) support
available: ver>=3.0,cmd:grep -qi smep /proc/cpuinfo
enabled: cmd:grep -qi smep /proc/cpuinfo
analysis-url: https://github.com/mzet-/les-res/blob/master/features/smep.md
EOF
)

FEATURES[((n++))]=$(cat <<EOF
feature: Supervisor Mode Access Prevention (SMAP) support
available: ver>=3.7,cmd:grep -qi smap /proc/cpuinfo
enabled: cmd:grep -qi smap /proc/cpuinfo
analysis-url: https://github.com/mzet-/les-res/blob/master/features/smap.md
EOF
)

FEATURES[((n++))]=$(cat <<EOF
feature: Randomize the address of the kernel image (KASLR)
available: CONFIG_RANDOMIZE_BASE=y
analysis-url: https://github.com/mzet-/les-res/blob/master/features/kaslr.md
EOF
)

FEATURES[((n++))]=$(cat <<EOF
feature: Hardened user copy support
available: CONFIG_HARDENED_USERCOPY=y
analysis-url: https://github.com/mzet-/les-res/blob/master/features/hardened_usercopy.md
EOF
)

FEATURES[((n++))]=$(cat <<EOF
feature: Make kernel text and rodata read-only
available: CONFIG_STRICT_KERNEL_RWX=y
analysis-url: https://github.com/mzet-/les-res/blob/master/features/strict_kernel_rwx.md
EOF
)

FEATURES[((n++))]=$(cat <<EOF
feature: Set loadable kernel module data as NX and text as RO
available: CONFIG_STRICT_MODULE_RWX=y
analysis-url: https://github.com/mzet-/les-res/blob/master/features/strict_module_rwx.md
EOF
)

FEATURES[((n++))]=$(cat <<EOF
feature: Restrict /dev/mem access
available: CONFIG_STRICT_DEVMEM=y
analysis-url: https://github.com/mzet-/les-res/blob/master/features/strict_devmem.md
EOF
)

FEATURES[((n++))]=$(cat <<EOF
feature: Restrict I/O access to /dev/mem
available: CONFIG_IO_STRICT_DEVMEM=y
analysis-url: https://github.com/mzet-/les-res/blob/master/features/io_strict_devmem.md
EOF
)

FEATURES[((n++))]=$(cat <<EOF
section: Attack Surface:
EOF
)

FEATURES[((n++))]=$(cat <<EOF
feature: Support for /dev/mem access
available: CONFIG_DEVMEM=y
analysis-url: https://github.com/mzet-/les-res/blob/master/features/devmem.md
EOF
)

FEATURES[((n++))]=$(cat <<EOF
feature: Support for /dev/kmem access
available: CONFIG_DEVKMEM=y
analysis-url: https://github.com/mzet-/les-res/blob/master/features/devkmem.md
EOF
)

FEATURES[((n++))]=$(cat <<EOF
feature: User namespaces for unprivileged accounts
available: CONFIG_USER_NS=y
enabled: sysctl:kernel.unprivileged_userns_clone==1
analysis-url: https://github.com/mzet-/les-res/blob/master/features/user_ns.md
EOF
)

FEATURES[((n++))]=$(cat <<EOF
feature: Unprivileged access to bpf() system call
available: CONFIG_BPF_SYSCALL=y
enabled: sysctl:kernel.unprivileged_bpf_disabled!=1
analysis-url: https://github.com/mzet-/les-res/blob/master/features/bpf_syscall.md
EOF
)

version() {
    echo "linux-exploit-suggester "$VERSION", mzet, http://z-labs.eu, February 2018"
}

usage() {
    echo "Usage: linux-exploit-suggester.sh [OPTIONS]"
    echo
    echo " -V | --version               - print version of this script"
    echo " -h | --help                  - print this help"
    echo " -k | --kernel <version>      - provide kernel version"
    echo " -u | --uname <string>        - provide 'uname -a' string"
    echo " --skip-more-checks           - do not perform additional checks (kernel config, sysctl) to determine if exploit is applicable"
    echo " --skip-pkg-versions          - skip checking for exact userspace package version (helps to avoid false negatives)"
    echo " -p | --pkglist-file <file>   - provide file with 'dpkg -l' or 'rpm -qa' command output"
    echo " --cvelist-file <file>        - provide file with Linux kernel CVEs list"
    echo " --checksec                   - list security related features for your HW/kernel"
    echo " -s | --fetch-sources         - automatically downloads source for matched exploit"
    echo " -b | --fetch-binaries        - automatically downloads binary for matched exploit if available"
    echo " -f | --full                  - show full info about matched exploit"
    echo " -g | --short                 - show shorten info about matched exploit"
    echo " --kernelspace-only           - show only kernel vulnerabilities"
    echo " --userspace-only             - show only userspace vulnerabilities"
    echo " -d | --show-dos              - show also DoSes in results"
}

exitWithErrMsg() {
    echo "$1" 1>&2
    exit 1
}

# extracts all information from output of 'uname -a' command
parseUname() {
    local uname=$1

    KERNEL=$(echo "$uname" | awk '{print $3}' | cut -d '-' -f 1)
    KERNEL_ALL=$(echo "$uname" | awk '{print $3}')
    ARCH=$(echo "$uname" | awk '{print $(NF-1)}')

    OS=""
    echo "$uname" | grep -q -i 'deb' && OS="debian"
    echo "$uname" | grep -q -i 'ubuntu' && OS="ubuntu"
    echo "$uname" | grep -q -i '\-ARCH' && OS="arch"
    echo "$uname" | grep -q -i '\-deepin' && OS="deepin"
    echo "$uname" | grep -q -i '\-MANJARO' && OS="manjaro"
    echo "$uname" | grep -q -i '\.fc' && OS="fedora"
    echo "$uname" | grep -q -i '\.el' && OS="RHEL"
    echo "$uname" | grep -q -i '\.mga' && OS="mageia"

    # 'uname -a' output doesn't contain distribution number (at least not in case of all distros)
}

getPkgList() {
    local distro=$1
    local pkglist_file=$2
    
    # take package listing from provided file & detect if it's 'rpm -qa' listing or 'dpkg -l' or 'pacman -Q' listing of not recognized listing
    if [ "$opt_pkglist_file" = "true" -a -e "$pkglist_file" ]; then

        # ubuntu/debian package listing file
        if [ $(cat "$pkglist_file" | head -1 | grep 'Desired=Unknown/Install/Remove/Purge/Hold') ]; then 
            PKG_LIST=$(cat "$pkglist_file" | awk '{print $2"-"$3}' | sed 's/:amd64//g')

            OS="debian"
            [ "$(cat "$pkglist_file" | grep "ubuntu")" ] && OS="ubuntu"
        # redhat package listing file
        elif [ $(cat "$pkglist_file" | head -1 | grep -E '\.el[1-9]+\.') ]; then
            PKG_LIST=$(cat "$pkglist_file")
            OS="RHEL"
        # fedora package listing file
        elif [ $(cat "$pkglist_file" | head -1 | grep -E '\.fc[1-9]+') ]; then
            PKG_LIST=$(cat "$pkglist_file")
            OS="fedora"
        # mageia package listing file
        elif [ $(cat "$pkglist_file" | head -1 | grep -E '\.mga[1-9]+') ]; then
            PKG_LIST=$(cat "$pkglist_file")
            OS="mageia"
        # pacman package listing file
        elif [ "$(head -1 $pkglist_file | grep -E '\ [0-9]+\.')" ]; then
            PKG_LIST=$(cat "$pkglist_file" | awk '{print $1"-"$2}')
            OS="arch"
        # file not recognized - skipping
        else
            PKG_LIST=""
        fi

    elif [ "$distro" = "debian" -o "$distro" = "ubuntu" -o "$distro" = "deepin" ]; then
        PKG_LIST=$(dpkg -l | awk '{print $2"-"$3}' | sed 's/:amd64//g')
    elif [ "$distro" = "RHEL" -o "$distro" = "fedora" -o "$distro" = "mageia" ]; then
        PKG_LIST=$(rpm -qa)
    elif [ "$distro" = "arch" -o "$distro" = "manjaro" ]; then
        PKG_LIST=$(pacman -Q | awk '{print $1"-"$2}')
    else
        # packages listing not available
        PKG_LIST=""
    fi
}

# from: https://stackoverflow.com/questions/4023830/how-compare-two-strings-in-dot-separated-version-format-in-bash
verComparision() {

    if [[ $1 == $2 ]]
    then
        return 0
    fi

    local IFS=.
    local i ver1=($1) ver2=($2)

    # fill empty fields in ver1 with zeros
    for ((i=${#ver1[@]}; i<${#ver2[@]}; i++))
    do
        ver1[i]=0
    done

    for ((i=0; i<${#ver1[@]}; i++))
    do
        if [[ -z ${ver2[i]} ]]
        then
            # fill empty fields in ver2 with zeros
            ver2[i]=0
        fi
        if ((10#${ver1[i]} > 10#${ver2[i]}))
        then
            return 1
        fi
        if ((10#${ver1[i]} < 10#${ver2[i]}))
        then
            return 2
        fi
    done

    return 0
}

doVersionComparision() {
    local reqVersion="$1"
    local reqRelation="$2"
    local currentVersion="$3"

    verComparision $currentVersion $reqVersion
    case $? in
        0) currentRelation='=';;
        1) currentRelation='>';;
        2) currentRelation='<';;
    esac

    if [ "$reqRelation" == "=" ]; then
        [ $currentRelation == "=" ] && return 0
    elif [ "$reqRelation" == ">" ]; then
        [ $currentRelation == ">" ] && return 0
    elif [ "$reqRelation" == "<" ]; then
        [ $currentRelation == "<" ] && return 0
    elif [ "$reqRelation" == ">=" ]; then
        [ $currentRelation == "=" ] && return 0
        [ $currentRelation == ">" ] && return 0
    elif [ "$reqRelation" == "<=" ]; then
        [ $currentRelation == "=" ] && return 0
        [ $currentRelation == "<" ] && return 0
    fi
}

compareValues() {
    curVal=$1
    val=$2
    sign=$3

    if [ "$sign" == "==" ]; then
        [ "$val" == "$curVal" ] && return 0
    elif [ "$sign" == "!=" ]; then
        [ "$val" != "$curVal" ] && return 0
    fi

    return 1
}

checkRequirement() {
    #echo "Checking requirement: $1"
    local IN="$1"
    local pkgName="${2:4}"

    if [[ "$IN" =~ ^pkg=.*$ ]]; then

        # always true for Linux OS
        [ ${pkgName} == "linux-kernel" ] && return 0

        # verify if package is present 
        pkg=$(echo "$PKG_LIST" | grep -E -i "^$pkgName-[0-9]+" | head -1)
        if [ -n "$pkg" ]; then
            return 0
        fi

    elif [[ "$IN" =~ ^ver.*$ ]]; then
        version="${IN//[^0-9.]/}"
        rest="${IN#ver}"
        operator=${rest%$version}

        if [ "$pkgName" == "linux-kernel" -o "$opt_checksec_mode" == "true" ]; then

            # for --cvelist-file mode skip kernel version comparision
            [ "$opt_cvelist_file" = "true" ] && return 0

            doVersionComparision $version $operator $KERNEL && return 0
        else
            # extract package version and check if requiremnt is true
            pkg=$(echo "$PKG_LIST" | grep -E -i "^$pkgName-[0-9]+" | head -1)

            # skip (if run with --skip-pkg-versions) version checking if package with given name is installed
            [ "$opt_skip_pkg_versions" = "true" -a -n "$pkg" ] && return 0

            # versioning:
            #echo "pkg: $pkg"
            pkgVersion=$(echo "$pkg" | grep -E -i -o -e '-[\.0-9\+:p]+[-\+]' | cut -d':' -f2 | sed 's/[\+-]//g' | sed 's/p[0-9]//g')
            #echo "version: $pkgVersion"
            #echo "operator: $operator"
            #echo "required version: $version"
            #echo
            doVersionComparision $version $operator $pkgVersion && return 0
        fi
    elif [[ "$IN" =~ ^x86_64$ ]] && [ "$ARCH" == "x86_64" -o "$ARCH" == "" ]; then
        return 0
    elif [[ "$IN" =~ ^x86$ ]] && [ "$ARCH" == "i386" -o "$ARCH" == "i686" -o "$ARCH" == "" ]; then
        return 0
    elif [[ "$IN" =~ ^CONFIG_.*$ ]]; then

        # skip if check is not applicable (-k or --uname or -p set) or if user said so (--skip-more-checks)
        [ "$opt_skip_more_checks" = "true" ] && return 0

        # if kernel config IS available:
        if [ -n "$KCONFIG" ]; then
            if $KCONFIG | grep -E -qi $IN; then
                return 0;
            # required option wasn't found, exploit is not applicable
            else
                return 1;
            fi
        # config is not available
        else
            return 0;
        fi
    elif [[ "$IN" =~ ^sysctl:.*$ ]]; then

        # skip if check is not applicable (-k or --uname or -p modes) or if user said so (--skip-more-checks)
        [ "$opt_skip_more_checks" = "true" ] && return 0

        sysctlCondition="${IN:7}"

        # extract sysctl entry, relation sign and required value
        if echo $sysctlCondition | grep -qi "!="; then
            sign="!="
        elif echo $sysctlCondition | grep -qi "=="; then
            sign="=="
        else
            exitWithErrMsg "Wrong sysctl condition. There is syntax error in your features DB. Aborting."
        fi
        val=$(echo "$sysctlCondition" | awk -F "$sign" '{print $2}')
        entry=$(echo "$sysctlCondition" | awk -F "$sign" '{print $1}')

        # get current setting of sysctl entry
        curVal=$(/sbin/sysctl -a 2> /dev/null | grep "$entry" | awk -F'=' '{print $2}')

        # special case for --checksec mode: return 2 if there is no such switch in sysctl
        [ -z "$curVal" -a "$opt_checksec_mode" = "true" ] && return 2

        # for other modes: skip if there is no such switch in sysctl
        [ -z "$curVal" ] && return 0

        # compare & return result
        compareValues $curVal $val $sign && return 0

    elif [[ "$IN" =~ ^cmd:.*$ ]]; then

        # skip if check is not applicable (-k or --uname or -p modes) or if user said so (--skip-more-checks)
        [ "$opt_skip_more_checks" = "true" ] && return 0

        cmd="${IN:4}"
        if eval "${cmd}"; then
            return 0
        fi
    fi

    return 1
}

getKernelConfig() {
    if [ -f /proc/config.gz ] ; then
        KCONFIG="zcat /proc/config.gz"
    elif [ -f /boot/config-`uname -r` ] ; then
        KCONFIG="cat /boot/config-`uname -r`"
    elif [ -f "${KBUILD_OUTPUT:-/usr/src/linux}"/.config ] ; then
        KCONFIG="cat ${KBUILD_OUTPUT:-/usr/src/linux}/.config"
    else
        KCONFIG=""
    fi
}

checksecMode() {

    # start analysis
for FEATURE in "${FEATURES[@]}"; do

    # create array from current exploit here doc and fetch needed lines
    i=0
    # ('-r' is used to not interpret backslash used for bash colors)
    while read -r line
    do
        arr[i]="$line"
        i=$((i + 1))
    done <<< "$FEATURE"

    NAME="${arr[0]}"
    PRE_NAME="${NAME:0:8}"
    NAME="${NAME:9}"
    if [ "${PRE_NAME}" = "section:" ]; then
        echo
        echo -e "${bldwht}${NAME}${txtrst}"
        echo
        continue
    fi

    AVAILABLE="${arr[1]}" && AVAILABLE="${AVAILABLE:11}"
    ENABLE=$(echo "$FEATURE" | grep "enabled: " | awk -F'ed: ' '{print $2}')
    analysis_url=$(echo "$FEATURE" | grep "analysis-url: " | awk '{print $2}')

    # split line with availability requirements & loop thru all availability reqs one by one & check whether it is met
    IFS=',' read -r -a array <<< "$AVAILABLE"
    AVAILABLE_REQS_NUM=${#array[@]}
    AVAILABLE_PASSED_REQ=0
    for REQ in "${array[@]}"; do
        if (checkRequirement "$REQ"); then
            AVAILABLE_PASSED_REQ=$(($AVAILABLE_PASSED_REQ + 1))
        else
            break
        fi
    done

    # split line with enablement requirements & loop thru all enablement reqs one by one & check whether it is met
    ENABLE_PASSED_REQ=0
    ENABLE_REQS_NUM=-1
    noSysctl=0
    if [ -n "$ENABLE" ]; then
        IFS=',' read -r -a array <<< "$ENABLE"
        ENABLE_REQS_NUM=${#array[@]}
        for REQ in "${array[@]}"; do
            checkRequirement "$REQ"
            retVal=$?
            if [ $retVal -eq 0 ]; then
                ENABLE_PASSED_REQ=$(($ENABLE_PASSED_REQ + 1))
            elif [ $retVal -eq 2 ]; then
            # special case: sysctl entry is not present on given system: signal it as: N/A
                noSysctl=1
                break
            else
                break
            fi
        done
    fi

    feature=$(echo "$FEATURE" | grep "feature: " | cut -d' ' -f 2-)

    available="${txtred}Available${txtrst}"
    enabled="  ${txtgray}N/A${txtrst}  "

    if [ $AVAILABLE_PASSED_REQ -eq $AVAILABLE_REQS_NUM ]; then
        available="${txtgrn}Available${txtrst}"
    fi

    if [ $ENABLE_PASSED_REQ -eq $ENABLE_REQS_NUM -a $noSysctl -eq 0 -a -n "$ENABLE" ]; then
        enabled="${txtgrn}Enabled${txtrst}"
    elif [ -n "$ENABLE" -a $noSysctl -eq 0 ]; then
        enabled="${txtred}Disabled${txtrst}"
    fi

    # short (--short) output
    if [ "$opt_summary" = "true" ]; then
        echo -e "[ $available ][ $enabled ] $feature"
        continue
    fi

    echo -e "[+] $feature"
    echo -e "\n   [ $available ]: $AVAILABLE"
    [ -n "$ENABLE" ] && echo -e "   [ $enabled ]: $ENABLE"
    [ -n "$analysis_url" ] && echo -e "   Feature analysis: $analysis_url"
    echo

done

}

# parse command line parameters
ARGS=$(getopt --options $SHORTOPTS  --longoptions $LONGOPTS -- "$@")
[ $? != 0 ] && exitWithErrMsg "Aborting."

eval set -- "$ARGS"

while true; do
    case "$1" in
        -u|--uname)
            shift
            UNAME_A="$1"
            opt_uname_string=true
            ;;
        -V|--version)
            version
            exit 0
            ;;
        -h|--help)
            usage 
            exit 0
            ;;
        -f|--full)
            opt_full=true
            ;;
        -g|--short)
            opt_summary=true
            ;;
        -b|--fetch-binaries)
            opt_fetch_bins=true
            ;;
        -s|--fetch-sources)
            opt_fetch_srcs=true
            ;;
        -k|--kernel)
            shift
            KERNEL="$1"
            opt_kernel_version=true
            ;;
        -d|--show-dos)
            opt_show_dos=true
            ;;
        -p|--pkglist-file)
            shift
            PKGLIST_FILE="$1"
            opt_pkglist_file=true
            ;;
        --cvelist-file)
            shift
            CVELIST_FILE="$1"
            opt_cvelist_file=true
            ;;
        --checksec)
            opt_checksec_mode=true
            ;;
        --kernelspace-only)
            opt_kernel_only=true
            ;;
        --userspace-only)
            opt_userspace_only=true
            ;;
        --skip-more-checks)
            opt_skip_more_checks=true
            ;;
        --skip-pkg-versions)
            opt_skip_pkg_versions=true
            ;;
        *)
            shift
            if [ "$#" != "0" ]; then
                exitWithErrMsg "Unknown option '$1'. Aborting."
            fi
            break
            ;;
    esac
    shift
done

# check Bash version (associative arrays need Bash in version 4.0+)
if ((BASH_VERSINFO[0] < 4)); then
    exitWithErrMsg "Script needs Bash in version 4.0 or newer. Aborting."
fi

# exit if both --kernel and --uname are set
[ "$opt_kernel_version" = "true" ] && [ $opt_uname_string = "true" ] && exitWithErrMsg "Switches -u|--uname and -k|--kernel are mutually exclusive. Aborting."

# exit if both --full and --short are set
[ "$opt_full" = "true" ] && [ $opt_summary = "true" ] && exitWithErrMsg "Switches -f|--full and -g|--short are mutually exclusive. Aborting."

# --cvelist-file mode is standalone mode and is not applicable when one of -k | -u | -p | --checksec switches are set
if [ "$opt_cvelist_file" = "true" ]; then
    [ ! -e "$CVELIST_FILE" ] && exitWithErrMsg "Provided CVE list file does not exists. Aborting."
    [ "$opt_kernel_version" = "true" ] && exitWithErrMsg "Switches -k|--kernel and --cvelist-file are mutually exclusive. Aborting."
    [ "$opt_uname_string" = "true" ] && exitWithErrMsg "Switches -u|--uname and --cvelist-file are mutually exclusive. Aborting."
    [ "$opt_pkglist_file" = "true" ] && exitWithErrMsg "Switches -p|--pkglist-file and --cvelist-file are mutually exclusive. Aborting."
fi

# --checksec mode is standalone mode and is not applicable when one of -k | -u | -p | --cvelist-file switches are set
if [ "$opt_checksec_mode" = "true" ]; then
    [ "$opt_kernel_version" = "true" ] && exitWithErrMsg "Switches -k|--kernel and --checksec are mutually exclusive. Aborting."
    [ "$opt_uname_string" = "true" ] && exitWithErrMsg "Switches -u|--uname and --checksec are mutually exclusive. Aborting."
    [ "$opt_pkglist_file" = "true" ] && exitWithErrMsg "Switches -p|--pkglist-file and --checksec are mutually exclusive. Aborting."
fi

# extract kernel version and other OS info like distro name, distro version, etc. 3 possibilities here:
# case 1: --kernel set
if [ "$opt_kernel_version" == "true" ]; then
    # TODO: add kernel version number validation
    [ -z "$KERNEL" ] && exitWithErrMsg "Unrecognized kernel version given. Aborting."
    ARCH=""
    OS=""

    # do not perform additional checks on current machine
    opt_skip_more_checks=true

    # do not consider current OS
    getPkgList "" "$PKGLIST_FILE"

# case 2: --uname set
elif [ "$opt_uname_string" == "true" ]; then
    [ -z "$UNAME_A" ] && exitWithErrMsg "uname string empty. Aborting."
    parseUname "$UNAME_A"

    # do not perform additional checks on current machine
    opt_skip_more_checks=true

    # do not consider current OS
    getPkgList "" "$PKGLIST_FILE"

# case 3: --cvelist-file mode
elif [ "$opt_cvelist_file" = "true" ]; then

    # get kernel configuration in this mode
    [ "$opt_skip_more_checks" = "false" ] && getKernelConfig

# case 4: --checksec mode
elif [ "$opt_checksec_mode" = "true" ]; then

    # this switch is not applicable in this mode
    opt_skip_more_checks=false

    # get kernel configuration in this mode
    getKernelConfig
    [ -z "$KCONFIG" ] && exitWithErrMsg "Kernel configuration file not available. Aborting."

    # launch checksec mode
    checksecMode

    exit 0

# case 5: no --uname | --kernel | --cvelist-file | --checksec set
else

    # --pkglist-file NOT provided: take all info from current machine
    # case for vanilla execution: ./linux-exploit-suggester.sh
    if [ "$opt_pkglist_file" == "false" ]; then
        UNAME_A=$(uname -a)
        [ -z "$UNAME_A" ] && exitWithErrMsg "uname string empty. Aborting."
        parseUname "$UNAME_A"

        # get kernel configuration in this mode
        [ "$opt_skip_more_checks" = "false" ] && getKernelConfig

        # extract distribution version from /etc/issue
        [ -n "$OS" -a "$opt_skip_more_checks" = "false" ] && DISTRO=$(cat /etc/issue | grep -E -o '[0-9\.]+' | head -1)

        # extract package listing from current OS
        getPkgList "$OS" ""

    # --pkglist-file provided: only consider userspace exploits against provided package listing
    else
        KERNEL=""
        #TODO: extract machine arch from package listing
        ARCH=""
        unset EXPLOITS
        declare -A EXPLOITS
        getPkgList "" "$PKGLIST_FILE"

        # additional checks are not applicable for this mode
        opt_skip_more_checks=true
    fi
fi

echo
echo -e "${bldwht}Available information:${txtrst}"
echo
[ -n "$KERNEL" ] && echo -e "Kernel version: ${txtgrn}$KERNEL${txtrst}" || echo -e "Kernel version: ${txtred}N/A${txtrst}"
echo "Architecture: $([ -n "$ARCH" ] && echo -e "${txtgrn}$ARCH${txtrst}" || echo -e "${txtred}N/A${txtrst}")"
echo "Distribution: $([ -n "$OS" ] && echo -e "${txtgrn}$OS${txtrst}" || echo -e "${txtred}N/A${txtrst}")"
echo -e "Distribution version: $([ -n "$DISTRO" ] && echo -e "${txtgrn}$DISTRO${txtrst}" || echo -e "${txtred}N/A${txtrst}")"

echo "Additional checks (CONFIG_*, sysctl entries, custom Bash commands): $([ "$opt_skip_more_checks" == "false" ] && echo -e "${txtgrn}performed${txtrst}" || echo -e "${txtred}N/A${txtrst}")"

if [ -n "$PKGLIST_FILE" -a -n "$PKG_LIST" ]; then
    pkgListFile="${txtgrn}$PKGLIST_FILE${txtrst}"
elif [ -n "$PKGLIST_FILE" ]; then
    pkgListFile="${txtred}unrecognized file provided${txtrst}"
elif [ -n "$PKG_LIST" ]; then
    pkgListFile="${txtgrn}from current OS${txtrst}"
fi

echo -e "Package listing: $([ -n "$pkgListFile" ] && echo -e "$pkgListFile" || echo -e "${txtred}N/A${txtrst}")"

# handle --kernelspacy-only & --userspace-only filter options
if [ "$opt_kernel_only" = "true" -o -z "$PKG_LIST" ]; then
    unset EXPLOITS_USERSPACE
    declare -A EXPLOITS_USERSPACE
fi

if [ "$opt_userspace_only" = "true" ]; then
    unset EXPLOITS
    declare -A EXPLOITS
fi

echo
echo -e "${bldwht}Searching among:${txtrst}"
echo
echo "${#EXPLOITS[@]} kernel space exploits"
echo "${#EXPLOITS_USERSPACE[@]} user space exploits"
echo

echo -e "${bldwht}Possible Exploits:${txtrst}"
echo

# start analysis
for EXP in "${EXPLOITS[@]}" "${EXPLOITS_USERSPACE[@]}"; do

    # create array from current exploit here doc and fetch needed lines
    i=0
    # ('-r' is used to not interpret backslash used for bash colors)
    while read -r line
    do
        arr[i]="$line"
        i=$((i + 1))
    done <<< "$EXP"

    REQS="${arr[1]}" && REQS="${REQS:6}"
    NAME="${arr[0]}" && NAME="${NAME:6}"
    TAGS="${arr[2]}" && TAGS="${TAGS:6}"

    # split line with requirements & loop thru all reqs one by one & check whether it is met
    IFS=',' read -r -a array <<< "$REQS"
    REQS_NUM=${#array[@]}
    PASSED_REQ=0
    for REQ in "${array[@]}"; do
        if (checkRequirement "$REQ" "${array[0]}"); then
            PASSED_REQ=$(($PASSED_REQ + 1))
        else
            break
        fi
    done

    # execute for exploits with all requirements met
    if [ $PASSED_REQ -eq $REQS_NUM ]; then

        # additional requirement for --cvelist-file mode: check if CVE associated with the exploit is on the CVELIST_FILE
        if [ "$opt_cvelist_file" = "true" ]; then

            # extract CVE(s) associated with given exploit (also translates ',' to '|' for easy handling multiple CVEs case - via extended regex)
            cve=$(echo "$NAME" | grep '.*\[.*\].*' | cut -d 'm' -f2 | cut -d ']' -f1 | tr -d '[' | tr "," "|")
            #echo "CVE: $cve"

            # check if it's on CVELIST_FILE list, if no move to next exploit
            [ ! $(cat "$CVELIST_FILE" | grep -E "$cve") ] && continue
        fi

        # process tags and highlight those that match current OS (only for deb|ubuntu|RHEL and if we know distro version - direct mode)
        tags=""
        if [ -n "$TAGS" -a -n "$OS" -a -n "$DISTRO" ]; then
            IFS=',' read -r -a tags_array <<< "$TAGS"
            TAGS_NUM=${#tags_array[@]}
            for TAG in "${tags_array[@]}"; do
                tag_distro=$(echo "$TAG" | cut -d'=' -f1)
                tag_distro_num_all=$(echo "$TAG" | cut -d'=' -f2)
                # in case of tag of form: 'ubuntu=16.04{kernel:4.4.0-21} remove kernel versioning part for comparision
                tag_distro_num="${tag_distro_num_all%{*}"

                # if distro matches:
                if [ "$OS" == "$tag_distro" -a "$(echo "$DISTRO" | grep -E "$tag_distro_num")" ]; then

                    # get name (kernel or package name) and version of kernel/pkg if provided:
                    tag_pkg=$(echo "$tag_distro_num_all" | cut -d'{' -f 2 | tr -d '}' | cut -d':' -f 1)
                    tag_pkg_num=""
                    [ $(echo "$tag_distro_num_all" | grep '{') ] && tag_pkg_num=$(echo "$tag_distro_num_all" | cut -d'{' -f 2 | tr -d '}' | cut -d':' -f 2)

                    #[ -n "$tag_pkg_num" ] && echo "tag_pkg_num: $tag_pkg_num; kernel: $KERNEL_ALL"

                    # if pkg/kernel version is not provided:
                    if [ -z "$tag_pkg_num" ]; then
                        TAG="${lightyellow}[ ${TAG} ]${txtrst}"

                    # kernel version provided, check for match:
                    elif [ -n "$tag_pkg_num" -a "$tag_pkg" = "kernel" ]; then
                        [ $(echo "$KERNEL_ALL" | grep -E "${tag_pkg_num}") ] && TAG="${yellow}[ ${TAG} ]${txtrst}" || TAG="${lightyellow}[ $tag_distro=$tag_distro_num ]${txtrst}{kernel:$tag_pkg_num}"

                    # pkg version provided, check for match (TBD):
                    elif [ -n "$tag_pkg_num" -a -n "$tag_pkg"  ]; then
                        TAG="${lightyellow}[ $tag_distro=$tag_distro_num ]${txtrst}{$tag_pkg:$tag_pkg_num}"
                    fi

                fi

                # append current tag to tags list
                tags="${tags}${TAG},"
            done
            # trim ',' added by above loop
            [ -n "$tags" ] && tags="${tags%?}"
        else
            tags="$TAGS"
        fi

        EXPLOIT_DB=$(echo "$EXP" | grep "exploit-db: " | awk '{print $2}')
        analysis_url=$(echo "$EXP" | grep "analysis-url: " | awk '{print $2}')
        ext_url=$(echo "$EXP" | grep "ext-url: " | awk '{print $2}')
        comments=$(echo "$EXP" | grep "Comments: " | cut -d' ' -f 2-)
        reqs=$(echo "$EXP" | grep "Reqs: " | cut -d' ' -f 2)
        
        # exploit name without CVE number and without commonly used special chars
        name=$(echo "$NAME" | cut -d' ' -f 2- | tr -d ' ()/')

        src_url=$(echo "$EXP" | grep "src-url: " | awk '{print $2}')
        [ -z "$src_url" ] && [ -n "$EXPLOIT_DB" ] && src_url="https://www.exploit-db.com/download/$EXPLOIT_DB"
        [ -z "$src_url" ] && exitWithErrMsg "Both 'src-url' and 'exploit-db' entries are empty for '$NAME' exploit - fix that. Aborting."

        if [ -n "$analysis_url" ]; then
            details="$analysis_url"
        elif $(echo "$src_url" | grep -q 'www.exploit-db.com'); then
            details="https://www.exploit-db.com/exploits/$EXPLOIT_DB/"
        elif [[ "$src_url" =~ ^.*tgz|tar.gz|zip$ && -n "$EXPLOIT_DB" ]]; then
            details="https://www.exploit-db.com/exploits/$EXPLOIT_DB/"
        else
            details="$src_url"
        fi

        # skip DoS by default
        dos=$(echo "$EXP" | grep -o -i "(dos")
        [ "$opt_show_dos" == "false" ] && [ -n "$dos" ] && continue 

        # handles --fetch-binaries option
        if [ $opt_fetch_bins = "true" ]; then
            for i in $(echo "$EXP" | grep "bin-url: " | awk '{print $2}'); do
                [ -f "${name}_$(basename $i)" ] && rm -f "${name}_$(basename $i)"
                wget -q -k "$i" -O "${name}_$(basename $i)"
            done
        fi

        # handles --fetch-sources option
        if [ $opt_fetch_srcs = "true" ]; then
            [ -f "${name}_$(basename $src_url)" ] && rm -f "${name}_$(basename $src_url)"
            wget -q -k "$src_url" -O "${name}_$(basename $src_url)" &
        fi

        # display result (short)
        if [ "$opt_summary" = "true" ]; then
            [ -z "$tags" ] && tags="-"
            echo -e "$NAME || $tags || $src_url"
            continue
        fi

        # display result (standard)
        echo -e "[+] $NAME"
        echo -e "\n   Details: $details"
        [ -n "$tags" ] && echo -e "   Tags: $tags"
        echo -e "   Download URL: $src_url"
        [ -n "$ext_url" ] && echo -e "   ext-url: $ext_url"
        [ -n "$comments" ] && echo -e "   Comments: $comments"

        # handles --full filter option
        if [ "$opt_full" = "true" ]; then
            [ -n "$reqs" ] && echo -e "   Requirements: $reqs"

            [ -n "$EXPLOIT_DB" ] && echo -e "   exploit-db: $EXPLOIT_DB"

            author=$(echo "$EXP" | grep "author: " | cut -d' ' -f 2-)
            [ -n "$author" ] && echo -e "   author: $author"
        fi

        echo
    fi
done
