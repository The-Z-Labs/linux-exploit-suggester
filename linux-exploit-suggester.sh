#!/bin/bash

#
# Copyright (c) 2016-2023, https://github.com/mzet-
#
# linux-exploit-suggester.sh comes with ABSOLUTELY NO WARRANTY.
# This is free software, and you are welcome to redistribute it
# under the terms of the GNU General Public License. See LICENSE
# file for usage of this software.
#

VERSION=v1.1

# bash colors
#txtred="\e[0;31m"
txtred="\e[91;1m"
txtgrn="\e[1;32m"
txtgray="\e[0;37m"
txtblu="\e[0;36m"
txtrst="\e[0m"
bldwht='\e[1;37m'
wht='\e[0;36m'
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

## temporary array for purpose of sorting exploits (based on exploits' rank)
declare -a exploits_to_sort
declare -a SORTED_EXPLOITS

############ LINUX KERNELSPACE EXPLOITS ####################
n=0

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2004-1235]${txtrst} elflbl
Reqs: pkg=linux-kernel,ver=2.4.29
Tags:
Rank: 1
analysis-url: http://isec.pl/vulnerabilities/isec-0021-uselib.txt
bin-url: https://web.archive.org/web/20111103042904/http://tarantula.by.ru/localroot/2.6.x/elflbl
exploit-db: 744
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2004-1235]${txtrst} uselib()
Reqs: pkg=linux-kernel,ver=2.4.29
Tags:
Rank: 1
analysis-url: http://isec.pl/vulnerabilities/isec-0021-uselib.txt
exploit-db: 778
Comments: Known to work only for 2.4 series (even though 2.6 is also vulnerable)
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2004-1235]${txtrst} krad3
Reqs: pkg=linux-kernel,ver>=2.6.5,ver<=2.6.11
Tags:
Rank: 1
exploit-db: 1397
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2004-0077]${txtrst} mremap_pte
Reqs: pkg=linux-kernel,ver>=2.6.0,ver<=2.6.2
Tags:
Rank: 1
exploit-db: 160
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2006-2451]${txtrst} raptor_prctl
Reqs: pkg=linux-kernel,ver>=2.6.13,ver<=2.6.17
Tags:
Rank: 1
exploit-db: 2031
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2006-2451]${txtrst} prctl
Reqs: pkg=linux-kernel,ver>=2.6.13,ver<=2.6.17
Tags:
Rank: 1
exploit-db: 2004
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2006-2451]${txtrst} prctl2
Reqs: pkg=linux-kernel,ver>=2.6.13,ver<=2.6.17
Tags:
Rank: 1
exploit-db: 2005
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2006-2451]${txtrst} prctl3
Reqs: pkg=linux-kernel,ver>=2.6.13,ver<=2.6.17
Tags:
Rank: 1
exploit-db: 2006
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2006-2451]${txtrst} prctl4
Reqs: pkg=linux-kernel,ver>=2.6.13,ver<=2.6.17
Tags:
Rank: 1
exploit-db: 2011
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2006-3626]${txtrst} h00lyshit
Reqs: pkg=linux-kernel,ver>=2.6.8,ver<=2.6.16
Tags:
Rank: 1
bin-url: https://web.archive.org/web/20111103042904/http://tarantula.by.ru/localroot/2.6.x/h00lyshit
exploit-db: 2013
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2008-0600]${txtrst} vmsplice1
Reqs: pkg=linux-kernel,ver>=2.6.17,ver<=2.6.24
Tags:
Rank: 1
exploit-db: 5092
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2008-0600]${txtrst} vmsplice2
Reqs: pkg=linux-kernel,ver>=2.6.23,ver<=2.6.24
Tags:
Rank: 1
exploit-db: 5093
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2008-4210]${txtrst} ftrex
Reqs: pkg=linux-kernel,ver>=2.6.11,ver<=2.6.22
Tags:
Rank: 1
exploit-db: 6851
Comments: world-writable sgid directory and shell that does not drop sgid privs upon exec (ash/sash) are required
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2008-4210]${txtrst} exit_notify
Reqs: pkg=linux-kernel,ver>=2.6.25,ver<=2.6.29
Tags:
Rank: 1
exploit-db: 8369
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2009-2692]${txtrst} sock_sendpage (simple version)
Reqs: pkg=linux-kernel,ver>=2.6.0,ver<=2.6.30
Tags: ubuntu=7.10,RHEL=4,fedora=4|5|6|7|8|9|10|11
Rank: 1
exploit-db: 9479
Comments: Works for systems with /proc/sys/vm/mmap_min_addr equal to 0
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2009-2692,CVE-2009-1895]${txtrst} sock_sendpage
Reqs: pkg=linux-kernel,ver>=2.6.0,ver<=2.6.30
Tags: ubuntu=9.04
Rank: 1
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
Rank: 1
src-url: https://github.com/offensive-security/exploit-database-bin-sploits/raw/master/bin-sploits/9436.tgz
exploit-db: 9436
Comments: Works for systems with /proc/sys/vm/mmap_min_addr equal to 0
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2009-2692,CVE-2009-1895]${txtrst} sock_sendpage3
Reqs: pkg=linux-kernel,ver>=2.6.0,ver<=2.6.30
Tags: 
Rank: 1
src-url: https://github.com/offensive-security/exploit-database-bin-sploits/raw/master/bin-sploits/9641.tar.gz
exploit-db: 9641
Comments: /proc/sys/vm/mmap_min_addr needs to equal 0 OR pulseaudio needs to be installed
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2009-2692,CVE-2009-1895]${txtrst} sock_sendpage (ppc)
Reqs: pkg=linux-kernel,ver>=2.6.0,ver<=2.6.30
Tags: ubuntu=8.10,RHEL=4|5
Rank: 1
exploit-db: 9545
Comments: /proc/sys/vm/mmap_min_addr needs to equal 0
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2009-2698]${txtrst} the rebel (udp_sendmsg)
Reqs: pkg=linux-kernel,ver>=2.6.1,ver<=2.6.19
Tags: debian=4
Rank: 1
src-url: https://github.com/offensive-security/exploit-database-bin-sploits/raw/master/bin-sploits/9574.tgz
exploit-db: 9574
analysis-url: https://blog.cr0.org/2009/08/cve-2009-2698-udpsendmsg-vulnerability.html
author: spender
Comments: /proc/sys/vm/mmap_min_addr needs to equal 0 OR pulseaudio needs to be installed
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2009-2698]${txtrst} hoagie_udp_sendmsg
Reqs: pkg=linux-kernel,ver>=2.6.1,ver<=2.6.19,x86
Tags: debian=4
Rank: 1
exploit-db: 9575
analysis-url: https://blog.cr0.org/2009/08/cve-2009-2698-udpsendmsg-vulnerability.html
author: andi
Comments: Works for systems with /proc/sys/vm/mmap_min_addr equal to 0
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2009-2698]${txtrst} katon (udp_sendmsg)
Reqs: pkg=linux-kernel,ver>=2.6.1,ver<=2.6.19,x86
Tags: debian=4
Rank: 1
src-url: https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack/raw/master/2009/CVE-2009-2698/katon.c
analysis-url: https://blog.cr0.org/2009/08/cve-2009-2698-udpsendmsg-vulnerability.html
author: VxHell Labs
Comments: Works for systems with /proc/sys/vm/mmap_min_addr equal to 0
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2009-2698]${txtrst} ip_append_data
Reqs: pkg=linux-kernel,ver>=2.6.1,ver<=2.6.19,x86
Tags: fedora=4|5|6,RHEL=4
Rank: 1
analysis-url: https://blog.cr0.org/2009/08/cve-2009-2698-udpsendmsg-vulnerability.html
exploit-db: 9542
author: p0c73n1
Comments: Works for systems with /proc/sys/vm/mmap_min_addr equal to 0
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2009-3547]${txtrst} pipe.c 1
Reqs: pkg=linux-kernel,ver>=2.6.0,ver<=2.6.31
Tags:
Rank: 1
exploit-db: 33321
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2009-3547]${txtrst} pipe.c 2
Reqs: pkg=linux-kernel,ver>=2.6.0,ver<=2.6.31
Tags:
Rank: 1
exploit-db: 33322
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2009-3547]${txtrst} pipe.c 3
Reqs: pkg=linux-kernel,ver>=2.6.0,ver<=2.6.31
Tags:
Rank: 1
exploit-db: 10018
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2010-3301]${txtrst} ptrace_kmod2
Reqs: pkg=linux-kernel,ver>=2.6.26,ver<=2.6.34
Tags: debian=6.0{kernel:2.6.(32|33|34|35)-(1|2|trunk)-amd64},ubuntu=(10.04|10.10){kernel:2.6.(32|35)-(19|21|24)-server}
Rank: 1
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
Rank: 1
analysis-url: https://jon.oberheide.org/blog/2010/04/10/reiserfs-reiserfs_priv-vulnerability/
src-url: https://jon.oberheide.org/files/team-edward.py
exploit-db: 12130
comments: Requires a ReiserFS filesystem mounted with extended attributes
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2010-2959]${txtrst} can_bcm
Reqs: pkg=linux-kernel,ver>=2.6.18,ver<=2.6.36
Tags: ubuntu=10.04{kernel:2.6.32-24-generic}
Rank: 1
bin-url: https://web.archive.org/web/20160602192641/https://www.kernel-exploits.com/media/can_bcm
exploit-db: 14814
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2010-3904]${txtrst} rds
Reqs: pkg=linux-kernel,ver>=2.6.30,ver<2.6.37
Tags: debian=6.0{kernel:2.6.(31|32|34|35)-(1|trunk)-amd64},ubuntu=10.10|9.10,fedora=13{kernel:2.6.33.3-85.fc13.i686.PAE},ubuntu=10.04{kernel:2.6.32-(21|24)-generic}
Rank: 1
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
Tags: ubuntu=(10.04|9.10){kernel:2.6.(31|32)-(14|21)-server}
Rank: 1
bin-url: http://web.archive.org/web/20160602192631/https://www.kernel-exploits.com/media/half-nelson3
exploit-db: 17787
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[N/A]${txtrst} caps_to_root
Reqs: pkg=linux-kernel,ver>=2.6.34,ver<=2.6.36,x86
Tags: ubuntu=10.10
Rank: 1
exploit-db: 15916
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[N/A]${txtrst} caps_to_root 2
Reqs: pkg=linux-kernel,ver>=2.6.34,ver<=2.6.36
Tags: ubuntu=10.10
Rank: 1
exploit-db: 15944
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2010-4347]${txtrst} american-sign-language
Reqs: pkg=linux-kernel,ver>=2.6.0,ver<=2.6.36
Tags:
Rank: 1
exploit-db: 15774
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2010-3437]${txtrst} pktcdvd
Reqs: pkg=linux-kernel,ver>=2.6.0,ver<=2.6.36
Tags: ubuntu=10.04
Rank: 1
exploit-db: 15150
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2010-3081]${txtrst} video4linux
Reqs: pkg=linux-kernel,ver>=2.6.0,ver<=2.6.33
Tags: RHEL=5
Rank: 1
exploit-db: 15024
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2012-0056]${txtrst} memodipper
Reqs: pkg=linux-kernel,ver>=3.0.0,ver<=3.1.0
Tags: ubuntu=(10.04|11.10){kernel:3.0.0-12-(generic|server)}
Rank: 1
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
Tags: ubuntu=(9.10|10.10){kernel:2.6.(31|35)-(14|19)-(server|generic)},ubuntu=10.04{kernel:2.6.32-(21|24)-server}
Rank: 1
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
Rank: 1
src-url: http://stealth.openwall.net/xSports/clown-newuser.c
analysis-url: https://lwn.net/Articles/543273/
exploit-db: 38390
author: Sebastian Krahmer
Comments: CONFIG_USER_NS needs to be enabled 
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2013-2094]${txtrst} perf_swevent
Reqs: pkg=linux-kernel,ver>=2.6.32,ver<3.8.9,x86_64
Tags: RHEL=6,ubuntu=12.04{kernel:3.2.0-(23|29)-generic},fedora=16{kernel:3.1.0-7.fc16.x86_64},fedora=17{kernel:3.3.4-5.fc17.x86_64},debian=7{kernel:3.2.0-4-amd64}
Rank: 1
analysis-url: http://timetobleed.com/a-closer-look-at-a-recent-privilege-escalation-bug-in-linux-cve-2013-2094/
bin-url: https://web.archive.org/web/20160602192631/https://www.kernel-exploits.com/media/perf_swevent
bin-url: https://web.archive.org/web/20160602192631/https://www.kernel-exploits.com/media/perf_swevent64
exploit-db: 26131
author: Andrea 'sorbo' Bittau
Comments: No SMEP/SMAP bypass
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2013-2094]${txtrst} perf_swevent 2
Reqs: pkg=linux-kernel,ver>=2.6.32,ver<3.8.9,x86_64
Tags: ubuntu=12.04{kernel:3.(2|5).0-(23|29)-generic}
Rank: 1
analysis-url: http://timetobleed.com/a-closer-look-at-a-recent-privilege-escalation-bug-in-linux-cve-2013-2094/
src-url: https://cyseclabs.com/exploits/vnik_v1.c
exploit-db: 33589
author: Vitaly 'vnik' Nikolenko
Comments: No SMEP/SMAP bypass
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2013-0268]${txtrst} msr
Reqs: pkg=linux-kernel,ver>=2.6.18,ver<3.7.6
Tags: 
Rank: 1
exploit-db: 27297
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2013-1959]${txtrst} userns_root_sploit
Reqs: pkg=linux-kernel,ver>=3.0.1,ver<3.8.9
Tags: 
Rank: 1
analysis-url: http://www.openwall.com/lists/oss-security/2013/04/29/1
exploit-db: 25450
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2013-2094]${txtrst} semtex
Reqs: pkg=linux-kernel,ver>=2.6.32,ver<3.8.9
Tags: RHEL=6
Rank: 1
analysis-url: http://timetobleed.com/a-closer-look-at-a-recent-privilege-escalation-bug-in-linux-cve-2013-2094/
exploit-db: 25444
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2014-0038]${txtrst} timeoutpwn
Reqs: pkg=linux-kernel,ver>=3.4.0,ver<=3.13.1,CONFIG_X86_X32=y
Tags: ubuntu=13.10
Rank: 1
analysis-url: http://blog.includesecurity.com/2014/03/exploit-CVE-2014-0038-x32-recvmmsg-kernel-vulnerablity.html
bin-url: https://web.archive.org/web/20160602192631/https://www.kernel-exploits.com/media/timeoutpwn64
exploit-db: 31346
Comments: CONFIG_X86_X32 needs to be enabled
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2014-0038]${txtrst} timeoutpwn 2
Reqs: pkg=linux-kernel,ver>=3.4.0,ver<=3.13.1,CONFIG_X86_X32=y
Tags: ubuntu=(13.04|13.10){kernel:3.(8|11).0-(12|15|19)-generic}
Rank: 1
analysis-url: http://blog.includesecurity.com/2014/03/exploit-CVE-2014-0038-x32-recvmmsg-kernel-vulnerablity.html
exploit-db: 31347
Comments: CONFIG_X86_X32 needs to be enabled
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2014-0196]${txtrst} rawmodePTY
Reqs: pkg=linux-kernel,ver>=2.6.31,ver<=3.14.3
Tags:
Rank: 1
analysis-url: http://blog.includesecurity.com/2014/06/exploit-walkthrough-cve-2014-0196-pty-kernel-race-condition.html
exploit-db: 33516
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2014-2851]${txtrst} use-after-free in ping_init_sock() ${bldblu}(DoS)${txtrst}
Reqs: pkg=linux-kernel,ver>=3.0.1,ver<=3.14
Tags: 
Rank: 0
analysis-url: https://cyseclabs.com/page?n=02012016
exploit-db: 32926
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2014-4014]${txtrst} inode_capable
Reqs: pkg=linux-kernel,ver>=3.0.1,ver<=3.13
Tags: ubuntu=12.04
Rank: 1
analysis-url: http://www.openwall.com/lists/oss-security/2014/06/10/4
exploit-db: 33824
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2014-4699]${txtrst} ptrace/sysret
Reqs: pkg=linux-kernel,ver>=3.0.1,ver<=3.8
Tags: ubuntu=12.04
Rank: 1
analysis-url: http://www.openwall.com/lists/oss-security/2014/07/08/16
exploit-db: 34134
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2014-4943]${txtrst} PPPoL2TP ${bldblu}(DoS)${txtrst}
Reqs: pkg=linux-kernel,ver>=3.2,ver<=3.15.6
Tags: 
Rank: 1
analysis-url: https://cyseclabs.com/page?n=01102015
exploit-db: 36267
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2014-5207]${txtrst} fuse_suid
Reqs: pkg=linux-kernel,ver>=3.0.1,ver<=3.16.1
Tags: 
Rank: 1
exploit-db: 34923
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2015-9322]${txtrst} BadIRET
Reqs: pkg=linux-kernel,ver>=3.0.1,ver<3.17.5,x86_64
Tags: RHEL<=7,fedora=20
Rank: 1
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
Rank: 1
analysis-url: http://www.openwall.com/lists/oss-security/2015/08/04/8
exploit-db: 37722
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[N/A]${txtrst} bluetooth
Reqs: pkg=linux-kernel,ver<=2.6.11
Tags:
Rank: 1
exploit-db: 4756
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2015-1328]${txtrst} overlayfs
Reqs: pkg=linux-kernel,ver>=3.13.0,ver<=3.19.0
Tags: ubuntu=(12.04|14.04){kernel:3.13.0-(2|3|4|5)*-generic},ubuntu=(14.10|15.04){kernel:3.(13|16).0-*-generic}
Rank: 1
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
Rank: 1
analysis-url: http://www.halfdog.net/Security/2015/UserNamespaceOverlayfsSetuidWriteExec/
exploit-db: 39230
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2015-8660]${txtrst} overlayfs (ovl_setattr)
Reqs: pkg=linux-kernel,ver>=3.0.0,ver<=4.3.3
Tags: ubuntu=(14.04|15.10){kernel:4.2.0-(18|19|20|21|22)-generic}
Rank: 1
analysis-url: http://www.halfdog.net/Security/2015/UserNamespaceOverlayfsSetuidWriteExec/
exploit-db: 39166
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2016-0728]${txtrst} keyring
Reqs: pkg=linux-kernel,ver>=3.10,ver<4.4.1
Tags:
Rank: 0
analysis-url: http://perception-point.io/2016/01/14/analysis-and-exploitation-of-a-linux-kernel-vulnerability-cve-2016-0728/
exploit-db: 40003
Comments: Exploit takes about ~30 minutes to run. Exploit is not reliable, see: https://cyseclabs.com/blog/cve-2016-0728-poc-not-working
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2016-2384]${txtrst} usb-midi
Reqs: pkg=linux-kernel,ver>=3.0.0,ver<=4.4.8
Tags: ubuntu=14.04,fedora=22
Rank: 1
analysis-url: https://xairy.github.io/blog/2016/cve-2016-2384
src-url: https://raw.githubusercontent.com/xairy/kernel-exploits/master/CVE-2016-2384/poc.c
exploit-db: 41999
Comments: Requires ability to plug in a malicious USB device and to execute a malicious binary as a non-privileged user
author: Andrey 'xairy' Konovalov
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2016-4997]${txtrst} target_offset
Reqs: pkg=linux-kernel,ver>=4.4.0,ver<=4.4.0,cmd:grep -qi ip_tables /proc/modules
Tags: ubuntu=16.04{kernel:4.4.0-21-generic}
Rank: 1
src-url: https://github.com/offensive-security/exploit-database-bin-sploits/raw/master/bin-sploits/40053.zip
Comments: ip_tables.ko needs to be loaded
exploit-db: 40049
author: Vitaly 'vnik' Nikolenko
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2016-4557]${txtrst} double-fdput()
Reqs: pkg=linux-kernel,ver>=4.4,ver<4.5.5,CONFIG_BPF_SYSCALL=y,sysctl:kernel.unprivileged_bpf_disabled!=1
Tags: ubuntu=16.04{kernel:4.4.0-21-generic}
Rank: 1
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
Rank: 4
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
Rank: 4
analysis-url: https://github.com/dirtycow/dirtycow.github.io/wiki/VulnerabilityDetails
ext-url: https://www.exploit-db.com/download/40847
Comments: For RHEL/CentOS see exact vulnerable versions here: https://access.redhat.com/sites/default/files/rh-cve-2016-5195_5.sh
exploit-db: 40839
author: FireFart (author of exploit at EDB 40839); Gabriele Bonacini (author of exploit at 'ext-url')
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2016-8655]${txtrst} chocobo_root
Reqs: pkg=linux-kernel,ver>=4.4.0,ver<4.9,CONFIG_USER_NS=y,sysctl:kernel.unprivileged_userns_clone==1
Tags: ubuntu=(14.04|16.04){kernel:4.4.0-(21|22|24|28|31|34|36|38|42|43|45|47|51)-generic}
Rank: 1
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
Rank: 1
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
Rank: 1
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
Rank: 1
analysis-url: https://googleprojectzero.blogspot.com/2017/05/exploiting-linux-kernel-via-packet.html
src-url: https://raw.githubusercontent.com/xairy/kernel-exploits/master/CVE-2017-7308/poc.c
ext-url: https://raw.githubusercontent.com/bcoles/kernel-exploits/master/CVE-2017-7308/poc.c
Comments: CAP_NET_RAW cap or CONFIG_USER_NS=y needed. Modified version at 'ext-url' adds support for additional kernels
bin-url: https://raw.githubusercontent.com/rapid7/metasploit-framework/master/data/exploits/cve-2017-7308/exploit
exploit-db: 41994
author: Andrey 'xairy' Konovalov (orginal exploit author); Brendan Coles (author of exploit update at 'ext-url')
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2017-16995]${txtrst} eBPF_verifier
Reqs: pkg=linux-kernel,ver>=4.4,ver<=4.14.8,CONFIG_BPF_SYSCALL=y,sysctl:kernel.unprivileged_bpf_disabled!=1
Tags: debian=9.0{kernel:4.9.0-3-amd64},fedora=25|26|27,ubuntu=14.04{kernel:4.4.0-89-generic},ubuntu=(16.04|17.04){kernel:4.(8|10).0-(19|28|45)-generic}
Rank: 5
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
Rank: 1
analysis-url: http://www.openwall.com/lists/oss-security/2017/08/13/1
src-url: https://raw.githubusercontent.com/xairy/kernel-exploits/master/CVE-2017-1000112/poc.c
ext-url: https://raw.githubusercontent.com/bcoles/kernel-exploits/master/CVE-2017-1000112/poc.c
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
Rank: 1
analysis-url: https://www.qualys.com/2017/09/26/linux-pie-cve-2017-1000253/cve-2017-1000253.txt
src-url: https://www.qualys.com/2017/09/26/linux-pie-cve-2017-1000253/cve-2017-1000253.c
exploit-db: 42887
author: Qualys
Comments:
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2018-5333]${txtrst} rds_atomic_free_op NULL pointer dereference
Reqs: pkg=linux-kernel,ver>=4.4,ver<=4.14.13,cmd:grep -qi rds /proc/modules,x86_64
Tags: ubuntu=16.04{kernel:4.4.0|4.8.0}
Rank: 1
src-url: https://gist.githubusercontent.com/wbowling/9d32492bd96d9e7c3bf52e23a0ac30a4/raw/959325819c78248a6437102bb289bb8578a135cd/cve-2018-5333-poc.c
ext-url: https://raw.githubusercontent.com/bcoles/kernel-exploits/master/CVE-2018-5333/cve-2018-5333.c
Comments: rds.ko kernel module needs to be loaded. Modified version at 'ext-url' adds support for additional targets and bypassing KASLR.
author: wbowling (orginal exploit author); bcoles (author of exploit update at 'ext-url')
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2018-18955]${txtrst} subuid_shell
Reqs: pkg=linux-kernel,ver>=4.15,ver<=4.19.2,CONFIG_USER_NS=y,sysctl:kernel.unprivileged_userns_clone==1,cmd:[ -u /usr/bin/newuidmap ],cmd:[ -u /usr/bin/newgidmap ]
Tags: ubuntu=18.04{kernel:4.15.0-20-generic},fedora=28{kernel:4.16.3-301.fc28}
Rank: 1
analysis-url: https://bugs.chromium.org/p/project-zero/issues/detail?id=1712
src-url: https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/45886.zip
exploit-db: 45886
author: Jann Horn
Comments: CONFIG_USER_NS needs to be enabled
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2019-13272]${txtrst} PTRACE_TRACEME
Reqs: pkg=linux-kernel,ver>=4,ver<5.1.17,sysctl:kernel.yama.ptrace_scope==0,x86_64
Tags: ubuntu=16.04{kernel:4.15.0-*},ubuntu=18.04{kernel:4.15.0-*},debian=9{kernel:4.9.0-*},debian=10{kernel:4.19.0-*},fedora=30{kernel:5.0.9-*}
Rank: 1
analysis-url: https://bugs.chromium.org/p/project-zero/issues/detail?id=1903
src-url: https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/47133.zip
ext-url: https://raw.githubusercontent.com/bcoles/kernel-exploits/master/CVE-2019-13272/poc.c
Comments: Requires an active PolKit agent.
exploit-db: 47133
exploit-db: 47163
author: Jann Horn (orginal exploit author); bcoles (author of exploit update at 'ext-url')
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2019-15666]${txtrst} XFRM_UAF
Reqs: pkg=linux-kernel,ver>=3,ver<5.0.19,CONFIG_USER_NS=y,sysctl:kernel.unprivileged_userns_clone==1,CONFIG_XFRM=y
Tags:
Rank: 1
analysis-url: https://duasynt.com/blog/ubuntu-centos-redhat-privesc
bin-url: https://github.com/duasynt/xfrm_poc/raw/master/lucky0
Comments: CONFIG_USER_NS needs to be enabled; CONFIG_XFRM needs to be enabled
author: Vitaly 'vnik' Nikolenko
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2021-27365]${txtrst} linux-iscsi
Reqs: pkg=linux-kernel,ver<=5.11.3,CONFIG_SLAB_FREELIST_HARDENED!=y
Tags: RHEL=8
Rank: 1
analysis-url: https://blog.grimm-co.com/2021/03/new-old-bugs-in-linux-kernel.html
src-url: https://codeload.github.com/grimm-co/NotQuite0DayFriday/zip/trunk
Comments: CONFIG_SLAB_FREELIST_HARDENED must not be enabled
author: GRIMM
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2021-3490]${txtrst} eBPF ALU32 bounds tracking for bitwise ops
Reqs: pkg=linux-kernel,ver>=5.7,ver<5.12,CONFIG_BPF_SYSCALL=y,sysctl:kernel.unprivileged_bpf_disabled!=1
Tags: ubuntu=20.04{kernel:5.8.0-(25|26|27|28|29|30|31|32|33|34|35|36|37|38|39|40|41|42|43|44|45|46|47|48|49|50|51|52)-*},ubuntu=21.04{kernel:5.11.0-16-*}
Rank: 5
analysis-url: https://www.graplsecurity.com/post/kernel-pwning-with-ebpf-a-love-story
src-url: https://codeload.github.com/chompie1337/Linux_LPE_eBPF_CVE-2021-3490/zip/main
Comments: CONFIG_BPF_SYSCALL needs to be set && kernel.unprivileged_bpf_disabled != 1
author: chompie1337
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2021-22555]${txtrst} Netfilter heap out-of-bounds write
Reqs: pkg=linux-kernel,ver>=2.6.19,ver<=5.12-rc6
Tags: ubuntu=20.04{kernel:5.8.0-*}
Rank: 1
analysis-url: https://google.github.io/security-research/pocs/linux/cve-2021-22555/writeup.html
src-url: https://raw.githubusercontent.com/google/security-research/master/pocs/linux/cve-2021-22555/exploit.c
ext-url: https://raw.githubusercontent.com/bcoles/kernel-exploits/master/CVE-2021-22555/exploit.c
Comments: ip_tables kernel module must be loaded
exploit-db: 50135
author: theflow (orginal exploit author); bcoles (author of exploit update at 'ext-url')
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2022-0847]${txtrst} DirtyPipe
Reqs: pkg=linux-kernel,ver>=5.8,ver<=5.16.11
Tags: ubuntu=(20.04|21.04),debian=11
Rank: 1
analysis-url: https://dirtypipe.cm4all.com/
src-url: https://haxx.in/files/dirtypipez.c
exploit-db: 50808
author: blasty (original exploit author: Max Kellermann)
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2022-2586]${txtrst} nft_object UAF
Reqs: pkg=linux-kernel,ver>=3.16,CONFIG_USER_NS=y,sysctl:kernel.unprivileged_userns_clone==1
Tags: ubuntu=(20.04){kernel:5.12.13}
Rank: 1
analysis-url: https://www.openwall.com/lists/oss-security/2022/08/29/5
src-url: https://www.openwall.com/lists/oss-security/2022/08/29/5/1
Comments: kernel.unprivileged_userns_clone=1 required (to obtain CAP_NET_ADMIN)
author: vulnerability discovery: Team Orca of Sea Security; Exploit author: Alejandro Guerrero
EOF
)

EXPLOITS[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2022-32250]${txtrst} nft_object UAF (NFT_MSG_NEWSET)
Reqs: pkg=linux-kernel,ver<5.18.1,CONFIG_USER_NS=y,sysctl:kernel.unprivileged_userns_clone==1
Tags: ubuntu=(22.04){kernel:5.15.0-27-generic}
Rank: 1
analysis-url: https://research.nccgroup.com/2022/09/01/settlers-of-netlink-exploiting-a-limited-uaf-in-nf_tables-cve-2022-32250/
analysis-url: https://blog.theori.io/research/CVE-2022-32250-linux-kernel-lpe-2022/
src-url: https://raw.githubusercontent.com/theori-io/CVE-2022-32250-exploit/main/exp.c
Comments: kernel.unprivileged_userns_clone=1 required (to obtain CAP_NET_ADMIN)
author: vulnerability discovery: EDG Team from NCC Group; Author of this exploit: theori.io
EOF
)


############ USERSPACE EXPLOITS ###########################
n=0

EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2004-0186]${txtrst} samba
Reqs: pkg=samba,ver<=2.2.8
Tags: 
Rank: 1
exploit-db: 23674
EOF
)

EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2009-1185]${txtrst} udev
Reqs: pkg=udev,ver<141,cmd:[[ -f /etc/udev/rules.d/95-udev-late.rules || -f /lib/udev/rules.d/95-udev-late.rules ]]
Tags: ubuntu=8.10|9.04
Rank: 1
exploit-db: 8572
Comments: Version<1.4.1 vulnerable but distros use own versioning scheme. Manual verification needed 
EOF
)

EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2009-1185]${txtrst} udev 2
Reqs: pkg=udev,ver<141
Tags:
Rank: 1
exploit-db: 8478
Comments: SSH access to non privileged user is needed. Version<1.4.1 vulnerable but distros use own versioning scheme. Manual verification needed
EOF
)

EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2010-0832]${txtrst} PAM MOTD
Reqs: pkg=libpam-modules,ver<=1.1.1
Tags: ubuntu=9.10|10.04
Rank: 1
exploit-db: 14339
Comments: SSH access to non privileged user is needed
EOF
)

EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2010-4170]${txtrst} SystemTap
Reqs: pkg=systemtap,ver<=1.3
Tags: RHEL=5{systemtap:1.1-3.el5},fedora=13{systemtap:1.2-1.fc13}
Rank: 1
author: Tavis Ormandy
exploit-db: 15620
EOF
)

EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2011-1485]${txtrst} pkexec
Reqs: pkg=polkit,ver=0.96
Tags: RHEL=6,ubuntu=10.04|10.10
Rank: 1
exploit-db: 17942
EOF
)

EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2011-2921]${txtrst} ktsuss
Reqs: pkg=ktsuss,ver<=1.4
Tags: sparky=5|6
Rank: 1
analysis-url: https://www.openwall.com/lists/oss-security/2011/08/13/2
src-url: https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2011-2921/ktsuss-lpe.sh
EOF
)

EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2012-0809]${txtrst} death_star (sudo)
Reqs: pkg=sudo,ver>=1.8.0,ver<=1.8.3
Tags: fedora=16 
Rank: 1
analysis-url: http://seclists.org/fulldisclosure/2012/Jan/att-590/advisory_sudo.txt
exploit-db: 18436
EOF
)

EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2014-0476]${txtrst} chkrootkit
Reqs: pkg=chkrootkit,ver<0.50
Tags: 
Rank: 1
analysis-url: http://seclists.org/oss-sec/2014/q2/430
exploit-db: 33899
Comments: Rooting depends on the crontab (up to one day of delay)
EOF
)

EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2014-5119]${txtrst} __gconv_translit_find
Reqs: pkg=glibc|libc6,x86
Tags: debian=6
Rank: 1
analysis-url: http://googleprojectzero.blogspot.com/2014/08/the-poisoned-nul-byte-2014-edition.html
src-url: https://github.com/offensive-security/exploit-database-bin-sploits/raw/master/bin-sploits/34421.tar.gz
exploit-db: 34421
EOF
)

EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2015-1862]${txtrst} newpid (abrt)
Reqs: pkg=abrt,cmd:grep -qi abrt /proc/sys/kernel/core_pattern
Tags: fedora=20
Rank: 1
analysis-url: http://openwall.com/lists/oss-security/2015/04/14/4
src-url: https://gist.githubusercontent.com/taviso/0f02c255c13c5c113406/raw/eafac78dce51329b03bea7167f1271718bee4dcc/newpid.c
exploit-db: 36746
EOF
)

EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2015-3315]${txtrst} raceabrt
Reqs: pkg=abrt,cmd:grep -qi abrt /proc/sys/kernel/core_pattern
Tags: fedora=19{abrt:2.1.5-1.fc19},fedora=20{abrt:2.2.2-2.fc20},fedora=21{abrt:2.3.0-3.fc21},RHEL=7{abrt:2.1.11-12.el7}
Rank: 1
analysis-url: http://seclists.org/oss-sec/2015/q2/130
src-url: https://gist.githubusercontent.com/taviso/fe359006836d6cd1091e/raw/32fe8481c434f8cad5bcf8529789231627e5074c/raceabrt.c
exploit-db: 36747
author: Tavis Ormandy
EOF
)

EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2015-1318]${txtrst} newpid (apport)
Reqs: pkg=apport,ver>=2.13,ver<=2.17,cmd:grep -qi apport /proc/sys/kernel/core_pattern
Tags: ubuntu=14.04
Rank: 1
analysis-url: http://openwall.com/lists/oss-security/2015/04/14/4
src-url: https://gist.githubusercontent.com/taviso/0f02c255c13c5c113406/raw/eafac78dce51329b03bea7167f1271718bee4dcc/newpid.c
exploit-db: 36746
EOF
)

EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2015-1318]${txtrst} newpid (apport) 2
Reqs: pkg=apport,ver>=2.13,ver<=2.17,cmd:grep -qi apport /proc/sys/kernel/core_pattern
Tags: ubuntu=14.04.2
Rank: 1
analysis-url: http://openwall.com/lists/oss-security/2015/04/14/4
exploit-db: 36782
EOF
)

EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2015-3202]${txtrst} fuse (fusermount)
Reqs: pkg=fuse,ver<2.9.3
Tags: debian=7.0|8.0,ubuntu=*
Rank: 1
analysis-url: http://seclists.org/oss-sec/2015/q2/520
exploit-db: 37089
Comments: Needs cron or system admin interaction
EOF
)

EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2015-1815]${txtrst} setroubleshoot
Reqs: pkg=setroubleshoot,ver<3.2.22
Tags: fedora=21
Rank: 1
exploit-db: 36564
EOF
)

EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2015-3246]${txtrst} userhelper
Reqs: pkg=libuser,ver<=0.60
Tags: RHEL=6{libuser:0.56.13-(4|5).el6},RHEL=6{libuser:0.60-5.el7},fedora=13|19|20|21|22
Rank: 1
analysis-url: https://www.qualys.com/2015/07/23/cve-2015-3245-cve-2015-3246/cve-2015-3245-cve-2015-3246.txt 
exploit-db: 37706
Comments: RHEL 5 is also vulnerable, but installed version of glibc (2.5) lacks functions needed by roothelper.c
EOF
)

EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2015-5287]${txtrst} abrt/sosreport-rhel7
Reqs: pkg=abrt,cmd:grep -qi abrt /proc/sys/kernel/core_pattern
Tags: RHEL=7{abrt:2.1.11-12.el7}
Rank: 1
analysis-url: https://www.openwall.com/lists/oss-security/2015/12/01/1
src-url: https://www.openwall.com/lists/oss-security/2015/12/01/1/1
exploit-db: 38832
author: rebel
EOF
)

EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2015-6565]${txtrst} not_an_sshnuke
Reqs: pkg=openssh-server,ver>=6.8,ver<=6.9
Tags:
Rank: 1
analysis-url: http://www.openwall.com/lists/oss-security/2017/01/26/2
exploit-db: 41173
author: Federico Bento
Comments: Needs admin interaction (root user needs to login via ssh to trigger exploitation)
EOF
)

EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2015-8612]${txtrst} blueman set_dhcp_handler d-bus privesc
Reqs: pkg=blueman,ver<2.0.3
Tags: debian=8{blueman:1.23}
Rank: 1
analysis-url: https://twitter.com/thegrugq/status/677809527882813440
exploit-db: 46186
author: Sebastian Krahmer
Comments: Distros use own versioning scheme. Manual verification needed.
EOF
)

EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2016-1240]${txtrst} tomcat-rootprivesc-deb.sh
Reqs: pkg=tomcat
Tags: debian=8,ubuntu=16.04
Rank: 1
analysis-url: https://legalhackers.com/advisories/Tomcat-DebPkgs-Root-Privilege-Escalation-Exploit-CVE-2016-1240.html
src-url: http://legalhackers.com/exploits/tomcat-rootprivesc-deb.sh
exploit-db: 40450
author: Dawid Golunski
Comments: Affects only Debian-based distros
EOF
)

EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2016-1247]${txtrst} nginxed-root.sh
Reqs: pkg=nginx|nginx-full,ver<1.10.3
Tags: debian=8,ubuntu=14.04|16.04|16.10
Rank: 1
analysis-url: https://legalhackers.com/advisories/Nginx-Exploit-Deb-Root-PrivEsc-CVE-2016-1247.html
src-url: https://legalhackers.com/exploits/CVE-2016-1247/nginxed-root.sh
exploit-db: 40768
author: Dawid Golunski
Comments: Rooting depends on cron.daily (up to 24h of delay). Affected: deb8: <1.6.2; 14.04: <1.4.6; 16.04: 1.10.0; gentoo: <1.10.2-r3
EOF
)

EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2016-1531]${txtrst} perl_startup (exim)
Reqs: pkg=exim,ver<4.86.2
Tags: 
Rank: 1
analysis-url: http://www.exim.org/static/doc/CVE-2016-1531.txt
exploit-db: 39549
EOF
)

EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2016-1531]${txtrst} perl_startup (exim) 2
Reqs: pkg=exim,ver<4.86.2
Tags: 
Rank: 1
analysis-url: http://www.exim.org/static/doc/CVE-2016-1531.txt
exploit-db: 39535
EOF
)

EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2016-4989]${txtrst} setroubleshoot 2
Reqs: pkg=setroubleshoot
Tags: RHEL=6|7
Rank: 1
analysis-url: https://c-skills.blogspot.com/2016/06/lets-feed-attacker-input-to-sh-c-to-see.html
src-url: https://github.com/stealth/troubleshooter/raw/master/straight-shooter.c
exploit-db:
EOF
)

EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2016-5425]${txtrst} tomcat-RH-root.sh
Reqs: pkg=tomcat
Tags: RHEL=7
Rank: 1
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
Rank: 1
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
Rank: 1
analysis-url: https://legalhackers.com/advisories/Nagios-Exploit-Root-PrivEsc-CVE-2016-9566.html
src-url: https://legalhackers.com/exploits/CVE-2016-9566/nagios-root-privesc.sh
exploit-db: 40921
author: Dawid Golunski
Comments: Allows priv escalation from nagios user or nagios group
EOF
)

EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2017-0358]${txtrst} ntfs-3g-modprobe
Reqs: pkg=ntfs-3g,ver<2017.4
Tags: ubuntu=16.04{ntfs-3g:2015.3.14AR.1-1build1},debian=7.0{ntfs-3g:2012.1.15AR.5-2.1+deb7u2},debian=8.0{ntfs-3g:2014.2.15AR.2-1+deb8u2}
Rank: 1
analysis-url: https://bugs.chromium.org/p/project-zero/issues/detail?id=1072
src-url: https://github.com/offensive-security/exploit-database-bin-sploits/raw/master/bin-sploits/41356.zip
exploit-db: 41356
author: Jann Horn
Comments: Distros use own versioning scheme. Manual verification needed. Linux headers must be installed. System must have at least two CPU cores.
EOF
)

EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2017-5899]${txtrst} s-nail-privget
Reqs: pkg=s-nail,ver<14.8.16
Tags: ubuntu=16.04,manjaro=16.10
Rank: 1
analysis-url: https://www.openwall.com/lists/oss-security/2017/01/27/7
src-url: https://www.openwall.com/lists/oss-security/2017/01/27/7/1
ext-url: https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2017-5899/exploit.sh
author: wapiflapi (orginal exploit author); Brendan Coles (author of exploit update at 'ext-url')
Comments: Distros use own versioning scheme. Manual verification needed.
EOF
)

EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2017-1000367]${txtrst} Sudoer-to-root
Reqs: pkg=sudo,ver<=1.8.20,cmd:[ -f /usr/sbin/getenforce ]
Tags: RHEL=7{sudo:1.8.6p7}
Rank: 1
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
Rank: 1
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
Rank: 1
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
Rank: 1
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
Rank: 1
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
Rank: 1
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
Tags: debian=9{libc6:2.24-11+deb9u1},ubuntu=16.04.3{libc6:2.23-0ubuntu9}
Rank: 1
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
Tags: ubuntu=16.04{network-manager-vpnc:1.1.93-1},debian=9.0{network-manager-vpnc:1.2.4-4},manjaro=17
Rank: 1
analysis-url: https://pulsesecurity.co.nz/advisories/NM-VPNC-Privesc
src-url: https://bugzilla.novell.com/attachment.cgi?id=779110
exploit-db: 45313
author: Denis Andzakovic
Comments: Distros use own versioning scheme. Manual verification needed.
EOF
)

EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2018-14665]${txtrst} raptor_xorgy
Reqs: pkg=xorg-x11-server-Xorg,cmd:[ -u /usr/bin/Xorg ]
Tags: centos=7.4
Rank: 1
analysis-url: https://www.securepatterns.com/2018/10/cve-2018-14665-xorg-x-server.html
exploit-db: 45922
author: raptor
Comments: X.Org Server before 1.20.3 is vulnerable. Distros use own versioning scheme. Manual verification needed.
EOF
)

EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2019-7304]${txtrst} dirty_sock
Reqs: pkg=snapd,ver<2.37,cmd:[ -S /run/snapd.socket ]
Tags: ubuntu=18.10,mint=19
Rank: 1
analysis-url: https://initblog.com/2019/dirty-sock/
exploit-db: 46361
exploit-db: 46362
src-url: https://github.com/initstring/dirty_sock/archive/master.zip
author: InitString
Comments: Distros use own versioning scheme. Manual verification needed.
EOF
)

EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2019-10149]${txtrst} raptor_exim_wiz
Reqs: pkg=exim|exim4,ver>=4.87,ver<=4.91
Tags:
Rank: 1
analysis-url: https://www.qualys.com/2019/06/05/cve-2019-10149/return-wizard-rce-exim.txt
exploit-db: 46996
author: raptor
EOF
)

EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2019-12181]${txtrst} Serv-U FTP Server
Reqs: cmd:[ -u /usr/local/Serv-U/Serv-U ]
Tags: debian=9
Rank: 1
analysis-url: https://blog.vastart.dev/2019/06/cve-2019-12181-serv-u-exploit-writeup.html
exploit-db: 47009
src-url: https://raw.githubusercontent.com/guywhataguy/CVE-2019-12181/master/servu-pe-cve-2019-12181.c
ext-url: https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-12181/SUroot
author: Guy Levin (orginal exploit author); Brendan Coles (author of exploit update at 'ext-url')
Comments: Modified version at 'ext-url' uses bash exec technique, rather than compiling with gcc.
EOF
)
EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2019-18862]${txtrst} GNU Mailutils 2.0 <= 3.7 maidag url local root (CVE-2019-18862)
Reqs: cmd:[ -u /usr/local/sbin/maidag ]
Tags: 
Rank: 1
analysis-url: https://www.mike-gualtieri.com/posts/finding-a-decade-old-flaw-in-gnu-mailutils
ext-url: https://github.com/bcoles/local-exploits/raw/master/CVE-2019-18862/exploit.cron.sh
src-url: https://github.com/bcoles/local-exploits/raw/master/CVE-2019-18862/exploit.ldpreload.sh
author: bcoles
EOF
)

EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2019-18634]${txtrst} sudo pwfeedback
Reqs: pkg=sudo,ver<1.8.31
Tags: mint=19
Rank: 1
analysis-url: https://dylankatz.com/Analysis-of-CVE-2019-18634/
src-url: https://github.com/saleemrashid/sudo-cve-2019-18634/raw/master/exploit.c
author: saleemrashid
Comments: sudo configuration requires pwfeedback to be enabled.
EOF
)

EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2020-9470]${txtrst} Wing FTP Server <= 6.2.5 LPE
Reqs: cmd:[ -x /etc/init.d/wftpserver ]
Tags: ubuntu=18
Rank: 1
analysis-url: https://www.hooperlabs.xyz/disclosures/cve-2020-9470.php
src-url: https://www.hooperlabs.xyz/disclosures/cve-2020-9470.sh
exploit-db: 48154
author: Cary Cooper
Comments: Requires an administrator to login via the web interface.
EOF
)

EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2021-3156]${txtrst} sudo Baron Samedit
Reqs: pkg=sudo,ver<1.9.5p2
Tags: mint=19,ubuntu=18|20, debian=10
Rank: 1
analysis-url: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
src-url: https://codeload.github.com/blasty/CVE-2021-3156/zip/main
author: blasty
EOF
)

EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2021-3156]${txtrst} sudo Baron Samedit 2
Reqs: pkg=sudo,ver<1.9.5p2
Tags: centos=6|7|8,ubuntu=14|16|17|18|19|20, debian=9|10
Rank: 1
analysis-url: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
src-url: https://codeload.github.com/worawit/CVE-2021-3156/zip/main
author: worawit
EOF
)

EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2017-5618]${txtrst} setuid screen v4.5.0 LPE
Reqs: pkg=screen,ver==4.5.0
Tags: 
Rank: 1
analysis-url: https://seclists.org/oss-sec/2017/q1/184
exploit-db: https://www.exploit-db.com/exploits/41154
EOF
)

EXPLOITS_USERSPACE[((n++))]=$(cat <<EOF
Name: ${txtgrn}[CVE-2021-4034]${txtrst} PwnKit
Reqs: pkg=polkit|policykit-1,ver<=0.105-31
Tags: ubuntu=10|11|12|13|14|15|16|17|18|19|20|21,debian=7|8|9|10|11,fedora,manjaro
Rank: 1
analysis-url: https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt
src-url: https://codeload.github.com/berdav/CVE-2021-4034/zip/main
author: berdav
EOF
)

###########################################################
## security related HW/kernel features
###########################################################
n=0

FEATURES[((n++))]=$(cat <<EOF
section: Mainline kernel protection mechanisms:
EOF
)

FEATURES[((n++))]=$(cat <<EOF
feature: Kernel Page Table Isolation (PTI) support
available: ver>=4.15
enabled: cmd:grep -Eqi '\spti' /proc/cpuinfo
analysis-url: https://github.com/mzet-/les-res/blob/master/features/pti.md
EOF
)

FEATURES[((n++))]=$(cat <<EOF
feature: GCC stack protector support
available: CONFIG_HAVE_STACKPROTECTOR=y
analysis-url: https://github.com/mzet-/les-res/blob/master/features/stackprotector-regular.md
EOF
)

FEATURES[((n++))]=$(cat <<EOF
feature: GCC stack protector STRONG support
available: CONFIG_STACKPROTECTOR_STRONG=y,ver>=3.14
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
feature: Prevent users from using ptrace to examine the memory and state of their processes
available: CONFIG_SECURITY_YAMA=y
enabled: sysctl:kernel.yama.ptrace_scope!=0
analysis-url: https://github.com/mzet-/les-res/blob/master/features/yama_ptrace_scope.md
EOF
)

FEATURES[((n++))]=$(cat <<EOF
feature: Restrict unprivileged access to kernel syslog
available: CONFIG_SECURITY_DMESG_RESTRICT=y,ver>=2.6.37
enabled: sysctl:kernel.dmesg_restrict!=0
analysis-url: https://github.com/mzet-/les-res/blob/master/features/dmesg_restrict.md
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
feature: BUG() conditions reporting
available: CONFIG_BUG=y
analysis-url: https://github.com/mzet-/les-res/blob/master/features/bug.md
EOF
)

FEATURES[((n++))]=$(cat <<EOF
feature: Additional 'cred' struct checks
available: CONFIG_DEBUG_CREDENTIALS=y
analysis-url: https://github.com/mzet-/les-res/blob/master/features/debug_credentials.md
EOF
)

FEATURES[((n++))]=$(cat <<EOF
feature: Sanity checks for notifier call chains
available: CONFIG_DEBUG_NOTIFIERS=y
analysis-url: https://github.com/mzet-/les-res/blob/master/features/debug_notifiers.md
EOF
)

FEATURES[((n++))]=$(cat <<EOF
feature: Extended checks for linked-lists walking
available: CONFIG_DEBUG_LIST=y
analysis-url: https://github.com/mzet-/les-res/blob/master/features/debug_list.md
EOF
)

FEATURES[((n++))]=$(cat <<EOF
feature: Checks on scatter-gather tables
available: CONFIG_DEBUG_SG=y
analysis-url: https://github.com/mzet-/les-res/blob/master/features/debug_sg.md
EOF
)

FEATURES[((n++))]=$(cat <<EOF
feature: Checks for data structure corruptions
available: CONFIG_BUG_ON_DATA_CORRUPTION=y
analysis-url: https://github.com/mzet-/les-res/blob/master/features/bug_on_data_corruption.md
EOF
)

FEATURES[((n++))]=$(cat <<EOF
feature: Checks for a stack overrun on calls to 'schedule'
available: CONFIG_SCHED_STACK_END_CHECK=y
analysis-url: https://github.com/mzet-/les-res/blob/master/features/sched_stack_end_check.md
EOF
)

FEATURES[((n++))]=$(cat <<EOF
feature: Freelist order randomization on new pages creation
available: CONFIG_SLAB_FREELIST_RANDOM=y
analysis-url: https://github.com/mzet-/les-res/blob/master/features/slab_freelist_random.md
EOF
)

FEATURES[((n++))]=$(cat <<EOF
feature: Freelist metadata hardening
available: CONFIG_SLAB_FREELIST_HARDENED=y
analysis-url: https://github.com/mzet-/les-res/blob/master/features/slab_freelist_hardened.md
EOF
)

FEATURES[((n++))]=$(cat <<EOF
feature: Allocator validation checking
available: CONFIG_SLUB_DEBUG_ON=y,cmd:! grep 'slub_debug=-' /proc/cmdline
analysis-url: https://github.com/mzet-/les-res/blob/master/features/slub_debug.md
EOF
)

FEATURES[((n++))]=$(cat <<EOF
feature: Virtually-mapped kernel stacks with guard pages
available: CONFIG_VMAP_STACK=y
analysis-url: https://github.com/mzet-/les-res/blob/master/features/vmap_stack.md
EOF
)

FEATURES[((n++))]=$(cat <<EOF
feature: Pages poisoning after free_pages() call
available: CONFIG_PAGE_POISONING=y
enabled: cmd: grep 'page_poison=1' /proc/cmdline
analysis-url: https://github.com/mzet-/les-res/blob/master/features/page_poisoning.md
EOF
)

FEATURES[((n++))]=$(cat <<EOF
feature: Using 'refcount_t' instead of 'atomic_t'
available: CONFIG_REFCOUNT_FULL=y
analysis-url: https://github.com/mzet-/les-res/blob/master/features/refcount_full.md
EOF
)

FEATURES[((n++))]=$(cat <<EOF
feature: Hardening common str/mem functions against buffer overflows
available: CONFIG_FORTIFY_SOURCE=y
analysis-url: https://github.com/mzet-/les-res/blob/master/features/fortify_source.md
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
section: Hardware-based protection features:
EOF
)

FEATURES[((n++))]=$(cat <<EOF
feature: Supervisor Mode Execution Protection (SMEP) support
available: ver>=3.0
enabled: cmd:grep -qi smep /proc/cpuinfo
analysis-url: https://github.com/mzet-/les-res/blob/master/features/smep.md
EOF
)

FEATURES[((n++))]=$(cat <<EOF
feature: Supervisor Mode Access Prevention (SMAP) support
available: ver>=3.7
enabled: cmd:grep -qi smap /proc/cpuinfo
analysis-url: https://github.com/mzet-/les-res/blob/master/features/smap.md
EOF
)

FEATURES[((n++))]=$(cat <<EOF
section: 3rd party kernel protection mechanisms:
EOF
)

FEATURES[((n++))]=$(cat <<EOF
feature: Grsecurity
available: CONFIG_GRKERNSEC=y
enabled: cmd:test -c /dev/grsec
EOF
)

FEATURES[((n++))]=$(cat <<EOF
feature: PaX
available: CONFIG_PAX=y
enabled: cmd:test -x /sbin/paxctl
EOF
)

FEATURES[((n++))]=$(cat <<EOF
feature: Linux Kernel Runtime Guard (LKRG) kernel module
enabled: cmd:test -d /proc/sys/lkrg
analysis-url: https://github.com/mzet-/les-res/blob/master/features/lkrg.md
EOF
)

FEATURES[((n++))]=$(cat <<EOF
section: Attack Surface:
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

FEATURES[((n++))]=$(cat <<EOF
feature: Syscalls filtering
available: CONFIG_SECCOMP=y
enabled: cmd:grep -iw Seccomp /proc/self/status | awk '{print \$2}'
analysis-url: https://github.com/mzet-/les-res/blob/master/features/bpf_syscall.md
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


version() {
    echo "linux-exploit-suggester "$VERSION", mzet, https://z-labs.eu, March 2019"
}

usage() {
    echo "LES ver. $VERSION (https://github.com/mzet-/linux-exploit-suggester) by @_mzet_"
    echo
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
        if [ $(head -1 "$pkglist_file" | grep 'Desired=Unknown/Install/Remove/Purge/Hold') ]; then
            PKG_LIST=$(cat "$pkglist_file" | awk '{print $2"-"$3}' | sed 's/:amd64//g')

            OS="debian"
            [ "$(grep ubuntu "$pkglist_file")" ] && OS="ubuntu"
        # redhat package listing file
        elif [ "$(grep -E '\.el[1-9]+[\._]' "$pkglist_file" | head -1)" ]; then
            PKG_LIST=$(cat "$pkglist_file")
            OS="RHEL"
        # fedora package listing file
        elif [ "$(grep -E '\.fc[1-9]+'i "$pkglist_file" | head -1)" ]; then
            PKG_LIST=$(cat "$pkglist_file")
            OS="fedora"
        # mageia package listing file
        elif [ "$(grep -E '\.mga[1-9]+' "$pkglist_file" | head -1)" ]; then
            PKG_LIST=$(cat "$pkglist_file")
            OS="mageia"
        # pacman package listing file
        elif [ "$(grep -E '\ [0-9]+\.' "$pkglist_file" | head -1)" ]; then
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
    elif [ -x /usr/bin/equery ]; then
        PKG_LIST=$(/usr/bin/equery --quiet list '*' -F '$name:$version' | cut -d/ -f2- | awk '{print $1":"$2}')
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

    MODE=0

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

	# modes: kernel-feature (1) | hw-feature (2) | 3rdparty-feature (3) | attack-surface (4)
    NAME="${arr[0]}"
    PRE_NAME="${NAME:0:8}"
    NAME="${NAME:9}"
    if [ "${PRE_NAME}" = "section:" ]; then
		# advance to next MODE
		MODE=$(($MODE + 1))

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
	CONFIG=""
    for REQ in "${array[@]}"; do

		# find CONFIG_ name (if present) for current feature (only for display purposes)
		if [ -z "$CONFIG" ]; then
			config=$(echo "$REQ" | grep "CONFIG_")
			[ -n "$config" ] && CONFIG="($(echo $REQ | cut -d'=' -f1))"
		fi

        if (checkRequirement "$REQ"); then
            AVAILABLE_PASSED_REQ=$(($AVAILABLE_PASSED_REQ + 1))
        else
            break
        fi
    done

    # split line with enablement requirements & loop thru all enablement reqs one by one & check whether it is met
    ENABLE_PASSED_REQ=0
    ENABLE_REQS_NUM=0
    noSysctl=0
    if [ -n "$ENABLE" ]; then
        IFS=',' read -r -a array <<< "$ENABLE"
        ENABLE_REQS_NUM=${#array[@]}
        for REQ in "${array[@]}"; do
            cmdStdout=$(checkRequirement "$REQ")
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

    if [ -n "$cmdStdout" ]; then
        if [ $cmdStdout -eq 0 ]; then
            state="[ ${txtred}Set to $cmdStdout${txtrst} ]"
			cmdStdout=""
        else
            state="[ ${txtgrn}Set to $cmdStdout${txtrst} ]"
			cmdStdout=""
        fi
    else

	unknown="[ ${txtgray}Unknown${txtrst}  ]"

	# for 3rd party (3) mode display "N/A" or "Enabled"
	if [ $MODE -eq 3 ]; then
            enabled="[ ${txtgrn}Enabled${txtrst}   ]"
            disabled="[   ${txtgray}N/A${txtrst}    ]"

        # for attack-surface (4) mode display "Locked" or "Exposed"
        elif [ $MODE -eq 4 ]; then
           enabled="[ ${txtred}Exposed${txtrst}  ]"
           disabled="[ ${txtgrn}Locked${txtrst}   ]"

	# other modes" "Disabled" / "Enabled"
	else
		enabled="[ ${txtgrn}Enabled${txtrst}  ]"
		disabled="[ ${txtred}Disabled${txtrst} ]"
	fi

	if [ -z "$KCONFIG" -a "$ENABLE_REQS_NUM" = 0 ]; then
	    state=$unknown
    elif [ $AVAILABLE_PASSED_REQ -eq $AVAILABLE_REQS_NUM -a $ENABLE_PASSED_REQ -eq $ENABLE_REQS_NUM ]; then
        state=$enabled
    else
        state=$disabled
	fi

    fi

    echo -e " $state $feature ${wht}${CONFIG}${txtrst}"
    [ -n "$analysis_url" ] && echo -e "              $analysis_url"
    echo

done

}

displayExposure() {
    RANK=$1

    if [ "$RANK" -ge 6 ]; then
        echo "highly probable"
    elif [ "$RANK" -ge 3 ]; then
        echo "probable"
    else
        echo "less probable"
    fi
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
    [ -z "$KCONFIG" ] && echo "WARNING. Kernel Config not found on the system results won't be complete."

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

        # extract distribution version from /etc/os-release OR /etc/lsb-release
        [ -n "$OS" -a "$opt_skip_more_checks" = "false" ] && DISTRO=$(grep -s -E '^DISTRIB_RELEASE=|^VERSION_ID=' /etc/*-release | cut -d'=' -f2 | head -1 | tr -d '"')

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
j=0
for EXP in "${EXPLOITS[@]}" "${EXPLOITS_USERSPACE[@]}"; do

    # create array from current exploit here doc and fetch needed lines
    i=0
    # ('-r' is used to not interpret backslash used for bash colors)
    while read -r line
    do
        arr[i]="$line"
        i=$((i + 1))
    done <<< "$EXP"

    NAME="${arr[0]}" && NAME="${NAME:6}"
    REQS="${arr[1]}" && REQS="${REQS:6}"
    TAGS="${arr[2]}" && TAGS="${TAGS:6}"
    RANK="${arr[3]}" && RANK="${RANK:6}"

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
        if [ -n "$TAGS" -a -n "$OS" ]; then
            IFS=',' read -r -a tags_array <<< "$TAGS"
            TAGS_NUM=${#tags_array[@]}

            # bump RANK slightly (+1) if we're in '--uname' mode and there's a TAG for OS from uname string
            [ "$(echo "${tags_array[@]}" | grep "$OS")" -a "$opt_uname_string" == "true" ] && RANK=$(($RANK + 1))

            for TAG in "${tags_array[@]}"; do
                tag_distro=$(echo "$TAG" | cut -d'=' -f1)
                tag_distro_num_all=$(echo "$TAG" | cut -d'=' -f2)
                # in case of tag of form: 'ubuntu=16.04{kernel:4.4.0-21} remove kernel versioning part for comparision
                tag_distro_num="${tag_distro_num_all%{*}"

                # we're in '--uname' mode OR (for normal mode) if there is distro version match
                if [ "$opt_uname_string" == "true" -o \( "$OS" == "$tag_distro" -a "$(echo "$DISTRO" | grep -E "$tag_distro_num")" \) ]; then

                    # bump current exploit's rank by 2 for distro match (and not in '--uname' mode)
                    [ "$opt_uname_string" == "false" ] && RANK=$(($RANK + 2))

                    # get name (kernel or package name) and version of kernel/pkg if provided:
                    tag_pkg=$(echo "$tag_distro_num_all" | cut -d'{' -f 2 | tr -d '}' | cut -d':' -f 1)
                    tag_pkg_num=""
                    [ $(echo "$tag_distro_num_all" | grep '{') ] && tag_pkg_num=$(echo "$tag_distro_num_all" | cut -d'{' -f 2 | tr -d '}' | cut -d':' -f 2)

                    #[ -n "$tag_pkg_num" ] && echo "tag_pkg_num: $tag_pkg_num; kernel: $KERNEL_ALL"

                    # if pkg/kernel version is not provided:
                    if [ -z "$tag_pkg_num" ]; then
                        [ "$opt_uname_string" == "false" ] && TAG="${lightyellow}[ ${TAG} ]${txtrst}"

                    # kernel version provided, check for match:
                    elif [ -n "$tag_pkg_num" -a "$tag_pkg" = "kernel" ]; then
                        if [ $(echo "$KERNEL_ALL" | grep -E "${tag_pkg_num}") ]; then
                            # kernel version matched - bold highlight
                            TAG="${yellow}[ ${TAG} ]${txtrst}"

                            # bump current exploit's rank additionally by 3 for kernel version regex match
                            RANK=$(($RANK + 3))
                        else
                            [ "$opt_uname_string" == "false" ] && TAG="${lightyellow}[ $tag_distro=$tag_distro_num ]${txtrst}{kernel:$tag_pkg_num}"
                        fi

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

        # insert the matched exploit (with calculated Rank and highlighted tags) to arrary that will be sorted
        EXP=$(echo "$EXP" | sed -e '/^Name:/d' -e '/^Reqs:/d' -e '/^Tags:/d')
        exploits_to_sort[j]="${RANK}Name: ${NAME}D3L1mReqs: ${REQS}D3L1mTags: ${tags}D3L1m$(echo "$EXP" | sed -e ':a' -e 'N' -e '$!ba' -e 's/\n/D3L1m/g')"
        ((j++))
    fi
done

# sort exploits based on calculated Rank
IFS=$'\n'
SORTED_EXPLOITS=($(sort -r <<<"${exploits_to_sort[*]}"))
unset IFS

# display sorted exploits
for EXP_TEMP in "${SORTED_EXPLOITS[@]}"; do

	RANK=$(echo "$EXP_TEMP" | awk -F'Name:' '{print $1}')

	# convert entry back to canonical form
	EXP=$(echo "$EXP_TEMP" | sed 's/^[0-9]//g' | sed 's/D3L1m/\n/g')

	# create array from current exploit here doc and fetch needed lines
    i=0
    # ('-r' is used to not interpret backslash used for bash colors)
    while read -r line
    do
        arr[i]="$line"
        i=$((i + 1))
    done <<< "$EXP"

    NAME="${arr[0]}" && NAME="${NAME:6}"
    REQS="${arr[1]}" && REQS="${REQS:6}"
    TAGS="${arr[2]}" && tags="${TAGS:6}"

	EXPLOIT_DB=$(echo "$EXP" | grep "exploit-db: " | awk '{print $2}')
	analysis_url=$(echo "$EXP" | grep "analysis-url: " | awk '{print $2}')
	ext_url=$(echo "$EXP" | grep "ext-url: " | awk '{print $2}')
	comments=$(echo "$EXP" | grep "Comments: " | cut -d' ' -f 2-)
	reqs=$(echo "$EXP" | grep "Reqs: " | cut -d' ' -f 2)

	# exploit name without CVE number and without commonly used special chars
	name=$(echo "$NAME" | cut -d' ' -f 2- | tr -d ' ()/')

	bin_url=$(echo "$EXP" | grep "bin-url: " | awk '{print $2}')
	src_url=$(echo "$EXP" | grep "src-url: " | awk '{print $2}')
	[ -z "$src_url" ] && [ -n "$EXPLOIT_DB" ] && src_url="https://www.exploit-db.com/download/$EXPLOIT_DB"
	[ -z "$src_url" ] && [ -z "$bin_url" ] && exitWithErrMsg "'src-url' / 'bin-url' / 'exploit-db' entries are all empty for '$NAME' exploit - fix that. Aborting."

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
        echo -e "   Exposure: $(displayExposure $RANK)"
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

done
