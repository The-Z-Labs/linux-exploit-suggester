
## LES: Linux privilege escalation auditing tool

Quick download:

    wget https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh -O les.sh

Details about LES usage and inner workings:

    https://mzet-.github.io/2019/05/10/les-paper.html
    
Additional resources for the LES:

    https://github.com/mzet-/les-res

## Purpose

LES tool is designed to assist in detecting security deficiencies for a given Linux kernel/Linux-based machine. It provides following functionality:

### Assessing kernel exposure on publicly known exploits

Tool assesses (using heuristics methods discussed in details [here](https://mzet-.github.io/2019/05/10/les-paper.html)) exposure of the given kernel to publicly known Linux kernel exploits. Example of tool output:

```
$ ./linux-exploit-suggester.sh
...
[+] [CVE-2017-16995] eBPF_verifier

   Details: https://ricklarabee.blogspot.com/2018/07/ebpf-and-analysis-of-get-rekt-linux.html
   Exposure: highly probable
   Tags: debian=9.0{kernel:4.9.0-3-amd64},fedora=25|26|27,[ ubuntu=14.04 ]{kernel:4.4.0-89-generic},ubuntu=(16.04|17.04){kernel:4.(8|10).0-(19|28|45)-generic}
   Download URL: https://www.exploit-db.com/download/45010
   Comments: CONFIG_BPF_SYSCALL needs to be set && kernel.unprivileged_bpf_disabled != 1

[+] [CVE-2017-1000112] NETIF_F_UFO

   Details: http://www.openwall.com/lists/oss-security/2017/08/13/1
   Exposure: probable
   Tags: [ ubuntu=14.04{kernel:4.4.0-*} ],ubuntu=16.04{kernel:4.8.0-*}
   Download URL: https://raw.githubusercontent.com/xairy/kernel-exploits/master/CVE-2017-1000112/poc.c
   ext-url: https://raw.githubusercontent.com/bcoles/kernel-exploits/cve-2017-1000112/CVE-2017-1000112/poc.c
   Comments: CAP_NET_ADMIN cap or CONFIG_USER_NS=y needed. SMEP/KASLR bypass included. Modified version at 'ext-url' adds support for additional distros/kernels

[+] [CVE-2016-8655] chocobo_root

   Details: http://www.openwall.com/lists/oss-security/2016/12/06/1
   Exposure: probable
   Tags: [ ubuntu=(14.04|16.04){kernel:4.4.0-(21|22|24|28|31|34|36|38|42|43|45|47|51)-generic} ]
   Download URL: https://www.exploit-db.com/download/40871
   Comments: CAP_NET_RAW capability is needed OR CONFIG_USER_NS=y needs to be enabled
...
```

For each exploit, exposure is calculated. Following 'Exposure' states are possible:

 - **Highly probable** - assessed kernel is most probably affected and there's a very good chance that PoC exploit will work out of the box without any major modifications.

 - **Probable** - it's possible that exploit will work but most likely customization of PoC exploit will be needed to suit your target.

 - **Less probable** - additional manual analysis is needed to verify if kernel is affected.

 - **Unprobable** - highly unlikely that kernel is affected (exploit is not displayed in the tool's output)

### Verifying state of kernel hardening security measures

LES can check for most of security settings available by your Linux kernel. It verifies not only the kernel compile-time configurations (CONFIGs) but also verifies run-time settings (sysctl) giving more complete picture of security posture for running kernel. This functionality is modern continuation of `--kernel` switch from [checksec.sh](http://www.trapkit.de/tools/checksec.html) tool by Tobias Klein. Example of tool output:

```
$ ./linux-exploit-suggester.sh --checksec

Mainline kernel protection mechanisms:

 [ Disabled ] GCC stack protector support (CONFIG_HAVE_STACKPROTECTOR)
              https://github.com/mzet-/les-res/blob/master/features/stackprotector-regular.md

 [ Disabled ] GCC stack protector STRONG support (CONFIG_STACKPROTECTOR_STRONG)
              https://github.com/mzet-/les-res/blob/master/features/stackprotector-strong.md

 [ Enabled  ] Low address space to protect from user allocation (CONFIG_DEFAULT_MMAP_MIN_ADDR)
              https://github.com/mzet-/les-res/blob/master/features/mmap_min_addr.md

 [ Disabled ] Restrict unprivileged access to kernel syslog (CONFIG_SECURITY_DMESG_RESTRICT)
              https://github.com/mzet-/les-res/blob/master/features/dmesg_restrict.md

 [ Enabled  ] Randomize the address of the kernel image (KASLR) (CONFIG_RANDOMIZE_BASE)
              https://github.com/mzet-/les-res/blob/master/features/kaslr.md

 [ Disabled ] Hardened user copy support (CONFIG_HARDENED_USERCOPY)
              https://github.com/mzet-/les-res/blob/master/features/hardened_usercopy.md

...
```

## Usage

Assess exposure of the Linux box to publicly known exploits:

```
$ ./linux-exploit-suggester.sh
```

Show state of security features on the Linux box:

```
$ ./linux-exploit-suggester.sh --checksec
```

Assess exposure of Linux kernel on publicly known exploits based on the provided 'uname' string (i.e. output of `uname -a` command):

```
$ ./linux-exploit-suggester.sh --uname <uname-string>
```

For more usage examples, see [here](https://mzet-.github.io/2019/05/10/les-paper.html).

## Getting involved

You hopefully now know what LES is and what it can do for you. Now see what you can do for LES:

- Add newly published Linux privilege escalation exploits to it.
- Test existing exploits on various Linux distributions with multiple kernel versions, then document your findings in a form of `Tags` in LES, e.g. of a tag: `ubuntu=12.04{kernel:3.(2|5).0-(23|29)-generic}` which states: *tagged exploit was verifed to work correctly on Ubuntu 12.04 with kernels: 3.2.0-23-generic, 3.2.0-29-generic, 3.5.0-23-generic and 3.5.0-29-generic;*. With this tag added LES will automatically highlight and bump dynamic `Rank` of the exploit when run on Ubuntu 12.04 with one of listed kernel versions. This will help you (and others) during pentests to rapidly identify critically vulnerable Linux machines.
- Published exploits are often written only for PoC purposes only for one (or couple of) specific Linux distributions and/or kernel version(s). Pick sources of the exploit of choice and customize it to run on different kernel version(s). Then add your customized version of exploit as `ext-url` entry to LES and modify `Tags` to reflect newly added targets. See [this](https://ricklarabee.blogspot.com/2017/12/adapting-poc-for-cve-2017-1000112-to.html) article for an excellent example of adapting specific PoC exploit to different kernel versions.
- Conduct source code analysis of chosen kernel hardening security measure then add it to the `FEATURES` array (if not already there) and publish your analysis at: `https://github.com/mzet-/les-res/blob/master/features/<feature-name>.md`.

### Acknowledgments

[bcoles](https://github.com/bcoles/) for his excellent and frequent contributions to LES.
