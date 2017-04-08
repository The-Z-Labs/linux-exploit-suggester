
## linux-exploit-suggester

### Overview

linux-exploit-suggester.sh was inspired by the excellent [Linux_Exploit_Suggester](https://github.com/PenturaLabs/Linux_Exploit_Suggester) script by [PenturaLabs](https://penturalabs.wordpress.com/). The issue with Pentura's script however is that it isn't up to date anymore (the script was last updated in early 2014) so it lacks some recent Linux kernel exploits. linux-exploit-suggester.sh on the other hand also contains all the latest (as of early 2017) publicly known Linux kernel exploits. It is also capable to identify possible privilege escalation vectors via installed userspace packages and comes with some additional minor features that makes finding right exploit more time efficient.

The purpose of this script is twofold:

 - maintaining up-to-date list of Linux privilege escalation exploits and essential info about it.
 - **assisting** security analyst in identifying local priv esc attack vectors on target Linux machine.

Example of script's output:

![Alt text](/../screenshot/screenshot2.png "linux-exploit-suggester.sh output")

Here's the comparision between the linux-exploit-suggester.sh and [Linux_Exploit_Suggester](https://github.com/PenturaLabs/Linux_Exploit_Suggester) scripts:

- linux-exploit-suggester.sh aims to contain list of all publicly known Linux kernel exploits applicable for kernels 2.6 and up
- On debian-based & redhat-based distros linux-exploit-suggester.sh checks for privilege escalation vectors also via installed userspace packages by parsing `'dpkg -l'/'rpm -qa'` output and comparing it to contained list of publicly known privilege escalation exploits
- In linux-exploit-suggester.sh many exploits were tagged with the distribution name on which they have successfully run. This is an additional tip which is supposed to make chosing the right exploit for the target at hand easier and quicker. Tags comes from three main sources: exploit authors (they often indicate in exploit's source on which distro they have developed/run/tested the exploit); from exploit-db.com; and from my own testing. You are more than welcome to send me the info on which distro you have successfully run particular exploit to make exploit tagging more complete and more accurate
- linux-exploit-suggester.sh tries to be as compatible with Linux_Exploit_Suggester as possible. It uses the same exploits names, it supports `-k` flag and it has very similar output
- exploits that are aplicable solely for kernels 2.4.x were dropped from linux-exploit-suggester.sh - I believe that 2.4 kernels are so rare these days that there's no point in keeping them (if you don't agree and you work with this kernel line regularly during your pen testing engagements please let me know)
- exploits from Linux_Exploit_Suggester which have no download link (like: elfcd, kdump, local26, ong_bak, pwned, py2, etc.) were dropped from linux-exploit-suggester.sh because there's no point in keeping exploits with no source code available (if you have access to source code for these exploits please let me know)
- linux-exploit-suggester.sh has some additional minor features like `--fetch-sources` and `--fetch-binaries`
- linux-exploit-suggester.sh is written in bash as opposed to Linux_Exploit_Suggester which was coded in perl

### Tips, limitations, caveats

 - Remember that this script is only meant to **assist** the analyst in his auditing activities. It won't do the all work for him!
 - That's the analyst job to determine whether given target at hand isn't patched against generated list of candidate exploits (the script doesn't look at distro patchlevel so obviously it won't do that for you)
 - In addition to manual inspection [Oracle's Ksplice Inspector](http://www.ksplice.com/inspector) could come handy with determining the previous one
 - Selected exploit almost certainly will need some customization to suit your target (at minimum: correct commit_creds/prepare_kernel_cred pointers) so knowledge about kernel exploitation techniques is needed
 - Identifying privilege escalation vectors via installed userspace programs should be treated as experimental feature for now

### Usage

```
Usage: linux-exploit-suggester.sh [OPTIONS]

 --version                    - print version of this script
 -h | --help                  - print this help
 -k | --kernel <version>      - provide kernel version
 -u | --uname <string>        - provide 'uname -a' string
 -p | --pkglist-file <file>   - provide file with 'dpkg -l' or 'rpm -qa' command output
 -s | --fetch-sources         - automatically downloads source for matched exploit
 -b | --fetch-binaries        - automatically downloads binary for matched exploit if available
 -f | --full                  - show full info about matched exploit
 -g | --grepable              - show grep friendly info about matched exploit
 --kernelspace-only           - show only kernel vulnerabilities
 --userspace-only             - show only userspace vulnerabilities
 -d | --show-dos              - show DoSes in results
```

Kernel version and package listing are taken directly from current machine:

    $ ./linux-exploit-suggester.sh

As previously but only userspace exploits are displayed:

    $ ./linux-exploit-suggester.sh --userspace-only

Kernel version number is taken from command line (compatibility mode with Linux_Exploit_Suggester) additionally sources for applicable exploits are downloaded to current directory:

    $ ./linux-exploit-suggester.sh -k 3.1 --fetch-sources

`uname -a` string from remote machine is provided. Kernel version and architecture (x86, x86_64) is taken into account when generating list of applicable exploits:

    $ ./linux-exploit-suggester.sh --uname "Linux taris 3.16.0-30-generic #40~14.04.1-Ubuntu SMP Thu Jan 15 17:43:14 UTC 2015 x86_64 x86_64 x86_64 GNU/Linux"

As previously but additionally package listing from remote machine is provided for identifying possible priv esc vectors via installed packages (in terms of output its identical with executing `./linux-exploit-suggester.sh` directly on the given remote machine): 

    (remote machine) $ dpkg -l > dpkgOutput.txt
    $ ./linux-exploit-suggester.sh --uname "Linux taris 3.16.0-30-generic #40~14.04.1-Ubuntu SMP Thu Jan 15 17:43:14 UTC 2015 x86_64 x86_64 x86_64 GNU/Linux" --pkglist-file dpkgOutput.txt

Kernel version number is taken from command line, full details (like: kernel version requirements, comments and URL pointing to announcement/technical details about exploit) about matched exploits are listed:

    $ ./linux-exploit-suggester.sh -k 4.1 --full

Kernel version number is taken from current OS, binaries for applicable exploits are downloaded (if available) to current directory:

    $ ./linux-exploit-suggester.sh --fetch-binaries

Note however that `--fetch-binaries` is not recommended as it downloads binaries from generally not trusted sources and most likely these binaries weren't compiled for your target anyway. It should be used as a kind of last resort option when you're running out of time during your pen testing engagement and there is no compiler available on your target at hand.
