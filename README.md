
## linux-exploit-suggester

Quick download:

    wget https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh -O les.sh

### Purpose

Often during the penetration test engagement the security analyst faces the problem of identifying privilege escalation attack vectors on tested Linux machine(s). One of viable attack vectors is using publicly known Linux exploit to gain `root` privileges on tested machine. Of course in order to do that the analyst needs to identify the right PoC exploit, make sure that his target is affected by the associated vulnerability and finally modify the exploit to suit his target. The `linux-exploit-suggester.sh` tool is designed to help with these activities.

### Overview

The tool is meant to assist the security analyst in his testing for privilege escalation opportunities on Linux machine, it provides following features:

**"Remote" mode (--kernel or --uname switches)**

In this mode the analyst simply provides kernel version (`--kernel` switch) or `uname -a` command output (`--uname` switch) and receives list of candidate exploits for a given kernel version.

Using this mode one can also check for candidate user space exploits (with `--pkglist-file` switch) if he has access to installed packages listing (output of `dpkg -l/rpm -qa` commands) of examined system.

**"Direct" mode (default run)**

The basic idea behind this mode is the same as previously but additionally in an effort to produce more relevant list of candidate exploits, the tool also performs series of additional checks (like: kernel build settings aka CONFIG_*, sysctl entries and other custom checks defined on per-exploit basis) to rule out exploits that for sure won't be applicable due to OS customization. Obviously to take advantage of this mode the tool needs to be run **directly on target machine**. For example for 'af_packet' exploit which requirements looks like this:

    Reqs: pkg=linux-kernel,ver>=3.2,ver<=4.10.6,CONFIG_USER_NS=y,sysctl:kernel.unprivileged_userns_clone==1

the script (in addition to checking kernel version) will check if target kernel was built with `CONFIG_USER_NS` and if sysctl entry `kernel.unprivileged_userns_clone` is enabled. If desired those additional checks can by skipped by running with `--skip-more-checks` command line switch.

By default tool also checks for applicable user space exploits when distribution is one of `Debian, Ubuntu, RHEL/CentOS, Fedora`. To skip user space exploits checks one can run with `--kernelspace-only` switch.

Example of script's output in this mode:

![Alt text](/../screenshot/screenshot3.png "linux-exploit-suggester.sh output")

**"CVE list" mode (--cvelist-file switch)**

In this mode the analyst already posesses partial/full list of CVEs that affects his target kernel and wants to verify if there are any publicly known exploits against this CVEs. Of course efectivness of this mode highly depends on completness of provided CVE list. Such list is usually constructed by manual study and examination of distribution's Changelog for the given kernel version. Alternatively for most popular distros [Oracle's Ksplice Inspector](http://www.ksplice.com/inspector) could be used to speed up this proccess. For example following oneliner worked quite fine for me:

```
$ (uname -s; uname -m; uname -r; uname -v) | curl -s https://api-ksplice.oracle.com/api/1/update-list/ -L -H "Accept: text/text" --data-binary @- | grep CVE | tr ' ' '\n' | grep -o -E 'CVE-[0-9]+-[0-9]+' | sort -r -n | uniq
```

WARNING. By default in addition to comparing CVE IDs, this mode also performs **additional checks** to rule out exploits that won't be applicable due to OS customization (kernel build settings aka CONFIG_*, sysctl entries and other custom settings). So for the best possible results one should run it directly on tested machine or alternatively use `--skip-more-checks` command line switch if running on the target is not possible/not desired.

**"Check security" mode (--checksec switch)**

WARNING. This mode is in beta currently.

This mode is meant to be a modern continuation of [checksec.sh](http://www.trapkit.de/tools/checksec.html)'s `--kernel` switch functionality.

In this mode `linux-exploit-suggester.sh` enumerates target system for various kernel/hardware security features (KASLR, SMEP, etc.) and settings. It checks if given protection mechanism is available (builtin into the kernel): `[ Available ]` and (if applicable) it check if it can be disabled/enabled without recompiling the kernel (via `sysctl` entry or other means): `[ Enabled/Disabled ]` or shows `[ N/A]` if disabling/enabling is not possible/not supported.

Example of script's output in this mode:

![Alt text](/../screenshot/screenshot-checksec.png "linux-exploit-suggester.sh --checksec output")

### Tips, limitations, caveats

 - Remember that this script is only meant to **assist** the analyst in his auditing activities. It won't do the all work for him!
 - That's the analyst job to determine whether given target at hand isn't patched against generated list of candidate exploits (the script doesn't look at distro patchlevel so obviously it won't do that for you)
 - In addition to manual inspection [Oracle's Ksplice Inspector](http://www.ksplice.com/inspector) could come handy with determining the previous one
 - Selected exploit almost certainly will need some customization to suit your target (at minimum: correct commit_creds/prepare_kernel_cred pointers) so knowledge about kernel exploitation techniques is required

### Usage

Default run on target machine (kernel version, packages versions and additional checks as described in "Overview" paragraph are performed to give the list of possible exploits:

    $ ./linux-exploit-suggester.sh

As previously but only userspace exploits are checked:

    $ ./linux-exploit-suggester.sh --userspace-only

Check if exploit(s) for given list of CVE IDs are available:

    $ ./linux-exploit-suggester.sh --cvelist-file <cve-listing-file> --skip-more-checks

Generate list of CVEs for the target kernel and check if exploit(s) for it exists (also performs **additional checks**):

    $ (uname -s; uname -m; uname -r; uname -v) | curl -s https://api-ksplice.oracle.com/api/1/update-list/ -L -H "Accept: text/text" --data-binary @- | grep CVE | tr ' ' '\n' | grep -o -E 'CVE-[0-9]+-[0-9]+' | sort -r -n | uniq > <cve-listing-file>
    $ ./linux-exploit-suggester.sh --cvelist-file <cve-listing-file>

List available hardware/kernel security mechanisms for target machine:

    $ ./linux-exploit-suggester.sh --checksec

Running with `-k` option is handy if one wants to quickly examine which exploits could be potentially applicable for given kernel version (this is also compatibility mode with Linux_Exploit_Suggester):

    $ ./linux-exploit-suggester.sh -k 3.1

With `--uname` one provides slightly more information (`uname -a` output from target machine) to `linux-exploit-suggester.sh` and receives slightly specific list of possible exploits (for example also target arch `x86|x86_64` is taken into account when generating exploits list):

    $ ./linux-exploit-suggester.sh --uname "Linux taris 3.16.0-30-generic #40~14.04.1-Ubuntu SMP Thu Jan 15 17:43:14 UTC 2015 x86_64 x86_64 x86_64 GNU/Linux"

Optionally `--pkglist-file <file>` could be provided to `-k` or `--uname` to also check for user space exploits:

    (remote machine) $ dpkg -l > dpkgOutput.txt
    $ ./linux-exploit-suggester.sh --uname "Linux taris 3.16.0-30-generic #40~14.04.1-Ubuntu SMP Thu Jan 15 17:43:14 UTC 2015 x86_64 x86_64 x86_64 GNU/Linux" --pkglist-file dpkgOutput.txt

In terms of generated list of exploits its identical with executing (directly on the given remote machine):

    (remote machine) $ ./linux-exploit-suggester.sh --skip-more-checks

Sometimes it is desired to examine only package listing (in this case only check for userspace exploits is performed):

    (remote machine) $ dpkg -l > dpkgOutput.txt
    $ ./linux-exploit-suggester.sh --pkglist-file dpkgOutput.txt

As previously but no package versioning is performed (handy for quick preliminary checking if any package for which user space exploit is available is installed):

    $ ./linux-exploit-suggester.sh --pkglist-file dpkgOutput.txt --skip-pkg-versions

Kernel version number is taken from current OS, sources for possible exploits are downloaded to current directory (only kernel space exploits are examined):

    $ ./linux-exploit-suggester.sh --fetch-sources --kernelspace-only

Kernel version number is taken from command line, full details (like: kernel version requirements, comments and URL pointing to announcement/technical details about exploit) about matched exploits are listed:

    $ ./linux-exploit-suggester.sh -k 4.1 --full

Kernel version number is taken from current OS, binaries for applicable exploits are downloaded (if available) to current directory, additional checks are skipped:

    $ ./linux-exploit-suggester.sh --fetch-binaries --skip-more-checks

Note however that `--fetch-binaries` is not recommended as it downloads binaries from generally not trusted sources and most likely these binaries weren't compiled for your target anyway. It should be used as a kind of last resort option when you're running out of time during your pen testing engagement and there is no compiler available on your target at hand.

### Misc

 - The tool was inspired by the [Linux_Exploit_Suggester](https://github.com/PenturaLabs/Linux_Exploit_Suggester) script and it contains all the exploits that are present there (for kernels 2.6+) plus all more recent Linux kernel exploits
 - It is available in [BlackArch](https://www.blackarch.org/) distribution
 - I'm not responsible for how the tool is used and where it is used
