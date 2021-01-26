# sup

## a "small is beautiful" tool for unix privilege escalation

`sup` is a very small and secure c application. it is designed to run as
root (with suid bit on) to facilitate the privilege escalation of users
to execute certain programs as superuser.

all settings in sup are hard-coded at compile time. sup is very
portable and self-contained, designed for production use as a static
binary. sup is a sort of hard-coded `sudo`: it is an ideal companion
for artisans building small containers and embedded systems.

sup's new homepage is [sup.dyne.org](https://sup.dyne.org)

sup code can be [read and reviewed on-line](https://sup.dyne.org/sup.html)

stable releases can be downloaded from [files.dyne.org/sup](https://files.dyne.org/sup)

releases are signed with the [maintainer's keys](https://keybase.io/jaromil)

the develpment version of sup can be found at [git.devuan.org/jaromil/sup](https://git.devuan.org/jaromil/sup)

of course there is also a [github mirror](https://github.com/dyne/sup)

[![software by Dyne.org](https://www.dyne.org/wp-content/uploads/2015/12/software_by_dyne.png)](http://www.dyne.org)

[origin]: https://git.devuan.org/jaromil/sup
[m1]: https://github.com/dyne/sup

## why are you whispering?

as you may have realised already, sup is so minimal that all its
documentation is written lowercase. it was originally written in 2009 by
pancake of nopcode.org and maintained until 2011 as part of the suckless
tools. in 2016 sup is being adopted by jaromil of dyne.org, extending
its features to support static build with [musl-libc]() and hardcoded
sha256 hashing of binary files.

[musl-libc]: http://www.musl-libc.org/

## configure

sup's configuration resides in `config.h` and should be set before
building. here below an intuitive example:

```c
// sup's configuration file
// need sup to be re-compiled for any change to be effective

/// un/comment flags below to remove functionalities
#define HASH 1
#define DAEMON 1
// #define DEBUG 1

#ifndef FLAGSONLY

#define USER 1000
#define GROUP -1

#define SETUID 0
#define SETGID 0

#define CHROOT ""
#define CHRDIR ""

static struct rule_t rules[] = {
    // allow user to run these programs when found at a specific path location
    { USER, GROUP, "whoami",   "/usr/bin/whoami", "" },
    { USER, GROUP, "ifconfig", "/sbin/ifconfig",  "" },
    { USER, GROUP, "ls",       "/bin/ls",         "" },
    { USER, GROUP, "wifi",     "/root/wifi.sh",   "" },
    // allow to run id when found with matching hash anywhere in PATH
    { USER, GROUP, "id",       "*", "db533b77fc9e262209a46e0f.." },
     // allow to run any program found in PATH
    { USER, GROUP, "*",        "*"},
    { 0 }, // end of configuration
};
#endif
```

fields are organized as follows:

| USER | GROUP | binary name | binary path | hash (optional) |

- `USER` is the numeric id (UID) of the user authorized to execute the
  binary as superuser
- `GROUP` is the numeric group (GID) of the user authorized to execute
  the binary as superuser (use -1 for none)
- `binary name` is the command to run with `setuid/setgid`, e.g., `ls`
- `binary path` is the path to the program, e.g., `/bin/ls`
- `hash` can be computed before build using `sha256sum` (from GNU coreutils)

`binary name` and `binary path` accept the wildcard character `*` to
mean any executable, and anywhere in PATH, respectively.

running `sup -l` will display the compiled-in configuration.

## build

sup requires a c compiler and the gnu make tool to be built.

a simple `make` command will build a sup binary good enough for
evaluation purposes, with dynamic links to the `libm` and `libc`
libraries installed system-wide.

for production use, sup should be built as a static binary: this is
easily done by first installing `musl-libc` in its default location
(`/usr/local/musl`) and then using the `make musl` command inside sup.

## technical details

sup consists of 3 files:

- `sup.c` is the main source
- `config.h` is the configuration, hardcoded at compile time
- `sha256.c` is optional and provides the hashing functionality if
  `# define HASH 1` is set.

sup is written in ansi c with posix1.b compliance for gnu/linux and
bsd systems. it uses `setuid/gid` for privilege escalation and
`execv()` to launch processes as superuser. daemon mode uses `fork()`
to send processes in the background with `NOTTY` and `stdin/out/err`
file descriptors set to `/dev/null`.

## frequently asked questions

### is there a package for sup?

it does not make sense to have a sup package. sup is configured at
build-time and its built binaries are specific to the task they have
been built and set suid for. sup is a tool for people distributing
containers, online services, embedded devices, and such.

### why not use doas (openbsd)?

sup is different from `doas`, because `doas` is
[configured at runtime][doas].

[doas]: http://www.openbsd.org/cgi-bin/man.cgi/OpenBSD-current/man5/doas.conf.5

### why not use sudo?

same reason as above, `sudo` is configured at runtime.

also `sudo` is very complex and therefore less secure, for instance [it has been found to be vulnerable to an heap-overflow attack](https://blog.qualys.com/vulnerabilities-research/2021/01/26/cve-2021-3156-heap-based-buffer-overflow-in-sudo-baron-samedit) for a bug that went unnoticed for 10 years. 

### why not use su?

sup is made so that people (or scripts) don't have to type passwords
every time they need to execute something they are entitled to execute
as superusers. with `su` one has to type the root password every time.
also scripts won't work without interaction.

### is sup still a suckless tool?

this new code hasn't been grinded by the merry folks at suckless yet,
but pancake has acknowledged this development and, having left
maintainance, is happy to hand it over to jaromil.

## licensing

sup is copyleft software licensed as gnu lesser public license
(lgplv3). when compiled with hashing capability, its license turns into
gnu gplv2+ because of the sha256 component.

```
sup is copyleft (c) 2009-2011 by pancake of nopcode.org
.               (c) 2016      by jaromil of dyne.org
the fips-180-2 sha-256 implementation optionally included in sup is
copyleft (c) 2001-2003 by christophe cevine
```
