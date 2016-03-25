# sup

## a "small is beautiful" tool for unix privilege escalation

`sup` is a very small and secure c application. it is designed to run as
root (with suid bit on) to facilitate the privilege escalation of users
to execute certain programs as superuser.

all settings in sup are hard-coded at compile time. sup is very
portable and self-contained, designed for production use as a static
binary. sup is a sort of hard-coded `sudo`: it is an ideal companion
for artisans building small containers and embedded systems.

the latest version of sup can be found at
[https://git.devuan.org/jaromil/sup][origin]
and on its mirrors at dyne.org and [github.com][m1].

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
#define USER 1000
#define GROUP -1

#define SETUID 0
#define SETGID 0

#define CHROOT ""
#define CHRDIR ""

#define HASH 1

#define ENFORCE 1

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
easily done by first installing `musl-libc` in its default location and
then using the `make musl` command.

## technical details

sup consists of 3 files:

- `sup.c` is the main source
- `config.h` is the configuration, hardcoded at compile time
- `sha256.c` is optional and provides the hashing functionality if
  `# define HASH 1` is set.

sup is written in ansi c with posix1.b compliance for gnu/linux and bsd
systems. it uses `setuid/gid` for privilege escalation and `execv()` to
launch processes as superuser.

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

### why not use su?

sup is made so that people (or scripts) don't have to type passwords
every time they need to execute something they are entitled to execute
as superusers. with `su` one has to type the root password every time.
also scripts won't work without interaction.

## licensing

sup is copyleft software licensed as GNU Lesser Public License
(LGPLv3). when compiled with hashing capability, its license turns into
GNU GPLv2 because of the sha256 component.

```
sup is copyleft (c) 2009-2011 by pancake of nopcode.org
                (c) 2016      by jaromil of dyne.org

the FIPS-180-2 sha-256 implementation optionally included in sup is
copyleft (c) 2001-2003 by Christophe Devine
```
