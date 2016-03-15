/* pancake <nopcode.org> -- Copyleft 2009-2011 */

#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>

#define HELP "sup [-hlv] [cmd ..]"
#define VERSION "sup 0.1 pancake <nopcode.org> copyleft 2011"

struct rule_t {
    int uid;
    int gid;
    const char *cmd;
    const char *path;
};

#include "config.h"

static int die(int ret, const char *org, const char *str) {
    fprintf (stderr, "%s%s%s\n", org?org:"", org?": ":"", str);
    return ret;
}

static char *getpath(const char *str) {
    struct stat st;
    static char file[4096];
    char *p, *path = getenv ("PATH");
    if (path)
        for (p = path; *p; p++) {
            if (*p==':' && (p>path&&*(p-1)!='\\')) {
                *p = 0;
                snprintf (file, sizeof (file)-1, "%s/%s", path, str);
                if (!lstat (file, &st))
                    return file;
                *p = ':';
                path = p+1;
            }
        }
    return NULL;
}

#define MAXCMD 512

int main(int argc, char **argv) {

    static char cmd[MAXCMD];
    int i, uid, gid, ret;

    if (argc < 2 || !strcmp (argv[1], "-h"))
        return die (1, NULL, HELP);

    if (!strcmp (argv[1], "-v"))
        return die (1, NULL, VERSION);

    if (!strcmp (argv[1], "-l")) {
        for (i = 0; rules[i].cmd != NULL; i++)
            printf ("%d %d %10s %s\n", rules[i].uid, rules[i].gid,
                    rules[i].cmd, rules[i].path);
        return 0;
    }

    uid = getuid ();
    gid = getgid ();

    snprintf(cmd,MAXCMD,"%s",argv[1]);
    // fprintf(stderr,"execv: %s\n",cmd);
    for (i = 0; rules[i].cmd != NULL; i++) {
        if (*rules[i].cmd=='*' || !strcmp (argv[1], rules[i].cmd)) {
#if ENFORCE
            struct stat st;
            if (*rules[i].path=='*') {
                if (*argv[1]=='.' || *argv[1]=='/')
                    snprintf(cmd,MAXCMD,"%s",argv[1]);
                else if (snprintf(cmd,MAXCMD,"%s",getpath(argv[1]))<0)
                    return die (1, "execv", "cannot find program");
            } else snprintf(cmd,MAXCMD,"%s",rules[i].path);
            if (lstat (cmd, &st) == -1)
                return die (1, "lstat", "cannot stat program");
            /* if (st.st_mode & 0222) */
            /*     return die (1, "stat", "cannot run writable binaries."); */
#endif
            if (uid != SETUID && rules[i].uid != -1 && rules[i].uid != uid)
                return die (1, "urule", "user does not match");

            if (gid != SETGID && rules[i].gid != -1 && rules[i].gid != gid)
                return die (1, "grule", "group id does not match");

            if (setuid (SETUID) == -1 || setgid (SETGID) == -1 ||
                seteuid (SETUID) == -1 || setegid (SETGID) == -1)
                return die (1, "set[e][ug]id", strerror (errno));
#ifdef CHROOT
            if (*CHROOT)
                if (chdir (CHROOT) == -1 || chroot (".") == -1)
                    return die (1, "chroot", strerror (errno));
            if (*CHRDIR)
                if (chdir (CHRDIR) == -1)
                    return die (1, "chdir", strerror (errno));
#endif
            ret = execv (cmd, &argv[1]);
            return die (ret, "execv", strerror (errno));
        }
    }

    return die (1, NULL, "Sorry");
}
