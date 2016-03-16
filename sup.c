/* pancake <nopcode.org> -- Copyleft 2009-2011 */

#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>

#include <sys/types.h>
#include <pwd.h>

#define HELP "sup [-hlv] [cmd ..]"

#define MAXCMD 512

struct rule_t {
    int uid;
    int gid;
    const char *cmd;
    const char *path;
};

#include "config.h"

static int error(int ret, const char *org, const char *str) {
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


int main(int argc, char **argv) {

    static char cmd[MAXCMD];
    struct passwd *pw;
    int i, uid, gid, ret;

    if (argc < 2 || !strncmp (argv[1], "-h", 2)) {
        fprintf(stdout, "%s\n", HELP);
        return (0);
    }

    if (!strncmp (argv[1], "-v", 2)) {
        fprintf(stdout, "sup %.1f - small and beautiful superuser tool\n", VERSION);
        // "sup 0.1 pancake <nopcode.org> copyleft 2011"
        return (0);
    }

    if (!strcmp (argv[1], "-l")) {
        fprintf(stdout,"List of compiled in authorizations:\n\n");
        fprintf(stdout,"User\tUID\tGID\t%10s%25s\n",
                "Command","Forced PATH");
        for (i = 0; rules[i].cmd != NULL; i++) {
            pw = getpwuid( rules[i].uid );
            fprintf (stdout, "%s\t%d\t%d%16s%25s\n",
                    pw->pw_name, rules[i].uid,
                    rules[i].gid,
                    rules[i].cmd, rules[i].path);
        }
        fprintf(stdout,"\nFlags: %s %s %s\n",
                ENFORCE?"ENFORCE":"",
                strlen(CHROOT)?"CHROOT":"",
                strlen(CHRDIR)?"CHRDIR":"");
        return 0;
    }

    uid = getuid ();
    gid = getgid ();
    // get the username string from /etc/passwd
    pw = getpwuid( uid );

    // copy the execv argument locally
    snprintf(cmd,MAXCMD,"%s",argv[1]);

    fprintf(stderr,"sup %s called by %s(%d) gid(%d)\n",
            cmd, pw->pw_name, uid, gid);

    for (i = 0; rules[i].cmd != NULL; i++) {
        if (*rules[i].cmd=='*' || !strcmp (argv[1], rules[i].cmd)) {
#if ENFORCE
            struct stat st;
            if (*rules[i].path=='*') {
                if (*argv[1]=='.' || *argv[1]=='/')
                    snprintf(cmd,MAXCMD,"%s",argv[1]);
                else if (snprintf(cmd,MAXCMD,"%s",getpath(argv[1]))<0)
                    return error (1, "execv", "cannot find program");
            } else snprintf(cmd,MAXCMD,"%s",rules[i].path);
            if (lstat (cmd, &st) == -1)
                return error (1, "lstat", "cannot stat program");
            if (st.st_mode & 0022)
                return error (1, "stat", "cannot run binaries others can write.");
#endif
            if (uid != SETUID && rules[i].uid != -1 && rules[i].uid != uid)
                return error (1, "urule", "user does not match");

            if (gid != SETGID && rules[i].gid != -1 && rules[i].gid != gid)
                return error (1, "grule", "group id does not match");

            if (setuid (SETUID) == -1 || setgid (SETGID) == -1 ||
                seteuid (SETUID) == -1 || setegid (SETGID) == -1)
                return error (1, "set[e][ug]id", strerror (errno));
#ifdef CHROOT
            if (*CHROOT)
                if (chdir (CHROOT) == -1 || chroot (".") == -1)
                    return error (1, "chroot", strerror (errno));
            if (*CHRDIR)
                if (chdir (CHRDIR) == -1)
                    return error (1, "chdir", strerror (errno));
#endif
            ret = execv (cmd, &argv[1]);
            return error (ret, "execv", strerror (errno));
        }
    }

    return error (1, NULL, "Sorry");
}
