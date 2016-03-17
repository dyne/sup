/*  sup 1.0
 *
 *  (c) 2016 Dyne.org Foundation, Amsterdam
 *
 *  Written by:
 *  2009-2011 pancake <nopcode.org>         (first author)
 *  2016      Denis Roio <jaromil@dyne.org> (current maintainer)
 *
 * This source code is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 3 of
 * the License, or (at your option) any later version.
 *
 * This source code is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  Please refer
 * to the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this source code; if not, write to: Free
 * Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>

#include <pwd.h>

struct rule_t {
    int uid;
    int gid;
    const char *cmd;
    const char *path;
    const char *hash;
};

#include "config.h"

#ifdef HASH
#include "sha256.h"
#endif

#define HELP "sup [-hlv] [cmd ..]"

#define MAXCMD 512

#define MAXBINSIZE 10485760 // 10 MiBs

/* Always return 1 on error, conforming to standard shell checks.
   Reason of error is described by stderr text before colon,
   extended reason can be provided or falls back to errno. */
static int error(const char *code, const char *reason) {
    fprintf (stderr, "%s: %s\n",
             code? code : "",
             reason? reason : strerror (errno));
    exit(1);
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
    int i, uid, gid;

#ifdef HASH
    FILE *fd;
    unsigned char *buf;
    size_t len;
    sha256_context sha;

    unsigned char digest[32];
    char output[65];
#endif

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
            /* Using 'getpwuid' in statically linked applications
               requires at runtime the shared libraries from the glibc
               version used for linking. But not in case of musl-libc. */
            pw = getpwuid( rules[i].uid );
            fprintf (stdout, "%s\t%d\t%d%16s%25s\n",
                     pw?pw->pw_name:"", rules[i].uid, rules[i].gid,
                     rules[i].cmd, rules[i].path);
        }
        fprintf(stdout,"\nFlags: %s %s %s %s\n",
#ifdef HASH
                HASH?"HASH":"",
#else
                "",
#endif
                ENFORCE?"ENFORCE":"",
                strlen(CHROOT)?"CHROOT":"",
                strlen(CHRDIR)?"CHRDIR":"");
        return 0;
    }

    uid = getuid ();
    gid = getgid ();
    // get the username string from /etc/passwd

    // copy the execv argument locally
    snprintf(cmd,MAXCMD,"%s",argv[1]);

    pw = getpwuid( uid );
    /* one could maintain a log of calls here
       fprintf(stderr,"sup %s called by %s(%d) gid(%d)\n",
               cmd, pw?pw->pw_name:"", uid, gid); */

    for (i = 0; rules[i].cmd != NULL; i++) {

        if (*rules[i].cmd=='*' || !strcmp (argv[1], rules[i].cmd)) {

#if ENFORCE
            struct stat st;
            if (*rules[i].path=='*') {
                if (*argv[1]=='.' || *argv[1]=='/')
                    snprintf(cmd,MAXCMD,"%s",argv[1]);
                else if (snprintf(cmd,MAXCMD,"%s",getpath(argv[1]))<0)
                    return error("execv", "cannot find program");
            } else snprintf(cmd,MAXCMD,"%s",rules[i].path);
            if (lstat (cmd, &st) == -1)
                return error("lstat", "cannot stat program");
            if (st.st_mode & 0022)
                return error("perm", "cannot run binaries others can write.");
#endif

            if (uid != SETUID && rules[i].uid != -1 && rules[i].uid != uid)
                return error("uid", "user does not match");

            if (gid != SETGID && rules[i].gid != -1 && rules[i].gid != gid)
                return error("gid", "group id does not match");


#ifdef HASH
            if( strlen(rules[i].hash) ) {
                int c;

                if(st.st_size>MAXBINSIZE)
                    error("binsize", "cannot check hash of file, size too large");

                fd = fopen(cmd,"r");
                if(!fd) error("fopen", "cannot read binary file");

                buf = malloc(st.st_size);
                if(!buf) error("malloc", "cannot allocate memory");


                len = fread(buf,1,st.st_size,fd);
                if(len != st.st_size) {
                    error("fread", "cannot read from binary file");
                    free(buf); fclose(fd); }

                sha256_starts(&sha);
                sha256_update(&sha, buf, (uint32)len);
                sha256_finish(&sha, digest);

                for(c = 0; c<32; c++)
                    sprintf(output + (c * 2),"%02x",digest[c]);
                output[64] = '\0';

                if(strncmp(rules[i].hash, output, 64)!=0) {
                    fprintf(stderr,"%s\n%s\n", rules[i].hash, output);
                    return error("hash", "hash does not match");
                }
            }
#endif

            // privilege escalation done here
            if (setuid (SETUID) == -1 || setgid (SETGID) == -1 ||
                seteuid (SETUID) == -1 || setegid (SETGID) == -1)
                return error("set[e][ug]id", NULL);

#ifdef CHROOT
            if (*CHROOT)
                if (chdir (CHROOT) == -1 || chroot (".") == -1)
                    return error("chroot", NULL);
            if (*CHRDIR)
                if (chdir (CHRDIR) == -1)
                    return error("chdir", NULL);
#endif

            execv (cmd, &argv[1]);
            // execv returns only on errors
            error("execv", NULL);
        }
    }

    // be polite
    fprintf(stderr,"Sorry.\n");
    exit(1);
}
