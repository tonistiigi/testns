#define _GNU_SOURCE
#include <errno.h>
#include <linux/limits.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Use raw setns syscall for versions of glibc that don't include it
// (namely glibc-2.12)
#if __GLIBC__ == 2 && __GLIBC_MINOR__ < 14
    #define _GNU_SOURCE
    #include "syscall.h"
    #if defined(__NR_setns) && !defined(SYS_setns)
	#define SYS_setns __NR_setns
    #endif

    #ifdef SYS_setns
	int setns(int fd, int nstype)
	{
	    return syscall(SYS_setns, fd, nstype);
	}
    #endif
#endif

#define pr_perror(fmt, ...)                                                    \
	fprintf(stderr, "nsenter: " fmt ": %m\n", ##__VA_ARGS__)

static int get_init_pipe(char* env)
{
	char	buf[PATH_MAX];
	char	*initpipe;
	int	pipenum = -1;

	initpipe = getenv(env);
	if (initpipe == NULL) {
		return -1;
	}

	pipenum = atoi(initpipe);
	snprintf(buf, sizeof(buf), "%d", pipenum);
	if (strcmp(initpipe, buf)) {
		pr_perror("Unable to parse %s", env);
		exit(1);
	}

	return pipenum;
}


void initReexec(void)
{
	int	fd;
	fd = get_init_pipe("_TESTNS_SET_MNTNS");
	if (fd != -1) {
		 setns(fd, CLONE_NEWNS);
	}
	fd = get_init_pipe("_TESTNS_SET_NETNS");
	if (fd != -1) {
		 setns(fd, CLONE_NEWNET);
	}
}
