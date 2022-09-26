#ifndef _ARTHUR_INC_H_
#define _ARTHUR_INC_H_

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>
#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <stdio.h>
#include <fstream>
#include <sys/uio.h>
#include <assert.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <memory.h>
#include <dirent.h>
#include <unistd.h>

// version
#ifndef GIT_VERSION
#define GIT_VERSION "dev"
#endif

// macros
#define MIN(a,b) (((a)<(b))?(a):(b))
#define MAX(a,b) (((a)>(b))?(a):(b))

#define ARRAYSIZE(a) (sizeof(a) / sizeof(*(a)))

// logging
#ifdef USE_SYSLOG   // syslog doesn't work in docker.
#include <syslog.h>
#define logfmt(x, fmt, ...) \
	syslog(x, "turf[%d]: " fmt, getpid(), ## __VA_ARGS__)
#else
/* all log outputs to stderr, 
 * stdout is used for turf state info ouput.
 * example,
 * turf[1314] D: message info.
 */

#define LOG_ERROR   'E'
#define LOG_WARNING 'W'
#define LOG_INFO    'I'
#define LOG_DEBUG   'D'

#define logfmt(x, fmt, ...) \
	fprintf(stderr, "arthur[%d] %c: " fmt, getpid(), x, ## __VA_ARGS__)
#endif

#ifdef USE_DIE_ABORT   // prevent generate coredump.
#define _DIE()   abort()
#else
#define _DIE()   exit(6)
#endif

#define fatal(fmt, ...) \
do { \
    logfmt(LOG_ERROR, fmt, ## __VA_ARGS__); \
	_DIE(); \
} while (0)

#define die(fmt, ...)       fatal("%s:%d " fmt ": %m\n", __func__, __LINE__, ## __VA_ARGS__)
#define error(fmt, ...) 	logfmt(LOG_ERROR, fmt "\n", ## __VA_ARGS__)
#define warn(fmt, ...) 	    logfmt(LOG_WARNING, fmt "\n", ## __VA_ARGS__)
#define pwarn(fmt, ...)     logfmt(LOG_WARNING, fmt ": %m\n", ## __VA_ARGS__)
#define info(fmt, ...) 	    logfmt(LOG_INFO, fmt "\n", ## __VA_ARGS__)
#define die_oom()           die("Out of memory")

#ifdef DEBUG
#define dprint(fmt, ...) 	logfmt(LOG_DEBUG, fmt "\n", ## __VA_ARGS__)
void _hexbuf(const char*, int);
#define hexbuf(...)         _hexbuf(__VA_ARGS__)
#else
#define dprint(fmt, ...)  	
#define hexbuf(...)
#endif

// for path snprintf
#define PATH_MAX    (128)
#define PAGE_SIZE   (4096)

#endif // _ARTHUR_INC_H_
