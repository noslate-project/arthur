/* Arthur is a field tool belonging to alinode debugger project,
 * normally used to generate corefile, or inspect nodejs variables in live time.
 */

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>
#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>

#include "core.h"
#include "proc.h"
#include "lz4.h"

using namespace arthur;

enum ARTHUR_OP {
    ARTHUR_OP_GENERATE = 0, // process to acore
    ARTHUR_OP_DECOMPRESS,   // acore to corefile
    ARTHUR_OP_MERGE,        // merge acore and core to final corefile
};

struct ArthurCfg {
    pid_t pid;
    ARTHUR_OP op;
    const char *metafile;
    const char *corefile;
    const char *output;
    int mode;
} cfg = {0};

void show_version() 
{
    printf(GIT_VERSION "\n");
}

void help()
{
    const char* help = "Arthur - Alinode Runtime Debugger (" GIT_VERSION ")\n"
    "\n"
    "Capture a corefile,\n"
    "  arthur -p <pid> \n"
    "  arthur -p <pid> -o <filename>\n"
    "  arthur -p <pid> -o <filename> <Mode>\n"
    "\n"
    "Mode,\n"
    " -0 : forkcore and lz4 compressed. (default)\n"
    " -1 : same as gcore but lz4 compressed, less file size.\n"
    " -2 : same as (1) but corefile by kernel, merge a corefile afterwise.\n"
    " -3 : attach to process, write gcore with lz4 compressed on SIGSIL, SIGABRT and SIGSEGV\n"
    "      able to write out acorefile when monitoring"
    "\n"
    "Convert acore to corefile,\n"
    "  arthur -c <acore> -o <corefile>\n"
    "\n"
    "Merge support for Mode(2),\n"
    "  arthur -m <acore> <core> -o <corefile>\n"
    "\n" 
    ;

    puts(help);
}

int main(int argc, char *argv[])
{   
    const char *opts = "hvp:d:t:mc:o:1234567890";
    struct option longopts[] = {
             { "help", no_argument, NULL, 'h' },
             { "pid", required_argument, NULL, 'p' },
             { "merge", no_argument, NULL, 'm' },
             { "core", required_argument, NULL, 'c' },
             { "output", required_argument, NULL, 'o' },
             { "version", no_argument, NULL, 'v' },
             { NULL, 0, NULL, 0 }
    };

    int ch;
    while ((ch = getopt_long(argc, argv, opts, longopts, NULL)) != -1) {
        switch (ch) {

        case 'p':   // pid
            cfg.pid = atoi(optarg);
            break;

        case 'm':   // merge
            cfg.op = ARTHUR_OP_MERGE;
            break;
        
        case 'c':   // core
            cfg.op = ARTHUR_OP_DECOMPRESS;
            cfg.metafile = strdup(optarg);
            break;

        case 'o':   // output
            cfg.output = strdup(optarg);
            break;

        case '0':   // forkcore
            cfg.mode = 0;
            break;

        case '1':   // gcore
            cfg.mode = 1; 
            break;
        
        case '2':   // forkcore by kernel 
            cfg.mode = 2; 
            break;

        case '3':   // monitor
            cfg.mode = 3;
            break;

        case 'h':
            help();
            exit(0);
        
        case 'v':
            show_version();
            exit(0); 
        
        default:
            help();
            return -1;
        }
    }

    Coredump dump(cfg.pid);
    // capture
    if (cfg.pid) {
        char fpath[PATH_MAX];
        const char *fout = cfg.output;
        if (!fout) {
            snprintf(fpath, sizeof(fpath), "acore.%u", cfg.pid);
            fout = fpath; 
        }

        dump.takememspace();
        switch (cfg.mode) {
            case 0: 
                return dump.forkcore(fout, 0);
            case 1: 
                return dump.generate(fout);
            case 2: 
                return dump.forkcore(fout, 1);
            case 3:
                return dump.monitor(fout);
            default: 
                help();
                exit(1);
        }
    }

    // decompress 
    if (cfg.op == ARTHUR_OP_DECOMPRESS) {
        return dump.decompress(cfg.metafile, cfg.output);
    }

    // merge
    if (cfg.op == ARTHUR_OP_MERGE) {
         
    }

    if (argc == optind) {
        help();
        return 2;
    }

    // test file compress
    if (cfg.mode == 1) {
        const char *file = argv[optind];
        char buf[128];
        snprintf(buf, sizeof(buf), "%s.z4", file);
        return dump.test_compress(file, buf);
    } else if (cfg.mode == 2) {
        const char *in_file = argv[optind];
        const char *out_file = argv[optind+1];
        return dump.test_decompress(in_file, out_file);
    }

    return 0;
}
