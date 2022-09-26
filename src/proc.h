/* Support '/proc/xxx' pseudo-filesystem.
 */

#ifndef _ARTHUR_PROC_H_
#define _ARTHUR_PROC_H_

#include <stdlib.h>
#include <string>
#include <vector>

#include "inc.h"

namespace arthur {

#define PROC_TYPE_LIST(v) \
    v(PROC_TYPE_CMDLINE, "cmdline") \
    v(PROC_TYPE_STAT, "stat") \
    v(PROC_TYPE_AUXV, "auxv") \
    v(PROC_TYPE_MAPS, "maps") \
    v(PROC_TYPE_IO, "io") \
    v(PROC_TYPE_ENVIRON, "environ") \
    v(PROC_TYPE_LIMITS, "limits")

#define PROC_TYPE_BITS (6)
#define PROC_TYPE_SIZE (1 << PROC_TYPE_BITS)
// Proc File Type 
enum ProcType {
    PROC_TYPE_UNKNOWN = 0,

#define V(a,b) a,
    PROC_TYPE_LIST(V)
#undef V
    
    // keep append
    PROC_TYPE_MAX,
};
static_assert(PROC_TYPE_MAX <= PROC_TYPE_SIZE, "ProcType oversize"); 

// enum to string function
const char* szProcType(ProcType t);

// represents a /proc/<pid>/<file>
#pragma pack(push, 1)
struct ProcFile {
    uint32_t f_size;    // file size in byte
    uint32_t f_pid;     // pid
    uint8_t  f_type;    // proc type
    char f_data[0];     // begin the file contents

public:
    static ProcFile* ReadPid(char* buf, int buf_len, pid_t pid, ProcType type) {
        ProcFile *f = Read(buf, buf_len, "/proc/%u/%s", pid, szProcType(type));
        if (!f) { 
            return f;
        }
        f->f_pid = pid;
        f->f_type = type;
        return f;
    }

    // return the size of the structure.
    size_t Size() {
        return sizeof(ProcFile) + f_size;
    }

private:
    static ProcFile* ReadPath(char* buf, int buf_len, const char *path);
    static ProcFile* Read(char* buf, int buf_len, const char *fmt, ...);
};
#pragma pack(pop)

// a entry in /proc/<pid>/maps
struct MemRegion {
    uint64_t start_addr;
    uint64_t end_addr;
    uint64_t offset;
    uint32_t dev_major;
    uint32_t dev_minor;
    uint64_t inode;

    char perms:3;
    char is_private:1;  // cow
    char is_shared:1;
    
    std::string name;
};

class ProcDecoder {

public:
    ProcDecoder(){};
    ProcDecoder(ProcFile* pf) : _pf(pf) {};
    int readline(int& cur, char*out, size_t n);
    virtual int Parse() = 0;

    int setpf(ProcFile* maps) {
        _pf = maps;
        return 0;
    }

protected:
    ProcFile* _pf;
};

// proc mmap decoder
struct ProcMaps : public ProcDecoder, private std::vector<MemRegion> {

    using std::vector<MemRegion>::operator[];
    using std::vector<MemRegion>::begin;
    using std::vector<MemRegion>::end;
    using std::vector<MemRegion>::size;
    
    ProcMaps() : ProcDecoder(){}
    ProcMaps(ProcFile *pf) : ProcDecoder(pf) {}
    int Parse();
};

// cmdline decoder
struct ProcCmdline : public ProcDecoder {
    std::vector<std::string> argv;

    ProcCmdline(ProcFile* pf) : ProcDecoder(pf) {};
    int Parse();
};

/*
/proc/#pid/stat, process status,
    == ============= ===============================================================
    No Field         Content
    == ============= ===============================================================
    1  pid           process id
    2  tcomm         filename of the executable
    3  state         state (R is running, S is sleeping, D is sleeping in an
                     uninterruptible wait, Z is zombie, T is traced or stopped)
    4  ppid          process id of the parent process
    5  pgrp          pgrp of the process
    6  sid           session id
    7  tty_nr        tty the process uses
    8  tty_pgrp      pgrp of the tty
    9  flags         task flags
    10 min_flt       number of minor faults
    11 cmin_flt      number of minor faults with child's
    12 maj_flt       number of major faults
    13 cmaj_flt      number of major faults with child's
    14 utime         user mode jiffies
    15 stime         kernel mode jiffies
    16 cutime        user mode jiffies with child's
    17 cstime        kernel mode jiffies with child's
    18 priority      priority level
    19 nice          nice level
    20 num_threads   number of threads
    21 it_real_value (obsolete, always 0)
    22 start_time    time the process started after system boot
    23 vsize         virtual memory size
    24 rss           resident set memory size
    25 rsslim        current limit in bytes on the rss
    26 start_code    address above which program text can run
    27 end_code      address below which program text can run
    28 start_stack   address of the start of the main process stack
    29 esp           current value of ESP
    30 eip           current value of EIP
    31 pending       bitmap of pending signals
    32 blocked       bitmap of blocked signals
    33 sigign        bitmap of ignored signals
    34 sigcatch      bitmap of caught signals
    35 0             (place holder, used to be the wchan address,
                     use /proc/PID/wchan instead)
    36 0             (place holder)
    37 0             (place holder)
    38 exit_signal   signal to send to parent thread on exit
    39 task_cpu      which CPU the task is scheduled on
    40 rt_priority   realtime priority
    41 policy        scheduling policy (man sched_setscheduler)
    42 blkio_ticks   time spent waiting for block IO
    43 gtime         guest time of the task in jiffies
    44 cgtime        guest time of the task children in jiffies
    45 start_data    address above which program data+bss is placed
    46 end_data      address below which program data+bss is placed
    47 start_brk     address above which program heap can be expanded with brk()
    48 arg_start     address above which program command line is placed
    49 arg_end       address below which program command line is placed
    50 env_start     address above which program environment is placed
    51 env_end       address below which program environment is placed
    51 exit_code     the thread's exit_code in the form reported by the waitpid
                     system call
    == ============= ===============================================================
*/
//
struct ProcStat : public ProcDecoder {

    char state;         //  012345
    char sname;         // "RSDTZW"

    pid_t pid;          // id of the process
    pid_t ppid;         // parent pid
    pid_t pgid;         // process group id, pgid == pid, as the group leader
    pid_t sid;          // session id, sid == pid, as the session leader

    unsigned long stime;     // kernel time in MS
    unsigned long utime;     // user time in MS 
    unsigned long cstime;    // kernel time with all children
    unsigned long cutime;    // user time with all children
    
    unsigned long vsize;     // virtual memory size, in KBs 
    unsigned long rss;       // physical memory size, in KBs 

    int num_threads;    // number of threads

    ProcStat(ProcFile* pf) : ProcDecoder(pf) {};
    int Parse();
};

/* Auxilitary Vector.
 *
 * LD_SHOW_AUXV=1 ls
 */
struct ProcAuxv : public ProcDecoder {
    
    uint32_t uid;
    uint32_t gid;
    uint32_t euid;
    uint32_t egid;

    ProcAuxv(ProcFile* pf) : ProcDecoder(pf) {};
    int Parse();
};

}; // arthur

#endif // _ARTHUR_PROC_H_
