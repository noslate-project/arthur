/* Arthur coredump implementation.
 */

#ifndef _ARTHUR_CORE_H_
#define _ARTHUR_CORE_H_

#include <sys/ptrace.h>
#include <sys/time.h>
#include <vector>
#include <map>
#include <sstream>

#include "inc.h"
#include "elf.h"
#include "proc.h"
#include "lz4.h"

namespace arthur {

class Coredump;
struct ThreadData;

// keeps 6 bytes for magic header
#define ACORE_MAGIC {'A', 'R', 'T', 'H', 'U', 'R'}

enum ARCHTYPE {
    ARCH_X64 = 0,
    ARCH_AARCH64 = 1,
    ARCH_MAX
};
static_assert(ARCH_MAX < 16, "arch type too large.");

// acore file header
struct AcoreHeader {
    char magic[6] = ACORE_MAGIC;

    /* version history:
     * 1: first u16 version.
     * 2: support arch and introduced aarch64 arch.
     */

#define ACORE_VERSION 2
    struct {
        uint16_t version:12;
        uint16_t arch:4;        // ARCHTYPE
    } m
#ifdef __aarch64__
    = {ACORE_VERSION, ARCH_AARCH64};
#else
    = {ACORE_VERSION, ARCH_X64};
#endif
};
static_assert(sizeof(AcoreHeader) == 8, "acore header oversize");

struct MetaData {
    uint32_t pid;
    uint32_t core_pid;
    uint32_t thread_count;
};

/* holds the Process information
 */
struct ProcessData { 
    // raw /proc/<pid>/<files>
    ProcFile *_cmdline;
    ProcFile *_auxv;
    ProcFile *_maps;
    ProcFile *_environ;
    ProcFile *_io;
    ProcFile *_limits;

    // proc file decoder
    ProcCmdline *_d_cmdline;
    ProcMaps *_d_maps;
    ProcAuxv *_d_auxv;
    
    // threads group
    std::vector<ThreadData> _threads;   // threads data
    std::vector<pid_t> _thrd_pid;

public:
    ProcessData() {
        _cmdline = NULL;
        _auxv = NULL;
        _maps = NULL;
        _environ = NULL;
        _io = NULL;
        _limits = NULL;
    }
    int ParseAll();
};

/* holds the Thread information
 */
struct ThreadData {
    uint32_t _pid;
    uint32_t _attached:1;
    uint32_t _arch:4;   // ARCHTYPE
    
    // Generic Registers 
    union {
        x64_user_regs64_struct      x64;
        arm64_user_regs64_struct    arm64;
    } _regs; 

    // FP Registers
    union {
        x64_user_fpregs64_struct    x64;
        arm64_user_fpsimd64_struct  arm64;
    } _fpregs; 
  
    union {
        x64_xstatereg               x64;           
    } _xstate; 

    siginfo_t _siginfo;   // SigInfo 
    
    ProcFile *_stat;
    ProcStat *_d_stat;

public:
    ThreadData() {
        memset(this, 0, sizeof(ThreadData));
    }
};

/* holds memory entry.
 */
struct Load {
    Elf64_Phdr phdr = {0};      // generated program header
};


/* Represents a Note in Corefile.
 *
 * note layout,
 * | Note Hdr | Name | Data |
 *
 *
 *
 *
 */
class Note {

public:
    Note(int t) : _type(t), _data(NULL) {}
    ~Note() {
        if (_data) {
            free(_data);
            _data = NULL;
        }
    }
    
    // process info
    int fill_prpsinfo(const ProcessData& proc);
    int fill_auxv(const ProcessData& proc);
    int fill_file(const ProcessData& proc);
    // thread info
    int fill_prstatus(const ThreadData& proc);
    int fill_fpregset(const ThreadData& proc);
    int fill_siginfo(const ThreadData& proc);
    int fill_x86_xstate(const ThreadData& proc);
    int fill_arm_sve(const ThreadData& proc);
    
    char *allocate(size_t payload_size);
    template <class T>
    T* allocate();

private:
    Note();
    int _type;
    char* _data;
    int _size;

    friend class Coredump;
};

// represens a Arthur Corefile
class Acore {

/* Arthur corefile layout,
 * 
 *   Metadata
 *     ProcessData
 *     Proc Files,
 *       cmdline,
 *       stat,
 *       auxv,
 *       maps,
 *   for (thread in process) {
 *      regs,
 *      fpregs,
 *      siginfo,
 *      x86state,
 *      Proc Files,
 *        stat,
 *   }
 *   memory regions
 *   header
 *      elf header
 *      all program headers 
 */

private:
    pid_t _pid;
    pid_t _core_pid;

    ProcessData _process;
    std::vector<ThreadData> _threads;
    std::vector<Load> _loads;

    friend class Coredump;
};


/* represents a corefile
 */
class Corefile {

/* Corefile Layout,
 *
 *    Elf Header (64)
 *    Program Headers (56 * nof_Loads)
 *    Note
 *      NT_PRSTATUS (0x150) : elf_prstatus64
 *      NT_PRPSINFO (0x88) : elf_prpsinfo
 *      NT_SIGINFO (0x80) : siginfo
 *      NT_AUXV (0x140) : /proc/<pid>/auxv
 *      NT_FILE 
 *      NT_FPREGSET (0x200) : 
 *      NT_X86_XSTATE (0xa80)
 *      for (thread in process) {
 *         NT_PRSTATUS (0x150)
 *         NT_FPREGSET (0x200)
 *         NT_X86_XSTATE (0xa80)
 *      }
 *    all Loads
 */

private:
    FILE *_file;            // file open

    Elf64_Ehdr _ehdr;       // elf header
    Elf64_Phdr _note_phdr;  // note program header
    std::vector<Elf64_Phdr> _loads_phdrs;   // program header for all loads
    std::vector<Elf64_Nhdr*> _nhdrs;    // all notes with header
    
    friend class Coredump;
};

/* main class for acore file.
 */
class Coredump {

public:
    Coredump(pid_t pid);
    // monitor the target process and collect data on process exit
    int monitor(const char *out_core = "core");
    // generate corefile for monitor mode
    int forkcore_m(const char *out_core = "core", bool sys_core = false);

    // generate acore by traditional
    int generate(const char *out_core = "core");
    
    // shield target process, genenrate an acore if crashed.
    int shield(const char *out_core = "core");

    // generate acore by fork
    int forkcore(const char *out_core = "core", bool sys_core = false);

    // generate corefile by merge metadata and target system corefile. 
    int merge(const char* in_core, const char* in_meta, const char* out_core);

    // decompression
    int decompress(const char* in_file, const char* out_core);

    // test_compress
    int test_compress(const char* in_file, const char* out_file);
    int test_decompress(const char* in_file, const char* out_file);

    int takememspace();

private:
    // write acore 
    int WriteFileHeader(Lz4Stream& out);
    int WriteMeta(Lz4Stream& out);
    int WriteLoads(Lz4Stream& out, pid_t pid, ProcMaps& maps);
    int WriteElfHeader(Lz4Stream& out);
    int WriteNotes(Lz4Stream& out);
    int WriteTailMark(Lz4Stream& out);

    // read acore 
    int VerifyFileHeader(Lz4Stream& in);
    int ReadMeta(Lz4Stream& in);
    int ReadLoads(Lz4Stream& in, FILE* fout);
    int ReadElfHeader(Lz4Stream& in);
 
    // write core
    int GenerateNotes();
    int WriteElfHeader(FILE* fout);

    // write corefile 
    int WriteCore(const char* out_core);
    int ReadCore(const char* in_core);

    int WriteProcessMeta(Lz4Stream& out, ProcMaps& maps);
    int WriteThreadMeta(Lz4Stream& out, pid_t pid, bool is_main = false);
private:
    pid_t _pid;             // target pid
    pid_t _core_pid;        // forked core's pid
    int _arch;              // ARCHTYPE

    // TBD: move to acore or corefile class. 
    ProcessData _process;   // process data
    Elf64_Ehdr _ehdr;
    Elf64_Phdr _note_phdr;
    std::vector<Note*> _notes;
    std::vector<Load> _loads;
    std::vector<Elf64_Phdr> _phdrs;

    long _offset_load;
};

// time stamp for debug
struct TS {
    struct timeval _begin, _end;
 
#if 0
    /* only work on x86-64, test purpose.
     */
    static uint64_t rdtsc(){
        unsigned int lo,hi;
        __asm__ __volatile__ ("rdtsc": "=a"(lo), "=d"(hi));
        return ((uint64_t)hi << 32) | lo;
    }
#endif
    
    static struct timeval _utime_diff(struct timeval &a, struct timeval &b)
    {
        struct timeval ret;
        if (b.tv_usec >= a.tv_usec) {
            ret.tv_usec = b.tv_usec - a.tv_usec;
            ret.tv_sec = b.tv_sec - a.tv_sec;
        } else {
            ret.tv_usec = 1000000 + b.tv_usec - a.tv_usec;
            ret.tv_sec = b.tv_sec - a.tv_sec - 1;
        }
        return ret;
    }

    void begin()
    {
        gettimeofday(&_begin, 0);
    }   

    void end()
    {
        gettimeofday(&_end, 0);
    }

    double timediff()
    {
        struct timeval result = _utime_diff(_begin, _end); 
        double gap = result.tv_sec + result.tv_usec / 1000000.0;
        return gap;
    }
};


}; // arthur

#endif // _ARTHUR_CORE_H_
