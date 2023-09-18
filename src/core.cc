/* Arthur coredump implementation.
 */

#ifndef __APPLE__
#include <sys/ptrace.h> // PTRACE_XXX
#endif

#include <sys/signal.h> // siginfo_t
#include <sys/types.h>  // size_t, second_t ...
#include <sys/wait.h>   // waitpid
#include <sys/mman.h>   // mmap
#include <sys/stat.h>   // fstat
#include <sys/utsname.h>// uname 
#include <sys/uio.h>    // pread/pwrite
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <memory.h>
#include <assert.h>
#include <fcntl.h>      // open
#include <dlfcn.h>      // dlsym
#include <dirent.h>     // readdir

#include <sstream>
#include <iterator>

#include "core.h"
//#include "proc.h"

// arthur only use a memory of BUFFER_SIZE on main stack.
#define BUFFER_SIZE 1L*1024*1024         // general buffer size to store data
#define ARTHUR_BUFFER_SIZE 2L*1024*1024  // take up 2M physical memory on stack

static_assert(BUFFER_SIZE >= 1*1024*1024, "buffer size should more than 1MB.");

#define roundup(x,n) (((x)+((n)-1))&(~((n)-1)))

extern "C" {

// the function is only for compile asm code.
#define __used__ __attribute__((used))

#ifdef __aarch64__
static __used__ void inject_fork(void) 
{
    // aarch64 doesn't have a fork syscall, needs clone flags for fork(). 
    asm(
    "inject_begin: \n"
        "mov x0, #17 \n"        // SIGCHLD
        "movk x0, #120, lsl #16 \n" // CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID
        "mov x1, #0 \n"
        "mov x2, #0 \n"
        "mov x3, #0 \n"
        "mov x4, #0 \n"
        "mov x8, #220 \n"       // SYS_clone
        "svc #0 \n"
        "cmp x0, #0 \n"
        "beq inject_child \n"
        "ret \n"
    "inject_child: \n"
        "brk #0 \n"             // generate a core by SIGTRACE
        "mov x8, #93 \n"        // exit(0)
        "mov x0, #0 \n"
        "svc #0 \n"
    "inject_end: \n"
    );
}

#else
static __used__ void inject_fork(void) 
{
    /* asm code for fork injection.
     */
    asm(
    "inject_begin: \n"
        "mov $57, %rax \n"  // SYS_fork
        "syscall \n"
        "cmpl $0, %eax \n"
        "je inject_child \n"
        "ret \n"
    "inject_child: \n"
        "int $3 \n"         // generate a core by SIGTRACE
        "mov $60, %rax \n"  // exit(0)
        "mov $0, %rdi \n"
        "syscall \n"
    "inject_end: \n"
   );
}
#endif
}; // extern 'C'

namespace arthur {

void debugstr(std::string a)
{
        //std::string a = note.str();
        //unsigned char *ptr2 = (unsigned char*)&nh;
        unsigned char *ptr = (unsigned char*)a.c_str();
        for (size_t i=0; i<a.size()+1; i++) {
            printf(" %02x", ptr[i]);
            if ((i+1) % 16 == 0) printf("\n");
        }
        printf("\n");
}

// function for get module base address 
uint64_t get_module_address(pid_t pid, const char* so_path)
{
    char line[PATH_MAX];
    char base[PATH_MAX];
    char name[PATH_MAX];
    uint64_t r_addr = 0;
    size_t cur, start;

    // this proc 
    if (pid == -1) {
        pid = getpid();
    }

    snprintf(name, sizeof(name), "/proc/%u/maps", pid);
    FILE *f = fopen(name, "r");
    while (!feof(f)) {
        // read line 
        fgets(line, PATH_MAX, f);

        // find path 
        cur = 0;
        while (line[cur] && line[cur]!='/') {
            cur++;
        }
       
        // not found 
        if (line[cur] != '/') {
            continue;
        }

        // read file name 
        start = cur;
        while (line[cur]) {
            name[cur-start] = line[cur];
            cur++;
        }
        name[cur-start-1] = 0;
        //printf("%s\n", name);

        // find
        int find_len = strlen(so_path);
        char *find = strstr(name, so_path);
        if (!find || (find[find_len]!='-' && find[find_len]!='.' )) {
            continue;
        } 

        // read base address
        cur = 0;
        while (line[cur] != '-') {
            base[cur] = line[cur];
            cur++;
        }
        base[cur] = 0;
        sscanf(base, "%lx", (long*)(&r_addr));

        break;
    }
    fclose(f);

    return r_addr;
}

// function for get function address
static uint64_t get_remote_func_address(pid_t pid,const char *so_path, const char *func_name){
    // fix: support debian
    uint64_t l_addr = (uint64_t)dlsym(NULL, func_name); 
    assert(l_addr);
    uint64_t l_mod = get_module_address(-1, so_path);
    assert(l_mod);
    uint64_t r_mod = get_module_address(pid, so_path);
    assert(r_mod);
    uint64_t r_addr = (l_addr - l_mod + r_mod);
    return r_addr;
}

#ifndef __APPLE__

/* pt_ functions, for ptrace_ calls.
 */
static inline int pt_wait(pid_t pid)
{
    int status;
    waitpid(pid, &status, WUNTRACED);
    //assert (rc == pid);
    dprint("status = %x (%d, %d)", status, WIFSTOPPED(status), WSTOPSIG(status));
    return status;
}

static inline int pt_detach(pid_t pid)
{
    int rc;

    rc = ptrace(PTRACE_DETACH, pid, NULL, (void *)SIGCONT);
    if (rc) {
        error("detach %d failed", pid);
    }
    return rc;
}

// read all general purpose registers
static inline int pt_getregs(pid_t pid, user_regs64_struct *pregs)
{
    int rc;

#ifdef __aarch64__
    struct iovec iov;
    iov.iov_base = pregs;
    iov.iov_len = sizeof(user_regs64_struct);
    rc = ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov);
#else
    rc = ptrace(PTRACE_GETREGS, pid, NULL, pregs);
#endif

    assert(rc == 0);
    return rc;
}

// read all fp registers
static inline int pt_getfpregs(pid_t pid, user_fpregs64_struct *pregs)
{
    int rc;

#ifdef __aarch64__
    struct iovec iov;
    iov.iov_base = pregs;
    iov.iov_len = sizeof(user_fpregs64_struct);
    rc = ptrace(PTRACE_GETREGSET, pid, NT_FPREGSET, &iov);
#else
    rc = ptrace(PTRACE_GETFPREGS, pid, NULL, pregs);
#endif

    assert(rc == 0);
    return rc;
}

// read all xstate registers (x64)
static inline int pt_getxstateregs(pid_t pid, x64_xstatereg *pregs)
{
    int rc;

    struct iovec iov;
    iov.iov_base = pregs;
    iov.iov_len = sizeof(x64_xstatereg);
    rc = ptrace(PTRACE_GETREGSET, pid, NT_X86_XSTATE, &iov);

    assert(rc == 0);
    return rc;
}

// write all general purpose registers
static inline int pt_setregs(pid_t pid, user_regs64_struct *pregs)
{
    int rc;

#ifdef __aarch64__
    struct iovec iov;
    iov.iov_base = pregs;
    iov.iov_len = sizeof(user_regs64_struct);
    rc = ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov);
#else
    rc = ptrace(PTRACE_SETREGS, pid, NULL, pregs);
#endif

    assert(rc == 0);
    return rc;
}

/* the pt_call put a call frame with return address of ZERO on top of the current thread,
 * and wait the SIGSEGV ocur.
 */
static inline int pt_call(pid_t pid, user_regs64_struct *oregs, uint64_t func, int argc, uint64_t argv[])
{
    int rc, status = 0;
    user_regs64_struct regs;
    assert(argc <= 6);

    // get origin regs
    rc = pt_getregs(pid, &regs);
    assert(rc == 0);

    // simulate call instruction
#ifdef __aarch64__
    regs.regs[30] = 0;
#else
    regs.rsp -= 8;
    rc = ptrace(PTRACE_POKEDATA, pid, regs.rsp, 0);
    assert(rc == 0);
#endif

    // makeup function call and arguments
    regs.set_pc(func);
    for (int i=0; i<argc; i++) {
        switch (i) {
            case 0:
                regs.set_arg0(argv[0]);
                break;
            case 1:
                regs.set_arg1(argv[1]);
                break; 
            case 2:
                regs.set_arg2(argv[2]);
                break; 
            case 3:
                regs.set_arg3(argv[3]);
                break; 
            case 4:
                regs.set_arg4(argv[4]);
                break; 
            case 5:
                regs.set_arg5(argv[5]);
                break;
            default:
               assert(0); 
        }
    }
 
    rc = pt_setregs(pid, &regs);
    assert(rc == 0);

    // wait for a SIGSEGV
    for (;;) {
        if (WIFSTOPPED(status)) {
            if (WSTOPSIG(status) == SIGSEGV) {
                break;
            }
            if ((status >> 8) == (SIGTRAP | (PTRACE_EVENT_FORK << 8))) {
                unsigned long msg;
                rc = ptrace(PTRACE_GETEVENTMSG, pid, 0, &msg);
                assert(rc == 0);
                dprint("child pid = %lu", msg);
            } 
            dprint("statux = %x", status);
        }
        rc = ptrace(PTRACE_CONT, pid, NULL, NULL);
        assert(rc >= 0);

        status = pt_wait(pid);
    }
    
    if (oregs) {
        pt_getregs(pid, oregs);
    }

    return rc;
}

static inline int pt_write(pid_t pid, uint64_t dest, void *src, size_t len)
{
    int rc;
    char pbuf[128];
    snprintf(pbuf, sizeof(pbuf), "/proc/%u/mem", pid);
    int fd = open(pbuf, O_RDWR);
    assert(fd > 2);
    lseek(fd, (uint64_t)dest, SEEK_SET);
    rc = write(fd, (void *)inject_fork, len);

#if 0
    char buf[64];
    lseek(fd, (uint64_t)dest, SEEK_SET);
    rc = read(fd, buf, len); 

    int i;
    for (i=0; i< inject_size; i++) {
        printf("%02x ", (unsigned char)buf[i]);
    }
    printf("\n");
#endif
    
    close(fd);
    return rc;
}

static inline int pt_attach(pid_t pid)
{
    int rc;

    rc = ptrace(PTRACE_ATTACH, pid, NULL, NULL);
    assert(rc == 0);
    pt_wait(pid);

    return rc;
}

static inline int pt_int(pid_t pid)
{
    int rc;
    rc = ptrace(PTRACE_INTERRUPT, pid, NULL, NULL);
    assert(rc == 0);
    pt_wait(pid);

    return rc;
}

static inline int pt_cont(pid_t pid) {
    int rc;
    rc = ptrace(PTRACE_CONT, pid, NULL, NULL);
    assert(rc == 0);

    return rc;
}

static inline int pt_monitor(pid_t pid) {
    int rc;
    rc = ptrace(PTRACE_SEIZE, pid, NULL, NULL);
    assert(rc == 0);
    pt_int(pid);
    rc = ptrace(PTRACE_SETOPTIONS, pid, NULL, PTRACE_O_TRACEEXIT);
    assert(rc == 0);
    // restart main thread
    rc = pt_cont(pid);
    return rc;
}
#endif

int makeroom(FILE* fout, size_t n)
{
    char zero[PAGE_SIZE] = {0};

    size_t m = 0;
    while (m < n) {
        size_t len = MIN(PAGE_SIZE, n-m);
        ssize_t rc = fwrite(zero, 1, len, fout);
        if (rc <= 0) {
            break;
        }
        m += rc;
    }

    return 0; 
}

int ProcessData::ParseAll()
{
    _d_maps = new ProcMaps(_maps);
    assert(_d_maps);
    _d_maps->Parse();

    _d_cmdline = new ProcCmdline(_cmdline);
    assert(_d_cmdline);
    _d_cmdline->Parse();

#if 0
    _d_stat = new ProcStat(_stat);
    assert(_d_stat);
    _d_stat->Parse();
    printf("pid = %d\n", _d_stat->pid);
    printf("ppid = %d\n", _d_stat->ppid);
    printf("pgid = %d\n", _d_stat->pgid);
    printf("sid = %d\n", _d_stat->sid);
#endif

    _d_auxv = new ProcAuxv(_auxv);
    assert(_d_auxv);
    _d_auxv->Parse();
    dprint("uid(%d), euid(%d), gid(%d), egid(%d)", 
            _d_auxv->uid, _d_auxv->euid, _d_auxv->gid, _d_auxv->egid);
    
    for (auto& t: _threads) {
        t._d_stat = new ProcStat(t._stat);
        assert(t._d_stat);
        t._d_stat->Parse();
    }

    return 0;
}

/* allocate a piece of NOTE memory, return the start of payload.
 */
char* Note::allocate(size_t payload_size)
{
    const char *name = "CORE";
    int name_size = 5;
    if (_type == NT_X86_XSTATE) {
        name = "LINUX"; 
        name_size = 6;
    }
 
    size_t size = roundup((sizeof(Elf64_Nhdr) + 8 + payload_size), 4);
    char *note = (char*)malloc(size);
    assert(note);
    memset(note, 0, size);
    
    Elf64_Nhdr *nhdr = (Elf64_Nhdr*)note;
    nhdr->n_namesz = name_size;
    nhdr->n_descsz = payload_size;
    nhdr->n_type = _type;
    
    strncpy(note+sizeof(Elf64_Nhdr), name, 8);

    _data = note;
    _size = size;

    return note + sizeof(Elf64_Nhdr) + 8; 
}

template <class T>
T* Note::allocate()
{
    return (T*)allocate(sizeof(T));
}

// NT_PRPSINFO
int Note::fill_prpsinfo(const ProcessData& proc)
{
    elf_prpsinfo64 *p = allocate<elf_prpsinfo64>();

    p->pr_state = proc._threads[0]._d_stat->state;
    p->pr_sname = proc._threads[0]._d_stat->sname;
    p->pr_uid = proc._d_auxv->uid;
    p->pr_gid = proc._d_auxv->gid;
    p->pr_pid = proc._threads[0]._d_stat->pid;
    p->pr_ppid = proc._threads[0]._d_stat->ppid;
    p->pr_pgrp = proc._threads[0]._d_stat->pgid;
    p->pr_sid = proc._threads[0]._d_stat->sid;
    strncpy(p->pr_fname, proc._d_cmdline->argv[0].c_str(), sizeof(p->pr_fname));

    const char* delim = " ";
    std::ostringstream args;
    std::copy(proc._d_cmdline->argv.begin(), proc._d_cmdline->argv.end(),
           std::ostream_iterator<std::string>(args, delim));
    strncpy(p->pr_psargs, args.str().c_str(), sizeof(p->pr_psargs));

    return 0; 
}

// NT_AUXV
int Note::fill_auxv(const ProcessData& proc)
{
    char *info = allocate(proc._auxv->f_size);
    memcpy(info, proc._auxv->f_data, proc._auxv->f_size);
    return 0; 
}

// NT_FILE
int Note::fill_file(const ProcessData& proc)
{
    Block block;
    struct file_entry {
        uint64_t start_addr;
        uint64_t end_addr;
        uint64_t offset;
        std::string filename;
    };
    std::vector<file_entry> entries;

    uint64_t v;
    block.Clear();
    for (auto &r : *proc._d_maps) {
        if (r.name.size() > 0 && r.inode > 0) {
            file_entry n;
            n.start_addr = r.start_addr;
            n.end_addr = r.end_addr;
            n.offset = r.offset;
            n.filename = r.name;
            entries.push_back(n);
        }
    }

    // number of entries
    v = entries.size();
    block.Write((const char*)&v, 8);
    
    // page size (4k)
    v = 0x1000;
    block.Write((const char*)&v, 8);

    // address 
    for (auto& n :entries) {
        block.Write((const char*)&n.start_addr, 8);
        block.Write((const char*)&n.end_addr, 8);
        block.Write((const char*)&n.offset, 8);
    }
   
    // file names
    for (auto& n :entries) {
        block.Write(n.filename.c_str(), n.filename.size() + 1);
    }
    
    // align to 4 bytes 
    int size = roundup(block.Size(), 4);
    char *p = allocate(size);
    memcpy(p, block.rBuf(), block.Size());
    
    return 0;
}

// NT_PRSTATUS
int Note::fill_prstatus(const ThreadData& thr)
{
    if (thr._arch == ARCH_X64) {
        x64_elf_prstatus *p = allocate<x64_elf_prstatus>();
        p->pr_info.si_code = thr._siginfo.si_code;
        p->pr_info.si_errno = thr._siginfo.si_errno;
        p->pr_info.si_signo = thr._siginfo.si_signo;
        p->pr_cursig = thr._siginfo.si_signo;
        memcpy(&p->pr_reg, &thr._regs.x64, sizeof(thr._regs.x64));
        p->pr_pid = thr._d_stat->pid; 
        p->pr_ppid = thr._d_stat->ppid; 
        p->pr_pgrp = thr._d_stat->pgid; 
        p->pr_sid = thr._d_stat->sid;
        memcpy(&p->pr_utime, &thr._d_stat->utime, sizeof(p->pr_utime));
        memcpy(&p->pr_stime, &thr._d_stat->stime, sizeof(p->pr_stime));
        memcpy(&p->pr_cutime, &thr._d_stat->cutime, sizeof(p->pr_cutime));
        memcpy(&p->pr_cstime, &thr._d_stat->cstime, sizeof(p->pr_cstime));
    }
    else if (thr._arch == ARCH_AARCH64) {
        arm64_elf_prstatus *p = allocate<arm64_elf_prstatus>();
        p->pr_info.si_code = thr._siginfo.si_code;
        p->pr_info.si_errno = thr._siginfo.si_errno;
        p->pr_info.si_signo = thr._siginfo.si_signo;
        p->pr_cursig = thr._siginfo.si_signo;
        memcpy(&p->pr_reg, &thr._regs.arm64, sizeof(thr._regs.arm64));
        p->pr_pid = thr._d_stat->pid; 
        p->pr_ppid = thr._d_stat->ppid; 
        p->pr_pgrp = thr._d_stat->pgid; 
        p->pr_sid = thr._d_stat->sid;
        memcpy(&p->pr_utime, &thr._d_stat->utime, sizeof(p->pr_utime));
        memcpy(&p->pr_stime, &thr._d_stat->stime, sizeof(p->pr_stime));
        memcpy(&p->pr_cutime, &thr._d_stat->cutime, sizeof(p->pr_cutime));
        memcpy(&p->pr_cstime, &thr._d_stat->cstime, sizeof(p->pr_cstime));
    }
    return 0;
}

// NT_FPREGSET
int Note::fill_fpregset(const ThreadData& thr)
{
    if (thr._arch == ARCH_X64) {
        x64_elf_fpregset *p = allocate<x64_elf_fpregset>();
        memcpy(p, &thr._fpregs.x64, sizeof(thr._fpregs.x64));
    }
    else if (thr._arch == ARCH_AARCH64) {
        arm64_elf_fpregset *p = allocate<arm64_elf_fpregset>();
        memcpy(p, &thr._fpregs.arm64, sizeof(thr._fpregs.arm64));
    }
    return 0;
}

// NT_SIGINFO
int Note::fill_siginfo(const ThreadData& thr)
{
    lnx_siginfo_t *p = allocate<lnx_siginfo_t>();
    memcpy(p, &thr._siginfo, sizeof(*p));
    return 0;
}

// NT_X86_XSTATE
int Note::fill_x86_xstate(const ThreadData& thr)
{
    char *p = allocate(2688);
    memcpy(p, &thr._xstate.x64, 2688);
    return 0;
}

// NT_ARM_SVE
int Note::fill_arm_sve(const ThreadData& thr)
{
    // TBD: support arm sve registsers
    return -1; 
}

Coredump::Coredump(pid_t pid) 
    : _pid(pid)
{

}

int Coredump::WriteFileHeader(Lz4Stream& out)
{
    AcoreHeader hdr;

    out.WriteRaw((const char*)&hdr, sizeof(hdr));

    return 0;
}

int Coredump::WriteProcessMeta(Lz4Stream& out, ProcMaps& maps)
{ 
    // put ProcessData
    {
        uint32_t u32;
        out.SetBlock(BLOCK_TYPE_PROCESS); 

        // this pid 
        u32 = _pid; 
        out.Write((const char*)&u32, sizeof(u32));
        
        // forked pid if has
        u32 = _core_pid;
        out.Write((const char*)&u32, sizeof(u32));

        // thread number
        u32 = _process._thrd_pid.size();
        out.Write((const char*)&u32, sizeof(u32));

        // time 
        struct timeval tv;
        struct timezone tz;
        gettimeofday (&tv, &tz); 
        out.Write((const char*)&tv, sizeof(tv));
        out.Write((const char*)&tz, sizeof(tz));

        // uname
        char ubuf[512];
        uname((utsname*)ubuf); 
        out.Write((const char*)ubuf, sizeof(ubuf));
        
        out.Flush();
    }

    // put raw files
    char buf[BUFFER_SIZE];
    ProcFile::ReadPid(buf, BUFFER_SIZE, _pid, PROC_TYPE_CMDLINE);
    out.PutFile((ProcFile*) buf);
    ProcFile::ReadPid(buf, BUFFER_SIZE, _pid, PROC_TYPE_AUXV);
    out.PutFile((ProcFile*) buf);

    ProcFile* _maps = ProcFile::ReadPid(buf, BUFFER_SIZE, _pid, PROC_TYPE_MAPS);
    out.PutFile(_maps);
    maps.setpf(_maps);
    maps.Parse();
    
    ProcFile::ReadPid(buf, BUFFER_SIZE, _pid, PROC_TYPE_ENVIRON); 
    out.PutFile((ProcFile*) buf);
    ProcFile::ReadPid(buf, BUFFER_SIZE, _pid, PROC_TYPE_IO); 
    out.PutFile((ProcFile*) buf);
    ProcFile::ReadPid(buf, BUFFER_SIZE, _pid, PROC_TYPE_LIMITS); 
    out.PutFile((ProcFile*) buf);

    return 0;
}

#ifndef __APPLE__
int Coredump::WriteThreadMeta(Lz4Stream& out, pid_t pid, bool is_main) {
    info("thread: %d", pid); // thread info
    int rc;
    char buf[BUFFER_SIZE];
    // ptrace_attach 
    if (!is_main) {
        pt_attach(pid);
    }

    // write thread meta
    ThreadData i;
    out.SetBlock(BLOCK_TYPE_THREAD);

    out.Write((const char*)&pid, sizeof(i._pid));

    // get Grnerate Registers
    rc = pt_getregs(pid, (user_regs64_struct*)buf);
    assert(rc == 0);
    out.Write(buf, sizeof(i._regs));

    // get FP Registers 
    rc = pt_getfpregs(pid, (user_fpregs64_struct*)buf);
    assert(rc == 0);
    out.Write(buf, sizeof(i._fpregs));

    // get SIGINFO
    rc = ptrace(PTRACE_GETSIGINFO, pid, 0, buf);
    assert(rc == 0);
    out.Write(buf, sizeof(i._siginfo));

    if (_arch == ARCH_X64) {
        // get NT_X86_XSTATE     
        rc = pt_getxstateregs(pid, (x64_xstatereg*)&i._xstate);
        assert(rc == 0);
        out.Write(buf, sizeof(i._xstate.x64));
    }

    out.Flush();
    // read /proc/<pid>/stat
    ProcFile::ReadPid(buf, BUFFER_SIZE, pid, PROC_TYPE_STAT);
    out.PutFile((ProcFile*) buf);

    return 0;
}

#endif

int Coredump::VerifyFileHeader(Lz4Stream& in)
{
    int rc;
    AcoreHeader hdr, good;
    rc = in.ReadRaw(hdr.magic, sizeof(hdr.magic));
    if (rc != sizeof(hdr.magic) || memcmp(hdr.magic, good.magic, sizeof(hdr.magic))) {
        error("magic failed.");
        return -1;
    }

    rc = in.ReadRaw((char*)&hdr.m, sizeof(hdr.m));
    if (rc != sizeof(hdr.m) || hdr.m.version > ACORE_VERSION) {
        error("acore version %d > %d.", hdr.m.version, ACORE_VERSION);
        return -1;
    }

    // for version 1, the arch is always x64.
    _arch = hdr.m.arch;

    return 0;
}

int Coredump::ReadMeta(Lz4Stream& in)
{
    Block *buf;
    BlockHeader hdr; 

    buf = in.ReadBlock(hdr);
    if (!buf) {
        return -1;
    }

    // process data
    int u = 0;
    int thread_num = 0;
    {
        buf->Read((char*)&u, sizeof(u));
        _pid = u;
        buf->Read((char*)&u, sizeof(u));
        _core_pid = u;
        buf->Read((char*)&u, sizeof(u));
        thread_num = u; 
    }
    info("pid = %d", _pid);
    info("thread_num = %d", thread_num);

    _process._cmdline = in.GetFile();
    _process._auxv = in.GetFile();
    _process._maps = in.GetFile();
    _process._environ = in.GetFile();
    _process._io = in.GetFile();
    _process._limits = in.GetFile();
   
    for (int i=0; i<thread_num; i++) {
        ThreadData td;
        td._arch = _arch; 
        
        buf = in.ReadBlock(hdr);
        
        buf->Read((char*)&td._pid, sizeof(td._pid));

        if (_arch == ARCH_X64) {
            buf->Read((char*)&td._regs, sizeof(td._regs.x64));
            buf->Read((char*)&td._fpregs, sizeof(td._fpregs.x64));
            buf->Read((char*)&td._siginfo, sizeof(td._siginfo));
            buf->Read((char*)&td._xstate, sizeof(td._xstate.x64));
        } else if (_arch == ARCH_AARCH64) {
            buf->Read((char*)&td._regs, sizeof(td._regs.arm64));
            buf->Read((char*)&td._fpregs, sizeof(td._fpregs.arm64));
            buf->Read((char*)&td._siginfo, sizeof(td._siginfo));
        }

        td._stat = in.GetFile();
        _process._threads.push_back(td);
        info("thread: %d", td._pid);
    }

    return 0;
}

int Coredump::WriteLoads(Lz4Stream& out, pid_t pid, ProcMaps& maps)
{
    int fd;
    {
        char fmem[128];
        snprintf(fmem, 128, "/proc/%u/mem", pid);
        fd = open(fmem, O_RDONLY);
        if (fd < 0) {
            return -1;
        }
    }

    out.SetBlock(BLOCK_TYPE_LOADS);

    // slot for loads size
    size_t file_size = 0, mem_size = 0;

#if 0
    long loads_slot = out.Tell();
    out.WriteRaw((const char *)&file_size, sizeof(file_size));
#endif

    // mem regions 
    char buf[BUFFER_SIZE];
    for (auto &r : maps) {

        // program header entry
        Elf64_Phdr ph = {};
        ph.p_type = PT_LOAD;
        ph.p_align = 1;
        ph.p_flags = r.perms; 
        ph.p_vaddr = r.start_addr;
        ph.p_memsz = (r.end_addr - r.start_addr);
        ph.p_filesz = 0;    // update after pread
        ph.p_offset = file_size;

        // TBD: if user request all memory. 
        uint64_t end_addr = r.end_addr;
        if (!(r.perms & PF_R)) { // not readable
            // do nothing
            continue;
        } else if (r.inode > 0 && (r.perms & PF_X) && (ph.p_memsz > 0x1000)) {
            // dump only the first page.
            end_addr = r.start_addr + 0x1000;
        }
    
        // write memory dump
        size_t size = 0;
        for (uint64_t addr = r.start_addr; addr < end_addr; addr += sizeof(buf)) {
            int req = MIN((end_addr - addr), sizeof(buf));
            ssize_t len = pread(fd, buf, req, addr);
            if (len < 0) {
                warn("pread mem(%lx) failed(%d).", addr, errno);
                break;
            }
            mem_size += len;

            for (ssize_t i=0; i<len; i+= BLOCK_SIZE) {
                size_t j = MIN(len - i, BLOCK_SIZE);
                size += out.WriteBlock((const char*)(buf+i), j, BLOCK_TYPE_LOADS);
            }

            // update file size
            dprint("read %lu bytes", len);

        } // for addr 
 
        // update file size in phdr
        ph.p_filesz = size;
        //printf("%lx : %ld %ld\n", ph.p_vaddr, ph.p_memsz, ph.p_filesz);
        _phdrs.emplace_back(ph);

        // update memory size
        file_size += size;

    } // for maps

#if 0
    pos_t saved_tail = out.tellp();
    out.seekp(loads_slot);
    out.write_raw((const char*)&file_size, sizeof(file_size));
    out.seekp(saved_tail);
    printf("compressed %lu into %lu Bytes, ratio %0.2f%\n", mem_size, file_size, ((double)file_size / mem_size * 100));
#endif

    close(fd);
    return 0; 
}

/* write elf header to stream
 */
int Coredump::WriteElfHeader(Lz4Stream& out)
{
    Elf64_Ehdr ehdr;
    ehdr.e_phnum = _phdrs.size();

    // hard coded the 'machine' by platform
#ifdef __aarch64__
    ehdr.e_machine = EM_AARCH64; 
#else
    ehdr.e_machine = EM_X86_64; 
#endif

    out.SetBlock(BLOCK_TYPE_ELF);
    out.Write((const char*)&ehdr, sizeof(ehdr));
   
    for (auto& phdr : _phdrs) {
        out.Write((const char*)&phdr, sizeof(phdr));
    }

    out.Flush(); 
    return 0;
}

int Coredump::WriteElfHeader(FILE* fout)
{
    int rc = 0;
    ssize_t len;
    Elf64_Ehdr ehdr;
   
    ehdr.e_machine = _ehdr.e_machine;
    ehdr.e_phnum = _phdrs.size();

    len = fwrite(&ehdr, 1, sizeof(ehdr), fout);
    assert(len == sizeof(ehdr));
    rc += len;

    for (auto& _phdr : _phdrs) {
        Elf64_Phdr phdr = _phdr;
        if (phdr.p_type == PT_LOAD) {
            phdr.p_offset += _offset_load;
        }
        len = fwrite(&phdr, 1, sizeof(phdr), fout);
        assert(len == sizeof(phdr));
        rc += len;
    }

    return rc; 
}

int Coredump::WriteTailMark(Lz4Stream& out)
{
    BlockHeader mark = BlockHeader::TailMark();
    out.WriteRaw((const char*)&mark, sizeof(mark));
    return 0;
}

int Coredump::ReadElfHeader(Lz4Stream& in)
{
    int rc;
    BlockHeader hdr;
    Block* block = in.ReadBlock(hdr);

    rc = block->Read((char*)&_ehdr, sizeof(_ehdr));
    if (rc != sizeof(_ehdr)) {
        error("decode ehdr failed.");
        return -1;
    } 
    
    while (block) {
        
        while (block->Size() > 0) {
            Elf64_Phdr phdr;
            rc = block->Read((char*)&phdr, sizeof(phdr));
            assert(rc == sizeof(phdr));
            _phdrs.push_back(phdr);
        }
        
        rc = in.Peek((char*)&hdr, sizeof(hdr));
        assert(rc == sizeof(hdr));
        if (hdr.block_type != BLOCK_TYPE_ELF) {
            break;
        }
        block = in.ReadBlock(hdr);
    }

    dprint("phdr : %d, %d", _ehdr.e_phnum, _phdrs.size());
    return 0;
}

int Coredump::ReadLoads(Lz4Stream& in, FILE* fout)
{
    int rc;
    //size_t file_size = 0;
    size_t loads_size = 0;

#if 0
    Block buf;
    char *pbuf = (char *)buf.rdbuf();
    in.ReadRaw((char *)&loads_size, sizeof(loads_size));
    printf("loads size %lu\n", loads_size);
#endif

    BlockHeader hdr;
    for (;;) {
        rc = in.Peek((char*)&hdr, sizeof(hdr));
        if (rc <= 0) {
            break;
        }

        if (hdr.block_type != BLOCK_TYPE_LOADS) {
            break;
        }

        Block *block = in.ReadBlock(hdr);
        assert(block);

        size_t len = fwrite(block->rBuf(), 1, block->Size(), fout);
        assert(len == block->Size());

        //file_size += hdr.size;
        loads_size += block->Size();
    }

    //dprint("Readloads: file(%lu), data(%lu)", file_size, loads_size);
    return loads_size;
}

int Coredump::GenerateNotes()
{
    int rc = 0;

    // NT_PRPSINFO (prpsinfo structure)
    Note *nt = new Note(NT_PRPSINFO);
    nt->fill_prpsinfo(_process);
    _notes.push_back(nt); 

    // NT_AUXV (auxiliary vector)
    nt = new Note(NT_AUXV);
    nt->fill_auxv(_process);
    _notes.push_back(nt);

    // NT_FILE (mapped files)
    nt = new Note(NT_FILE);
    nt->fill_file(_process);
    _notes.push_back(nt);

    for (auto& i : _process._threads) {
        // NT_PRSTATUS (prstatus structure)
        nt = new Note(NT_PRSTATUS);
        nt->fill_prstatus(i);
        _notes.push_back(nt);

        // NT_FPREGSET (floating point registers)
        nt = new Note(NT_FPREGSET);
        nt->fill_fpregset(i);
        _notes.push_back(nt);

        if (_arch == ARCH_X64) {        
            // NT_X86_XSTATE (x86 XSAVE extended state)
            nt = new Note(NT_X86_XSTATE);
            nt->fill_x86_xstate(i);
            _notes.push_back(nt);
        }

        // NT_SIGINFO (siginfo_t data)
        nt = new Note(NT_SIGINFO);
        nt->fill_siginfo(i);
        _notes.push_back(nt);
    }

    for (Note *nt : _notes) {
        dprint(" [%x] %d 0x%x", nt->_type, nt->_size, nt->_size);
        rc += nt->_size;
    }

    return rc;
}

int Coredump::takememspace()
{   
    char buf[ARTHUR_BUFFER_SIZE];
    int pg_size = getpagesize();
    int off = 0;
    while (off < ARTHUR_BUFFER_SIZE) {
        buf[off] = 0;
        off += pg_size;
    }
    assert(buf[0] == 0);
    return 0;
}

#ifndef __APPLE__

/* generate() is similar to gcore does.
 * 1) stop all threads.
 * 2) generate corefile.
 */
int Coredump::generate(const char *corefile)
{
    int rc = 0;
    Lz4Stream out(Lz4Stream::LZ4_Compress);
    rc = out.Open(corefile);
    if (rc < 0) {
        return -1;
    }

    // write acore
    WriteFileHeader(out);

    // attach main thread
    pt_attach(_pid);
    // get all threads pid
    char pbuf[64];
    snprintf(pbuf, sizeof(pbuf), "/proc/%u/task/", _pid);
    DIR *dirp = opendir(pbuf);
    struct dirent *dp = NULL;
    do {
        dp = readdir(dirp);
        if (dp && dp->d_name[0]!='.') {
            int tid = atoi(dp->d_name);
            if (tid == 0)
                continue;
            _process._thrd_pid.push_back(tid);
        }
    } while (dp);
    closedir(dirp);

    ProcMaps maps;
    WriteProcessMeta(out, maps);
    // handle  leader first and then rest
    WriteThreadMeta(out, _pid, true);
    for(pid_t& tid : _process._thrd_pid) {
        if (tid == _pid)
            continue;

        WriteThreadMeta(out, tid);
    }
    // write acore
    {
        WriteLoads(out, _pid, maps); // write maps content
        WriteElfHeader(out);
        WriteTailMark(out);
    }
    // detach all threads
    for (pid_t& tid : _process._thrd_pid) {
        pt_detach(tid);
    }
    
    out.PrintStat();
    out.Close();
    return 0;
}

int Coredump::forkcore(const char *corefile, bool sys_core)
{
    /* forkcore using a forked process for large memory dump, 
     * and all thread Registers Set is collected by this function.
     * 
     * after the function, there two parts of whole corefile.
     * 1) a corefile.<pid> from forked process, this has the contents of all COW memory files.
     * 2) a metadata.<pid> for orignal process info includes all Registers for all threads.
     *
     * the two parts should be merged by arthur merge command to generate the final corefile.
     */

    int rc;
    Lz4Stream out(Lz4Stream::LZ4_Compress);
    rc = out.Open(corefile);
    if (rc < 0) {
        return -1;
    }

    if (!sys_core) {
        WriteFileHeader(out);
    }
    
    TS ts_pause;
    ts_pause.begin();

    // attach main thread
    pt_attach(_pid);

    // get all threads pid
    char pbuf[64];
    snprintf(pbuf, sizeof(pbuf), "/proc/%u/task/", _pid);
    DIR *dirp = opendir(pbuf);
    struct dirent *dp = NULL;
    do {
        dp = readdir(dirp);
        if (dp && dp->d_name[0]!='.') {
            int tid = atoi(dp->d_name);
            if (tid == 0)
                continue;
            _process._thrd_pid.push_back(tid);
        }
    } while (dp);
    closedir(dirp);

    ProcMaps maps;
    WriteProcessMeta(out, maps); 
    // handle  leader first and then rest
    WriteThreadMeta(out, _pid, true);
    for(pid_t& tid : _process._thrd_pid) {
        if (tid == _pid) {
            continue;
        }
        WriteThreadMeta(out, tid);
    }
 
    // we've injected an 'int 3' in child process, that generates a corefile by kernel. 
    if (!sys_core) {
        rc = ptrace(PTRACE_SETOPTIONS, _pid, 0, PTRACE_O_TRACEFORK);
        assert(rc == 0);
    }

    // get functions address 
    const char *so_path = "libc";
    uint64_t r_mmap = get_remote_func_address(_pid, so_path, "mmap");
    uint64_t r_munmap = get_remote_func_address(_pid, so_path, "munmap");
    //uint64_t r_fork = get_remote_func_address(_pid, so_path, "fork");
    uint64_t r_waitpid = get_remote_func_address(_pid, so_path, "waitpid");
    info("remote mmap at %lx", r_mmap);
    //info("remote fork at %p", r_fork);
    info("remote waitpid at %lx", r_waitpid);

    // save the program regs
    user_regs64_struct saved_regs;
    pt_getregs(_pid, &saved_regs);

    // get a page for shellcode
    user_regs64_struct regs;

    uint64_t inject_page = 0;
    {
        //uint64_t gv[6] = {0, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_ANONYMOUS|MAP_PRIVATE, 0, 0};
        uint64_t gv[6] = {0, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_ANONYMOUS|MAP_PRIVATE, 0, 0};
        pt_call(_pid, &regs, r_mmap, 6, gv);
        info("mmap = %lx", regs.get_rc());
        inject_page = regs.get_rc();
    }
    pt_getregs(_pid, &regs);

    // inject fork
    {
        char *inject_begin=0, *inject_end=0; 
#ifdef __aarch64__
        asm ("adr %0, inject_begin\n" : "=r" (inject_begin));
        asm ("adr %0, inject_end\n" : "=r" (inject_end));
#else
        asm ("mov $inject_begin, %0 \n" : "=r" (inject_begin));
        asm ("mov $inject_end, %0 \n" : "=r" (inject_end));
#endif
        int inject_size = (inject_end - inject_begin);
        dprint("inject_range(%p - %p), size(%d)", inject_begin, inject_end, inject_size);
     
        pt_write(_pid, inject_page, (void *)inject_fork, inject_size);
        pt_call(_pid, &regs, inject_page, 0, NULL);
        info("child_pid = %d", (int)regs.get_rc());
        _core_pid = regs.get_rc();
    }

    // munmap injected page.
    {
        uint64_t gv[2] = {inject_page, 0x1000};
        pt_call(_pid, &regs, r_munmap, 2, gv);
        info("munmap = %d", (int)regs.get_rc());
    }

    // restore program 
    pt_setregs(_pid, &saved_regs);

    // detach all threads
    for(pid_t& tid : _process._thrd_pid) {
        pt_detach(tid);
    }
    ts_pause.end();

    if (!sys_core) {
        // write acore
        WriteLoads(out, _core_pid, maps);
        WriteElfHeader(out);
        WriteTailMark(out);
    }

    // kill the forked process
    ptrace(PTRACE_DETACH, _core_pid, NULL, SIGKILL);
    //assert(rc == 0);

    // now the process becomes zombie,
    // we have to waitpid the forked pid.
    pt_attach(_pid);
    pt_getregs(_pid, &saved_regs);
    {
        uint64_t gv[3] = { (uint64_t)_core_pid, (uint64_t)NULL, 0 };
        pt_call(_pid, &regs, r_waitpid, 3, gv);
        info("waitpid = %d", (int)regs.get_rc());
    }
    pt_setregs(_pid, &saved_regs);
    pt_detach(_pid);

    info("Process %u paused %0.3f ms.", _pid, ts_pause.timediff()*1000);
    out.PrintStat();
    out.Close();
    return 0;
}

/* forkcore_m() generate corefile in the same way as forkcore()
 * except: 
 *    1. using PTRACE_INTERRUPT to stop tracee
 *    2. resume tracee instead of detach from tracee
 */ 
int Coredump::forkcore_m(const char *corefile, bool sys_core)
{
    /* forkcore using a forked process for large memory dump, 
     * and all thread Registers Set is collected by this function.
     * 
     * after the function, there two parts of whole corefile.
     * 1) a corefile.<pid> from forked process, this has the contents of all COW memory files.
     * 2) a metadata.<pid> for orignal process info includes all Registers for all threads.
     *
     * the two parts should be merged by arthur merge command to generate the final corefile.
     */

    int rc;
    Lz4Stream out(Lz4Stream::LZ4_Compress);
    rc = out.Open(corefile);
    if (rc < 0) {
        return -1;
    }

    if (!sys_core) {
        WriteFileHeader(out);
    }
    
    TS ts_pause;
    ts_pause.begin();

    // stop tracee
    pt_int(_pid);

    // get all threads pid
    char pbuf[64];
    snprintf(pbuf, sizeof(pbuf), "/proc/%u/task/", _pid);
    DIR *dirp = opendir(pbuf);
    struct dirent *dp = NULL;
    do {
        dp = readdir(dirp);
        if (dp && dp->d_name[0]!='.') {
            int tid = atoi(dp->d_name);
            if (tid == 0)
                continue;
            _process._thrd_pid.push_back(tid);
        }
    } while (dp);
    closedir(dirp);

    ProcMaps maps;
    WriteProcessMeta(out, maps); 
    // handle  leader first and then rest
    WriteThreadMeta(out, _pid, true);
    for(pid_t& tid : _process._thrd_pid) {
        if (tid == _pid) {
            continue;
        }
        WriteThreadMeta(out, tid);
    }
 
    // we've injected an 'int 3' in child process, that generates a corefile by kernel. 
    if (!sys_core) {
        rc = ptrace(PTRACE_SETOPTIONS, _pid, 0, PTRACE_O_TRACEFORK);
        assert(rc == 0);
    }

    // get functions address 
    const char *so_path = "libc";
    uint64_t r_mmap = get_remote_func_address(_pid, so_path, "mmap");
    uint64_t r_munmap = get_remote_func_address(_pid, so_path, "munmap");
    //uint64_t r_fork = get_remote_func_address(_pid, so_path, "fork");
    uint64_t r_waitpid = get_remote_func_address(_pid, so_path, "waitpid");
    info("remote mmap at %lx", r_mmap);
    info("remote waitpid at %lx", r_waitpid);

    // save the program regs
    user_regs64_struct saved_regs;
    pt_getregs(_pid, &saved_regs);

    // get a page for shellcode
    user_regs64_struct regs;
    uint64_t inject_page = 0;
    {
        uint64_t gv[6] = {0, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_ANONYMOUS|MAP_PRIVATE, 0, 0};
        pt_call(_pid, &regs, r_mmap, 6, gv);
        info("mmap = %lx", regs.get_rc());
        inject_page = regs.get_rc();
    }
    pt_getregs(_pid, &regs);

    // inject fork
    {
        char *inject_begin=0, *inject_end=0; 
#ifdef __aarch64__
        asm ("adr %0, inject_begin\n" : "=r" (inject_begin));
        asm ("adr %0, inject_end\n" : "=r" (inject_end));
#else
        asm ("mov $inject_begin, %0 \n" : "=r" (inject_begin));
        asm ("mov $inject_end, %0 \n" : "=r" (inject_end));
#endif        
        int inject_size = (inject_end - inject_begin);
        dprint("inject_range(%p - %p), size(%d)", inject_begin, inject_end, inject_size);
     
        pt_write(_pid, inject_page, (void *)inject_fork, inject_size);
        pt_call(_pid, &regs, inject_page, 0, NULL);
        info("child_pid = %d", (int)regs.get_rc());
        _core_pid = regs.get_rc();
    }

    // munmap injected page.
    {
        uint64_t gv[2] = {inject_page, 0x1000};
        pt_call(_pid, &regs, r_munmap, 2, gv);
        info("munmap = %d", (int)regs.get_rc());
    }

    // restore program regs
    pt_setregs(_pid, &saved_regs);

    // detach all threads
    for(pid_t& tid : _process._thrd_pid) {
        if(tid == _pid)
            continue;
        
        // in pt_detach use SIGCONT, wont work here which will have tracee not resumed
        // send NULL signal instead
        ptrace(PTRACE_DETACH, tid, NULL, NULL); 
    }
    ts_pause.end();

    /**
     * Tracee will resume executing while writing out corefile with data from forked process;
     * if any exception happens in between this section, tracee will be stopped; 
     * the signal is supposed to be pending before finishing writing corefile
     */
    pt_cont(_pid);
    _process._thrd_pid.clear(); // clear all thread id in array

    // TBD: dump memory regions
    if (!sys_core) {
        // write acore
        {
            WriteLoads(out, _core_pid, maps);
            WriteElfHeader(out);
            WriteTailMark(out);
        }
    }

    // kill the forked process
    ptrace(PTRACE_DETACH, _core_pid, NULL, SIGKILL);
    // assert(rc == 0);

    // in case any signal generated above
    int s, sig = 0;
    waitpid(_pid, &s, WNOHANG);
    // tracee will be killed if signaled on termination (SIGKILL)
    // arthur will exit here
    if(WIFSIGNALED(s)) {
        info("%s: process %d terminated", strsignal(WTERMSIG(s)), _pid);
        exit(0);
    }
    // tracee will stop if signaled on exit
    if(WIFSTOPPED(s)) {
        sig = WSTOPSIG(s);
    } else {
        // now the process becomes zombie,
        // we have to waitpid the forked pid.
        pt_int(_pid);
    }
    pt_getregs(_pid, &saved_regs);
    {
        uint64_t gv[3] = {(uint64_t)_core_pid, (uint64_t)NULL, 0};
        pt_call(_pid, &regs, r_waitpid, 3, gv);
        info("waitpid = %d", (int)regs.get_rc());
    }
    pt_setregs(_pid, &saved_regs);
    if(!WIFSTOPPED(s)) {
        pt_cont(_pid);
    }

    info("Process %u paused %0.3f ms.", _pid, ts_pause.timediff()*1000);
    out.PrintStat();
    out.Close();

    // clean pending signal generated above by tracee
    sigset_t mask;
    //siginfo_t sig_info;
    sigaddset(&mask, SIGCHLD);
    sigwaitinfo(&mask, NULL);

    return sig;
}

/* monitor() will attacg the target process
 * write out corefile on target exit on signal
 * SIGSEGV, SIGABRT, SIGILL; able to produce corefile
 * on SIGUSR1
 */
int Coredump::monitor(const char* corefile) 
{   
    int rc;
    Lz4Stream out(Lz4Stream::LZ4_Compress);
    rc = out.Open(corefile);
    if (rc < 0) {
        return -1;
    }

    // write acore
    WriteFileHeader(out);

    pt_monitor(_pid);    
    info("Launched in monitor mode");

    // block all signals
    sigset_t mask;
    sigaddset(&mask, SIGCHLD); // signal from tracee
    sigaddset(&mask, SIGUSR1); // signal for generating corefile while monitor
    sigprocmask(SIG_BLOCK, &mask, NULL);

    int exit_sig = 0;
    int signal_forkcore = 0; // signal generated due to free section in forkcore
    lnx_siginfo_t sig_info;
    while(1) {
        if(signal_forkcore) {
            info("signal forkcore %d", signal_forkcore);
            if (signal_forkcore == SIGILL || signal_forkcore == SIGABRT || signal_forkcore == SIGSEGV) {
                // write out corefile under SIGILL, SIGABRT, SIGSEGV
                exit_sig = signal_forkcore;
                break;
            } else { // relay signals to tracee
                ptrace(PTRACE_CONT, _pid, NULL, (uintptr_t) signal_forkcore);
                signal_forkcore = 0; // reset forkcore signal
                continue;
            }
        }

        // unblock all signals and wait atomically
        sigwaitinfo(&mask, &sig_info);
        int signo = sig_info.si_signo;
        if(signo == SIGCHLD) {
            // signal from tracee
            int status = sig_info.si_status; // status signal code
            int code = sig_info.si_code;  // tracee current state
            if (code == CLD_KILLED || code == CLD_DUMPED || code == CLD_EXITED){
                if(status == 0) { // process exits normally
                    info("process %d exit voluntarily", _pid);
                } else { // process exits on receving signal
                    info("%s: process %d exit voluntarily", strsignal(status), _pid);
                    ptrace(PTRACE_DETACH, _pid, NULL, (uintptr_t) status);
                }
                return 0;
            } else if (status == SIGILL || status == SIGABRT || status == SIGSEGV) {
                // write out corefile under SIGILL, SIGABRT, SIGSEGV
                exit_sig = status;
                break;
            } else { // relay signals to tracee
                ptrace(PTRACE_CONT, _pid, NULL, (uintptr_t) status);
            }
            signal_forkcore = 0; // reset signal 
        } else { 
            // signal SIGUSR1 to arthur
            char out[17];
            sprintf(out, "acore.%u\n", (unsigned)time(NULL));
            out[16] = '\0';
            info("writing out %s...", out);
            signal_forkcore = forkcore_m(out, false);
            info("writing out acore finished, resume monitoring");
        }
    }

    info("%s: process %d exit", strsignal(exit_sig), _pid);
    info("Writing out corefile...");

    // get all threads pid
    char pbuf[64];
    snprintf(pbuf, sizeof(pbuf), "/proc/%u/task/", _pid);
    DIR *dirp = opendir(pbuf);
    struct dirent *dp = NULL;
    do {
        dp = readdir(dirp);
        if (dp && dp->d_name[0]!='.') {
            int tid = atoi(dp->d_name);
            if (tid == 0)
                continue;
            _process._thrd_pid.push_back(tid);
        }
    } while (dp);
    closedir(dirp);

    ProcMaps maps;
    WriteProcessMeta(out, maps);

    // handle  leader first and then rest
    WriteThreadMeta(out, _pid, true);
    for(pid_t& tid : _process._thrd_pid) {
        if (tid == _pid)
            continue;

        WriteThreadMeta(out, tid);
    }
    // write acore
    {
        WriteLoads(out, _pid, maps);
        WriteElfHeader(out);
        WriteTailMark(out);
    }

    for (pid_t& tid : _process._thrd_pid) {
        // cannot guarantee thread exit order, not to check ptrace rc
        ptrace(PTRACE_DETACH, tid, NULL, (uintptr_t) exit_sig);
    }
    out.PrintStat();
    out.Close();
    return 0;
}

#endif 

int Coredump::decompress(const char* in_file, const char* out_core)
{
    int rc = 0;
    Lz4Stream in(Lz4Stream::LZ4_Decompress);
    rc = in.Open(in_file);
    if (rc < 0) {
        return -1;
    }
    rc = VerifyFileHeader(in);
    if (rc != 0) {
        return rc;
    }

    // load meta
    rc = ReadMeta(in);
    if (rc != 0) {
        return rc;
    }
    
    char fpath[PATH_MAX];
    if (!out_core) {
        snprintf(fpath, sizeof(fpath), "core.%u", _pid);
        out_core = fpath; 
    }
    FILE *fout = fopen(out_core, "wb");
    if (!fout) {
        error("Fail to open file %s", out_core);
        return -1;
    }
    long p_elf = ftell(fout);

    // parse  
    _process.ParseAll();

    // make room for elf headers
    int phnum = _process._d_maps->size() + 1;
    size_t hdr_size = sizeof(Elf64_Ehdr) + (phnum * sizeof(Elf64_Phdr));
    hdr_size = roundup(hdr_size + 4096, 4096);
    dprint("room = %d", hdr_size);
    rc = makeroom(fout, hdr_size);
    if (rc < 0) {
        return -1;
    } 
    long p_note = ftell(fout);

    // makeup notes
    int notes_size = GenerateNotes();
    Elf64_Phdr note_phdr = {0};
    note_phdr.p_type = PT_NOTE;
    note_phdr.p_offset = p_note;
    note_phdr.p_filesz = notes_size;
    _phdrs.push_back(note_phdr);

    for (Note* nt : _notes) {
        ssize_t len;
        len = fwrite(nt->_data, 1, nt->_size, fout);
        assert(len == nt->_size);
    }
    _offset_load = ftell(fout);

    // write loads
    ReadLoads(in, fout);

    // write elf header
    ReadElfHeader(in);
    fseek(fout, p_elf, SEEK_SET); 
    WriteElfHeader(fout);

    in.Close();
    fclose(fout);
    info("saved corefile '%s'.", out_core);
    return 0;
}

#ifndef __APPLE__

int Coredump::test_compress(const char* in_file, const char* out_file)
{
    int rc = 0;
    FILE *fin = fopen(in_file, "rb"); 
    if (!fin) {
        error("Fail to open file %s", in_file);
        return -1;
    }

    Lz4Stream out(Lz4Stream::LZ4_Compress);
    rc = out.Open(out_file);
    if (rc < 0) {
        return -1;
    }

    size_t data_size = 0, file_size = 0;
    char buf[4*1024];
    for (;;) {
        size_t len = fread(buf, 1, sizeof(buf), fin);
        if (len == 0) {
            error("read failed (%ld)", len);
            break;
        } 
        
        for (size_t i=0; i<len; i+= BLOCK_SIZE) {
            size_t j = MIN(len - i, BLOCK_SIZE);
            int rc = out.Write((const char*)(buf+i), j);
            assert(rc > 0);
            data_size += len;
            file_size += rc;
        }
             
        if (len < sizeof(buf)) {
            break;
        }
    }
    out.Flush();
    WriteTailMark(out);
    out.Close();
    fclose(fin); 

    info(" %lu => %lu ", data_size, file_size);

    return 0;
}

int Coredump::test_decompress(const char* in_file, const char* out_file)
{
    int rc = 0;
    Lz4Stream in(Lz4Stream::LZ4_Decompress);
    rc = in.Open(in_file);
    if (rc < 0) {
        return -1;
    }

    FILE *fout = fopen(out_file, "wb");
    if (!fout) {
        error("Fail to open file %s", out_file);
        return -1;
    }
   
    size_t file_size = 0;
    BlockHeader hdr; 
    for (;;) {
        Block* block = in.ReadBlock(hdr);
        if (!block) {
            break;
        }

        ssize_t len = fwrite(block->rBuf(), 1, block->Size(), fout);
        if (len != (int)block->Size()) {
            break;
        }
        file_size += len; 
    }
    fclose(fout);
    in.Close();

    info("write %lu bytes.", file_size);
    return 0;
}

#endif

}; // arthur
