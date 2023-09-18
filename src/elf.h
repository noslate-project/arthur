/* Elf file format,
 * From man elf(5)
 */

#ifndef _ARTHUR_ELF_H_
#define _ARTHUR_ELF_H_

//#include <unistd.h>
#include <stdint.h>
//#include <signal.h>
#include <stdio.h>
#include <string.h>
#include "elf_defs.h"

#define ALIGN_UP(addr, align) ((((uint64_t) (addr)) + ((align) - 1)) & ~((align) - 1))

typedef uint64_t Elf64_Addr;
typedef uint64_t Elf64_Off;
typedef uint16_t Elf64_Section;
typedef uint16_t Elf64_Versym;
typedef uint8_t  Elf64_Byte;
typedef uint16_t Elf64_Half;
typedef int32_t  Elf64_SWord;
typedef uint32_t Elf64_Word;
typedef int64_t  Elf64_Sxword;
typedef uint64_t Elf64_Xword;

// Elf_Byte
#define V(name, value) \
    constexpr Elf64_Byte name = value;

EI_LIST(V);
ELFMAG_LIST(V);
EI_CLASS_LIST(V);
EI_DATA_LIST(V);
EI_VERSION_LIST(V);
ELFOSABI_LIST(V);
PF_LIST(V);
#undef V

// Elf_Half
#define V(name, value) \
    constexpr Elf64_Half name = value;

ET_LIST(V);
EM_LIST(V);

#undef V

// Elf_Word
#define V(name, value) \
    constexpr Elf64_Word name = value;

PT_LIST(V);
SHT_LIST(V);
NT_CORE_LIST(V);
AT_AUXV_LIST(V);

#undef V

// Program header
struct Elf64_Phdr {
    uint32_t   p_type;
    uint32_t   p_flags;
    Elf64_Off  p_offset;
    Elf64_Addr p_vaddr;
    Elf64_Addr p_paddr;
    uint64_t   p_filesz;
    uint64_t   p_memsz;
    uint64_t   p_align;
};

// Section header
struct Elf64_Shdr {
    uint32_t   sh_name;
    uint32_t   sh_type;
    uint64_t   sh_flags;
    Elf64_Addr sh_addr;
    Elf64_Off  sh_offset;
    uint64_t   sh_size;
    uint32_t   sh_link;
    uint32_t   sh_info;
    uint64_t   sh_addralign;
    uint64_t   sh_entsize;
};

// String and symbol tables
struct Elf64_Sym {
    uint32_t      st_name;
    unsigned char st_info;
    unsigned char st_other;
    uint16_t      st_shndx;
    Elf64_Addr    st_value;
    uint64_t      st_size;
};

// Relocation entries
struct Elf64_Rel {
    Elf64_Addr r_offset;
    uint64_t   r_info;
};

struct Elf64_Rela {
    Elf64_Addr r_offset;
    uint64_t   r_info;
    int64_t    r_addend;
};

// Dynamic tags
struct Elf64_Dyn {
    Elf64_Sxword    d_tag;
    union {
        Elf64_Xword d_val;
        Elf64_Addr  d_ptr;
    } d_un;
};
extern Elf64_Dyn _DYNAMIC[];

// Notes
struct Elf64_Nhdr {
    Elf64_Word n_namesz;
    Elf64_Word n_descsz;
    Elf64_Word n_type;
};

// Elf header
struct Elf64_Ehdr {
    unsigned char e_ident[EI_NIDENT];
    uint16_t      e_type;
    uint16_t      e_machine;
    uint32_t      e_version;
    Elf64_Addr    e_entry;
    Elf64_Off     e_phoff;
    Elf64_Off     e_shoff;
    uint32_t      e_flags;
    uint16_t      e_ehsize;
    uint16_t      e_phentsize;
    uint16_t      e_phnum;
    uint16_t      e_shentsize;
    uint16_t      e_shnum;
    uint16_t      e_shstrndx;

    Elf64_Ehdr() :
        e_ident{ ELFMAG0, ELFMAG1, ELFMAG2, ELFMAG3,
                 ELFCLASS64, ELFDATA2LSB, EV_CURRENT,
                 ELFOSABI_LINUX, 0,
                 0,0,0,0,0,0,0
               },
        e_type(ET_CORE),
        e_machine(EM_X86_64),
        e_version(1),
        e_entry(0),
        e_phoff(64),
        e_shoff(0),
        e_flags(0),
        e_ehsize(sizeof(Elf64_Ehdr)),
        e_phentsize(sizeof(Elf64_Phdr)),
        e_phnum(0),
        e_shentsize(sizeof(Elf64_Shdr)),
        e_shnum(0),
        e_shstrndx(0)
    {
         
    }
};

/* Core specifications */
/* Unsigned 64-bit integer aligned to 8 bytes.  */
//typedef uint64_t __attribute__ ((__aligned__ (8))) a8_uint64_t;
typedef uint64_t elf_greg64_t;

// general purpose registers for arm64
struct arm64_user_regs64_struct
{
    uint64_t regs[31];
    uint64_t sp;
    uint64_t pc;
    uint64_t pstate;

    inline uint64_t get_pc() { return pc; }
    inline uint64_t get_sp() { return sp; }
    inline uint64_t get_rc() { return regs[0]; }
#if 0
    inline uint64_t get_arg0() { return regs[0]; }
    inline uint64_t get_arg1() { return regs[1]; }
    inline uint64_t get_arg2() { return regs[2]; }
    inline uint64_t get_arg3() { return regs[3]; }
    inline uint64_t get_arg4() { return regs[4]; }
    inline uint64_t get_arg5() { return regs[5]; }
#endif

    inline void set_pc(uint64_t v) { pc = v; }
    inline void set_sp(uint64_t v) { sp = v; }
    inline uint64_t set_arg0(uint64_t v) { return regs[0] = v; }
    inline uint64_t set_arg1(uint64_t v) { return regs[1] = v; }
    inline uint64_t set_arg2(uint64_t v) { return regs[2] = v; }
    inline uint64_t set_arg3(uint64_t v) { return regs[3] = v; }
    inline uint64_t set_arg4(uint64_t v) { return regs[4] = v; }
    inline uint64_t set_arg5(uint64_t v) { return regs[5] = v; }

    static void DebugPrint(arm64_user_regs64_struct *r) {
        for (int i=0; i<31; i++) 
            printf("x%d = %lx (%lu)\n", i, r->regs[i], r->regs[i]);
        printf("pc = %lx\n", r->pc);
        printf("sp = %lx\n", r->sp);
    }
};

// fp and simd register for arm64
struct arm64_user_fpsimd64_struct
{
  __uint128_t  vregs[32];
  unsigned int fpsr;
  unsigned int fpcr;
};

static_assert(sizeof(arm64_user_fpsimd64_struct)==528, "invalid prstatus");

typedef arm64_user_fpsimd64_struct arm64_elf_fpregset;

#if 0
#define ELF_NGREG64 (sizeof (struct user_regs64_struct) / sizeof(elf_greg64_t))
typedef elf_greg64_t elf_gregset64_t[ELF_NGREG64];
typedef elf_prpsinfo elf_prpsinfo64;
typedef elf_prstatus elf_prstatus64;
#endif


// genenal purpose registers for x64
struct x64_user_regs64_struct
{
    uint64_t r15;
    uint64_t r14;
    uint64_t r13;
    uint64_t r12;
    uint64_t rbp;
    uint64_t rbx;
    uint64_t r11;
    uint64_t r10;
    uint64_t r9;
    uint64_t r8;
    uint64_t rax;
    uint64_t rcx;
    uint64_t rdx;
    uint64_t rsi;
    uint64_t rdi;
    uint64_t orig_rax;
    uint64_t rip;
    uint64_t cs;
    uint64_t eflags;
    uint64_t rsp;
    uint64_t ss;
    uint64_t fs_base;
    uint64_t gs_base;
    uint64_t ds;
    uint64_t es;
    uint64_t fs;
    uint64_t gs;

    inline uint64_t get_pc() { return rip; }
    inline uint64_t get_sp() { return rsp; }
    inline uint64_t get_rc() { return rax; }
#if 0
    inline uint64_t get_arg0(int i) { return rdi; }
    inline uint64_t get_arg1(int i) { return rsi; }
    inline uint64_t get_arg2(int i) { return rdx; }
    inline uint64_t get_arg3(int i) { return rcx; }
    inline uint64_t get_arg4(int i) { return r8; }
    inline uint64_t get_arg5(int i) { return r9; }
#endif

    inline void set_pc(uint64_t v) { rip = v; }
    inline void set_sp(uint64_t v) { rsp = v; }
    //inline void set_rc(uint64_t v) { rax = v; }
    inline uint64_t set_arg0(uint64_t v) { return rdi = v; }
    inline uint64_t set_arg1(uint64_t v) { return rsi = v; }
    inline uint64_t set_arg2(uint64_t v) { return rdx = v; }
    inline uint64_t set_arg3(uint64_t v) { return rcx = v; }
    inline uint64_t set_arg4(uint64_t v) { return r8 = v; }
    inline uint64_t set_arg5(uint64_t v) { return r9 = v; }

    static void DebugPrint(x64_user_regs64_struct *r) {
        printf("RIP %16lx FLG %16lx\n", r->rip, r->eflags);
        printf("RSP %16lx RBP %16lx\n", r->rsp, r->rbp);
        printf("RAX %16lx RBX %16lx\n", r->rax, r->rbx);
        printf("RCX %16lx RDX %16lx\n", r->rcx, r->rdx);
        printf("RSI %16lx RDI %16lx\n", r->rsi, r->rdi);
        printf("R8  %16lx R9  %16lx\n", r->r8, r->r9);
        printf("R10 %16lx R11 %16lx\n", r->r10, r->r11);
        printf("R12 %16lx R13 %16lx\n", r->r12, r->r13);
        printf("R14 %16lx R15 %16lx\n", r->r14, r->r15);
        printf("CS %4lx SS %4lx DS %4lx ES %4lx FS %4lx GS %4lx\n", 
                r->cs, r->ss, r->ds, r->es, r->fs, r->gs);
        printf("ORAX %16lx, BASE(FS %16lx, GS %16lx)\n", 
                r->orig_rax, r->fs_base, r->gs_base);
    }
};

// fp registers for x64 
struct x64_user_fpregs64_struct
{
  unsigned short int	cwd;
  unsigned short int	swd;
  unsigned short int	ftw;
  unsigned short int	fop;
  __extension__ unsigned long long int rip;
  __extension__ unsigned long long int rdp;
  unsigned int		mxcsr;
  unsigned int		mxcr_mask;
  unsigned int		st_space[32];   /* 8*16 bytes for each FP-reg = 128 bytes */
  unsigned int		xmm_space[64];  /* 16*16 bytes for each XMM-reg = 256 bytes */
  unsigned int		padding[24];
};
static_assert(sizeof(x64_user_fpregs64_struct)==0x200, "invalid prstatus");

typedef x64_user_fpregs64_struct x64_elf_fpregset;

// gregset for x64
#define X64_NGREG64 (sizeof (struct x64_user_regs64_struct) / sizeof(elf_greg64_t))
typedef elf_greg64_t x64_gregset64_t[X64_NGREG64];

// gregset for arm64
#define ARM64_NGREG64 (sizeof (struct arm64_user_regs64_struct) / sizeof(elf_greg64_t))
typedef elf_greg64_t arm64_gregset64_t[ARM64_NGREG64];

// x64 xstate 
#define X86_XSTATE_MAX_SIZE 2696
typedef char x64_xstatereg[X86_XSTATE_MAX_SIZE];

// signal info struct used in prstatus
struct elf_siginfo64
{
    int si_signo;			/* Signal number.  */
    int si_code;			/* Extra code.  */
    int si_errno;			/* Errno.  */
};

// timeval struct used in prstatus
struct prstatus64_timeval
{
    uint64_t tv_sec;
    uint64_t tv_usec;
};

// prstatus for arm64
struct arm64_elf_prstatus
{
    struct elf_siginfo64 pr_info;	/* Info associated with signal.  */
    short int pr_cursig;		/* Current signal.  */
    uint64_t pr_sigpend;		/* Set of pending signals.  */
    uint64_t pr_sighold;		/* Set of held signals.  */
    pid_t pr_pid;
    pid_t pr_ppid;
    pid_t pr_pgrp;
    pid_t pr_sid;
    struct prstatus64_timeval pr_utime;		/* User time.  */
    struct prstatus64_timeval pr_stime;		/* System time.  */
    struct prstatus64_timeval pr_cutime;	/* Cumulative user time.  */
    struct prstatus64_timeval pr_cstime;	/* Cumulative system time.  */
    arm64_gregset64_t pr_reg;		/* GP registers.  */
    int pr_fpvalid;			/* True if math copro being used.  */
};

static_assert(sizeof(arm64_elf_prstatus)==0x188, "invalid prstatus");

// prstatus for x64
struct x64_elf_prstatus
{
    struct elf_siginfo64 pr_info;	/* Info associated with signal.  */
    short int pr_cursig;		/* Current signal.  */
    uint64_t pr_sigpend;		/* Set of pending signals.  */
    uint64_t pr_sighold;		/* Set of held signals.  */
    pid_t pr_pid;
    pid_t pr_ppid;
    pid_t pr_pgrp;
    pid_t pr_sid;
    struct prstatus64_timeval pr_utime;		/* User time.  */
    struct prstatus64_timeval pr_stime;		/* System time.  */
    struct prstatus64_timeval pr_cutime;	/* Cumulative user time.  */
    struct prstatus64_timeval pr_cstime;	/* Cumulative system time.  */
    x64_gregset64_t pr_reg;		/* GP registers.  */
    int pr_fpvalid;			/* True if math copro being used.  */
};

static_assert(sizeof(x64_elf_prstatus)==0x150, "invalid prstatus");

// prpsinfo
struct elf_prpsinfo64
{
    char pr_state;			/* Numeric process state.  */
    char pr_sname;			/* Char for pr_state.  */
    char pr_zomb;			/* Zombie.  */
    char pr_nice;			/* Nice val.  */
    uint64_t pr_flag;	/* Flags.  */
    unsigned int pr_uid;
    unsigned int pr_gid;
    int pr_pid, pr_ppid, pr_pgrp, pr_sid;
    char pr_fname[16];			/* Filename of executable.  */
#define ELF_PRARGSZ     (80)    /* Number of chars for args.  */
    char pr_psargs[ELF_PRARGSZ];	/* Initial part of arg list.  */
};

static_assert(sizeof(elf_prpsinfo64)==0x88, "invalid prpsinfo");

// Linux siginfo_t
#ifdef __APPLE__
struct lnx_siginfo_t {

    int si_signo;		/* Signal number.  */
    int si_code;
    int si_errno;
    int __pad0;			/* Explicit padding.  */
    int pad[128/4-4];
};
#else
typedef siginfo_t lnx_siginfo_t;
#endif

static_assert(sizeof(lnx_siginfo_t)==0x80, "invalid prpsinfo");

#ifdef __aarch64__
typedef arm64_user_regs64_struct    user_regs64_struct;
typedef arm64_user_fpsimd64_struct  user_fpregs64_struct;

#elif __x86_64__
typedef x64_user_regs64_struct      user_regs64_struct;
typedef x64_user_fpregs64_struct    user_fpregs64_struct;

#endif


#endif // _ARTHUR_ELF_H_
