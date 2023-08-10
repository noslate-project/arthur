/* Elf file format,
 * From man elf(5)
 */

#ifndef _ARTHUR_ELF_H_
#define _ARTHUR_ELF_H_

#include <unistd.h>
#include <stdint.h>
#include <signal.h>
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
typedef uint64_t a8_uint64_t;
typedef a8_uint64_t elf_greg64_t;

#ifdef __aarch64__

struct user_regs64_struct
{
  uint64_t regs[31];
  uint64_t sp;
  uint64_t pc;
  uint64_t pstate;

#define s_pc    pc 
#define s_sp    sp 
#define s_fp    regs[29] 
#define s_rc    regs[0]

#define s_ag0   regs[0]
#define s_ag1   regs[1]
#define s_ag2   regs[2]
#define s_ag3   regs[3]
#define s_ag4   regs[4]
#define s_ag5   regs[5]

    static void DebugPrint(user_regs64_struct *r) {
        for (int i=0; i<31; i++) 
            printf("x%d = %lx (%lu)\n", i, r->regs[i], r->regs[i]);
        printf("pc = %lx\n", r->pc);
        printf("sp = %lx\n", r->sp);
    }
};

struct user_fpsimd64_struct
{
  __uint128_t  vregs[32];
  unsigned int fpsr;
  unsigned int fpcr;
};

#define ELF_NGREG64 (sizeof (struct user_regs64_struct) / sizeof(elf_greg64_t))
typedef elf_greg64_t elf_gregset64_t[ELF_NGREG64];
typedef user_fpsimd64_struct elf_fpregset64_t;
typedef elf_prpsinfo elf_prpsinfo64;
typedef elf_prstatus elf_prstatus64;

static_assert(sizeof(elf_prstatus64)==0x188, "invalid prstatus");
static_assert(sizeof(elf_prpsinfo64)==0x88, "invalid prpsinfo");
static_assert(sizeof(siginfo_t)==0x80, "invalid prpsinfo");

#else 
#define ELF_PRARGSZ     (80)    /* Number of chars for args.  */

/* Signal info.  */
struct elf_siginfo
  {
    int si_signo;			/* Signal number.  */
    int si_code;			/* Extra code.  */
    int si_errno;			/* Errno.  */
  };

struct user_regs64_struct
{
    a8_uint64_t r15;
    a8_uint64_t r14;
    a8_uint64_t r13;
    a8_uint64_t r12;
    a8_uint64_t rbp;
    a8_uint64_t rbx;
    a8_uint64_t r11;
    a8_uint64_t r10;
    a8_uint64_t r9;
    a8_uint64_t r8;
    a8_uint64_t rax;
    a8_uint64_t rcx;
    a8_uint64_t rdx;
    a8_uint64_t rsi;
    a8_uint64_t rdi;
    a8_uint64_t orig_rax;
    a8_uint64_t rip;
    a8_uint64_t cs;
    a8_uint64_t eflags;
    a8_uint64_t rsp;
    a8_uint64_t ss;
    a8_uint64_t fs_base;
    a8_uint64_t gs_base;
    a8_uint64_t ds;
    a8_uint64_t es;
    a8_uint64_t fs;
    a8_uint64_t gs;

#define s_pc    rip
#define s_sp    rsp
#define s_fp    rbp
#define s_rc    rax

#define s_ag0   rdi
#define s_ag1   rsi
#define s_ag2   rdx
#define s_ag3   rcx
#define s_ag4   r8
#define s_ag5   r9

    static void DebugPrint(user_regs64_struct *r) {
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

struct user_fpregs64_struct
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

static_assert(sizeof(user_fpregs64_struct)==0x200, "invalid prstatus");

#define ELF_NGREG64 (sizeof (struct user_regs64_struct) / sizeof(elf_greg64_t))
typedef elf_greg64_t elf_gregset64_t[ELF_NGREG64];

typedef user_fpregs64_struct elf_fpregset64_t;

#define X86_XSTATE_MAX_SIZE 2696
typedef char elf_x86xstatereg[X86_XSTATE_MAX_SIZE];

struct prstatus64_timeval
{
    a8_uint64_t tv_sec;
    a8_uint64_t tv_usec;
};

struct elf_prstatus64
{
    struct elf_siginfo pr_info;	/* Info associated with signal.  */
    short int pr_cursig;		/* Current signal.  */
    a8_uint64_t pr_sigpend;		/* Set of pending signals.  */
    a8_uint64_t pr_sighold;		/* Set of held signals.  */
    pid_t pr_pid;
    pid_t pr_ppid;
    pid_t pr_pgrp;
    pid_t pr_sid;
    struct prstatus64_timeval pr_utime;		/* User time.  */
    struct prstatus64_timeval pr_stime;		/* System time.  */
    struct prstatus64_timeval pr_cutime;	/* Cumulative user time.  */
    struct prstatus64_timeval pr_cstime;	/* Cumulative system time.  */
    elf_gregset64_t pr_reg;		/* GP registers.  */
    int pr_fpvalid;			/* True if math copro being used.  */
};

static_assert(sizeof(elf_prstatus64)==0x150, "invalid prstatus");

struct elf_prpsinfo64
{
    char pr_state;			/* Numeric process state.  */
    char pr_sname;			/* Char for pr_state.  */
    char pr_zomb;			/* Zombie.  */
    char pr_nice;			/* Nice val.  */
    a8_uint64_t pr_flag;	/* Flags.  */
    unsigned int pr_uid;
    unsigned int pr_gid;
    int pr_pid, pr_ppid, pr_pgrp, pr_sid;
    char pr_fname[16];			/* Filename of executable.  */
    char pr_psargs[ELF_PRARGSZ];	/* Initial part of arg list.  */
};

static_assert(sizeof(elf_prpsinfo64)==0x88, "invalid prpsinfo");

// defined in signal.h
static_assert(sizeof(siginfo_t)==0x80, "invalid prpsinfo");

#endif // x86_64

#endif // _ARTHUR_ELF_H_
