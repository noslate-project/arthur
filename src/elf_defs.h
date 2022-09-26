/* Elf constans definitions.
 * From man elf(5)
 */

#ifndef _ARTHUR_ELF_DEFS_H_
#define _ARTHUR_ELF_DEFS_H_

// Indentification Index
#define EI_LIST(V) \
    V(EI_MAG0, 0) \
    V(EI_MAG1, 1) \
    V(EI_MAG2, 2) \
    V(EI_MAG3, 3) \
    V(EI_CLASS, 4) \
    V(EI_DATA, 5) \
    V(EI_VERSION, 6) \
    V(EI_OSABI, 7) \
    V(EI_ABIVERSION, 8) \
    V(EI_PAD, 9) \
    V(EI_NIDENT, 16)

// Elf Magic
#define ELFMAG_LIST(V) \
    V(ELFMAG0, 0x7f) \
    V(ELFMAG1, 'E') \
    V(ELFMAG2, 'L') \
    V(ELFMAG3, 'F')

// EI_CLASS types
#define EI_CLASS_LIST(V) \
    V(ELFCLASSNONE, 0) \
    V(ELFCLASS32, 1) \
    V(ELFCLASS64, 2)

// EI_DATA types
#define EI_DATA_LIST(V) \
    V(ELFDATANONE, 0) \
    V(ELFDATA2LSB, 1) \
    V(ELFDATA2MSB, 2)

// EI_Version types
#define EI_VERSION_LIST(V) \
    V(EV_NONE, 0) \
    V(EV_CURRENT, 1) 

// Elf Types  
#define ET_LIST(V) \
    V(ET_NONE, 0) \
    V(ET_REL, 1) \
    V(ET_EXEC, 2) \
    V(ET_DYN, 3) \
    V(ET_CORE, 4)

// ELF OS/ABI types 
#define ELFOSABI_LIST(V) \
    V(ELFOSABI_NONE, 0) \
    V(ELFOSABI_LINUX, 3)

// Machine number
#define EM_LIST(V) \
    V(EM_NONE, 0) \
    V(EM_X86_64, 62) \

// Program types
#define PT_LIST(V) \
    V(PT_NULL, 0) \
    V(PT_LOAD, 1) \
    V(PT_DYNAMIC, 2) \
    V(PT_INTERP, 3) \
    V(PT_NOTE, 4) \
    V(PT_SHLIB, 5) \
    V(PT_PHDR, 6) \
    V(PT_TLS, 7) \
    V(PT_LOOS, 0X60000000) \
    V(PT_GNU_EH_FRAME, 0X6474E550) \
    V(PT_GNU_STACK, 0X6474E551) \
    V(PT_GNU_RELRO, 0X6474E552) \
    V(PT_GNU_PROPERTY, 0X6474E553) \
    V(PT_GNU_MBIND_LO, 0X6474E555) \
    V(PT_GNU_MBIND_HI, 0X6474F554)

// Program flags
#define PF_LIST(V) \
    V(PF_X, 1) \
    V(PF_W, 2) \
    V(PF_R, 4) 

// Section types
#define SHT_LIST(V) \
    V(SHT_NULL, 0) \
    V(SHT_PROGBITS, 1) \
    V(SHT_SYMTAB, 2) \
    V(SHT_STRTAB, 3) \
    V(SHT_RELA, 4) \
    V(SHT_HASH, 5) \
    V(SHT_DYNAMIC, 6) \
    V(SHT_NOTE, 7) \
    V(SHT_NOBITS, 8) \
    V(SHT_REL, 9) \
    V(SHT_SHLIB, 10) \
    V(SHT_DYNSYM, 11) \
    V(SHT_INIT_ARRAY, 14) \
    V(SHT_FINI_ARRAY, 15) \
    V(SHT_PREINIT_ARRAY, 16) \
    V(SHT_GROUP, 17) \
    V(SHT_SYMTAB_SHNDX, 18) \
    V(SHT_GNU_ATTRIBUTES, 0x6ffffff5) \
    V(SHT_GNU_HASH, 0x6ffffff6) \
    V(SHT_GNU_LIBLIST, 0x6ffffff7) \
    V(SHT_CHECKSUM, 0x6ffffff8) \
    V(SHT_LOSUNW, 0x6ffffffa) \
    V(SHT_SUNW_move, 0x6ffffffa) \
    V(SHT_SUNW_COMDAT, 0x6ffffffb) \
    V(SHT_SUNW_syminfo, 0x6ffffffc) \
    V(SHT_GNU_verdef, 0x6ffffffd) \
    V(SHT_GNU_verneed, 0x6ffffffe) \
    V(SHT_GNU_versym, 0x6fffffff)

// Note types
#define NT_CORE_LIST(V) \
    V(NT_PRSTATUS, 1) \
    V(NT_FPREGSET, 2) \
    V(NT_PRPSINFO, 3) \
    V(NT_TASKSTRUCT, 4) \
    V(NT_AUXV, 6) \
    V(NT_SIGINFO, 0x53494749) \
    V(NT_FILE, 0x46494c45) \
    V(NT_TLS, 0x200) \
    V(NT_X86_XSTATE, 0x202)

// AUXV defines
#define AT_AUXV_LIST(V) \
    V(AT_NULL, 0) \
    V(AT_IGNORE, 1) \
    V(AT_EXECFD, 2) \
    V(AT_PHDR, 3) \
    V(AT_PHENT, 4) \
    V(AT_PHNUM, 5) \
    V(AT_PAGESZ, 6) \
    V(AT_BASE, 7) \
    V(AT_FLAGS, 8) \
    V(AT_ENTRY, 9) \
    V(AT_NOTELF, 10) \
    V(AT_UID, 11) \
    V(AT_EUID, 12) \
    V(AT_GID, 13) \
    V(AT_EGID, 14) \
    V(AT_CLKTCK, 17)\
    V(AT_SYSINFO, 32) \
    V(AT_SYSINFO_EHDR, 33)

#endif // _ARTHUR_ELF_DEFS_H_
