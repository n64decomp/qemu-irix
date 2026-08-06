#ifndef ECOFF_H
#define ECOFF_H
#include <stdbool.h>
#include <sys/types.h>

#define ECOFF_FILE_HEADER_MAGIC_NUMBERS 6

// File hdr magic
#define MIPSEBMAGIC 0x0160
#define MIPSELMAGIC 0x0162
#define SMIPSEBMAGIC 0x6001
#define SMIPSELMAGIC 0x6201
#define MIPSEBUMAGIC 0x0180
#define MIPSELUMAGIC 0x0182

// Aout hdr magic
#define OMAGIC  407
#define NMAGIC  410
#define ZMAGIC  413
#define SMAGIC  411
#define LIBMAGIC 443


#define ECOFF_LIB_CHECK do { if (!sEcoffReadInitialized) { printf("(%s: %d) must call ecoff_init first!\n", __func__, __LINE__); _exit(0);} } while (0)

typedef struct filehdr_s
{
    u_int16_t f_magic;  /* magic number */
    u_int16_t f_nscns;  /* number of sections */
    int32_t f_timdat;   /* time & date stamp */
    int32_t f_symptr;   /* file pointer to symbolic header */
    int32_t f_nsyms;    /* sizeof(symbolic hdr) */
    u_int16_t f_opthdr; /* sizeof(optional hdr) */
    u_int16_t f_flags;  /* flags */
} filehdr;

typedef struct aouthdr_s
{
    int16_t magic;      /* see above                            */
    int16_t vstamp;     /* version stamp                        */
    int32_t tsize;      /* text size in bytes, padded to DW bdry*/
    int32_t dsize;      /* initialized data "  "                */
    int32_t bsize;      /* uninitialized data "   "             */
    int32_t entry;      /* entry pt.                            */
    int32_t text_start; /* base of text used for this file      */
    int32_t data_start; /* base of data used for this file      */
    int32_t bss_start;  /* base of bss used for this file       */
    int32_t gprmask;    /* general purpose register mask        */
    int32_t cprmask[4]; /* co-processor register masks          */
    int32_t gp_value;   /* the gp value used for this object    */
} aouthdr;

typedef struct scnhdr_s
{
    int8_t s_name[8];   /* section name */
    int32_t s_paddr;    /* physical address, aliased s_nlib */
    int32_t s_vaddr;    /* virtual address */
    int32_t s_size;     /* section size */
    int32_t s_scnptr;   /* file ptr to raw data for section */
    int32_t s_relptr;   /* file ptr to relocation */
    int32_t s_lnnoptr;  /* file ptr to gp histogram */
    u_int16_t s_nreloc; /* number of relocation entries */
    u_int16_t s_nlnno;  /* number of gp histogram entries */
    int32_t s_flags;    /* flags */
} scnhdr;


void ecoff_debug_print_file_header(filehdr* hdr);
void ecoff_debug_print_aout_header(aouthdr* hdr);
filehdr* ecoff_get_file_header(void);
aouthdr *ecoff_get_aout_header(void);
void ecoff_init(u_int8_t *buf, size_t len);
bool ecoff_is_header_valid(void);
void ecoff_sections_header_read(void);
scnhdr* ecoff_get_section_header(const char* sectionName);
const char *ecoff_get_interp_name(void);
void ecoff_destroy(void);
scnhdr* ecoff_get_section_after_text(void);
int ecoff_get_data_sections_size(char *exception);
int ecoff_get_bss_sections_size(char *exception);
bool ecoff_has_lib_section(void);
#endif /* ECOFF_H */
