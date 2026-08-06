#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <unistd.h>
#include <linux/swab.h>
#include <string.h>
#include "ecoff.h"

typedef struct LibSection_s
{
    char unkData[0x20];
    char interpName[0xC];
    char alignment[0x4];
} LibSection; // Size: 0x30

#define DEBUG_PRINT(...)                  \
    do                                    \
    {                                     \
        if (sEcoffDebug)                  \
        {                                 \
            fprintf(stderr, __VA_ARGS__); \
        }                                 \
    } while (0)

#define ARRAY_COUNT(arr) (int)(sizeof(arr) / sizeof(arr[0]))
static int sEcoffFileHeaderMagics[ECOFF_FILE_HEADER_MAGIC_NUMBERS] = {MIPSEBMAGIC, MIPSELMAGIC, SMIPSEBMAGIC, SMIPSELMAGIC, MIPSEBUMAGIC, MIPSELUMAGIC};
static u_int8_t *sEcoffBuffer;
static bool sEcoffReadInitialized = false;
static bool sEcoffFileHeaderByteSwapped = false;
static scnhdr **sEcoffSectionsHeader;
static const bool sEcoffDebug = false;

// Function to convert octal to decimal
static int decimal_to_octal(int n)
{
    int octal = 0;
    int place = 1;

    if (n == 0)
        return 0;

    while (n > 0)
    {
        int remainder = n % 8;
        octal += remainder * place;
        place *= 10;
        n /= 8;
    }

    return octal;
}

static const char *ecoff_aout_header_magic_to_string(u_int16_t magic)
{
    int realMagic = decimal_to_octal(magic);
    DEBUG_PRINT("From octal magic is: %d\n", realMagic);
    switch (realMagic)
    {
    case OMAGIC:
        return "OMAGIC";
    case NMAGIC:
        return "NMAGIC";
    case ZMAGIC:
        return "ZMAGIC";
    case LIBMAGIC:
        return "LIBMAGIC";
    default:
        DEBUG_PRINT("(ecoff_read.c) Unrecognized ecoff aout header magic: %d", magic);
        return NULL;
    }
}

static const char *ecoff_file_header_magic_to_string(u_int16_t magic)
{
    switch (magic)
    {
    case MIPSEBMAGIC:
        return "MIPSEBMAGIC";
    case MIPSELMAGIC:
        return "MIPSELMAGIC";
    case SMIPSEBMAGIC:
        return "SMIPSEBMAGIC";
    case SMIPSELMAGIC:
        return "SMIPSELMAGIC";
    case MIPSEBUMAGIC:
        return "MIPSEBUMAGIC";
    case MIPSELUMAGIC:
        return "MIPSELUMAGIC";
    default:
        DEBUG_PRINT("(ecoff_read.c) Unrecognized ecoff file header magic: %d", magic);
        return NULL;
    }
}

static void ecoff_byteswap_filehdr(filehdr *hdr)
{
    hdr->f_magic = __swab16(hdr->f_magic);
    hdr->f_nscns = __swab16(hdr->f_nscns);
    hdr->f_timdat = __swab32(hdr->f_timdat);
    hdr->f_symptr = __swab32(hdr->f_symptr);
    hdr->f_nsyms = __swab32(hdr->f_nsyms);
    hdr->f_opthdr = __swab16(hdr->f_opthdr);
    hdr->f_flags = __swab16(hdr->f_flags);
    sEcoffFileHeaderByteSwapped = true;
}

static void ecoff_byteswap_aout_header(aouthdr *hdr)
{
    hdr->magic = __swab16(hdr->magic);
    hdr->vstamp = __swab16(hdr->vstamp);
    hdr->tsize = __swab32(hdr->tsize);
    hdr->dsize = __swab32(hdr->dsize);
    hdr->bsize = __swab32(hdr->bsize);
    hdr->entry = __swab32(hdr->entry);
    hdr->text_start = __swab32(hdr->text_start);
    hdr->data_start = __swab32(hdr->data_start);
    hdr->bss_start = __swab32(hdr->bss_start);
    hdr->gprmask = __swab32(hdr->gprmask);

    for (int i = 0; i < 4; i++)
    {
        hdr->cprmask[i] = __swab32(hdr->cprmask[i]);
    }

    hdr->gp_value = __swab32(hdr->gp_value);
}

static void ecoff_byteswap_section_header(scnhdr *hdr)
{
    hdr->s_paddr = __swab32(hdr->s_paddr);
    hdr->s_vaddr = __swab32(hdr->s_vaddr);
    hdr->s_size = __swab32(hdr->s_size);
    hdr->s_scnptr = __swab32(hdr->s_scnptr);
    hdr->s_relptr = __swab32(hdr->s_relptr);
    hdr->s_lnnoptr = __swab32(hdr->s_lnnoptr);
    hdr->s_nreloc = __swab16(hdr->s_nreloc);
    hdr->s_nlnno = __swab16(hdr->s_nlnno);
    hdr->s_flags = __swab32(hdr->s_flags);
}

void ecoff_init(u_int8_t *buf, size_t len)
{
    if (!sEcoffReadInitialized)
    {
        sEcoffBuffer = malloc(len);
        if (sEcoffBuffer == NULL)
        {
            DEBUG_PRINT("Error couldn't allocate memory for ecoff buffer!\n");
            exit(EXIT_FAILURE);
        }

        memcpy(sEcoffBuffer, buf, len);

        sEcoffReadInitialized = true;
    }
}

filehdr *ecoff_get_file_header(void)
{
    ECOFF_LIB_CHECK;

    filehdr *ecoffFileHeader = (filehdr *)sEcoffBuffer;
    if (!sEcoffFileHeaderByteSwapped)
    {
        ecoff_byteswap_filehdr(ecoffFileHeader);
    }
    return ecoffFileHeader;
}

aouthdr *ecoff_get_aout_header(void)
{
    ECOFF_LIB_CHECK;
    aouthdr *header = (aouthdr *)&sEcoffBuffer[sizeof(filehdr)];

    ecoff_byteswap_aout_header(header);
    return header;
}

void ecoff_debug_print_aout_header(aouthdr *hdr)
{
    DEBUG_PRINT("-- Ecoff aout header -- \n\n");
    DEBUG_PRINT("Magic: %s\n", ecoff_aout_header_magic_to_string(hdr->magic));
    DEBUG_PRINT("Version stamp: %x\n", hdr->vstamp);
    DEBUG_PRINT("Text section size: %x\n", hdr->tsize);
    DEBUG_PRINT("Data section size: %x\n", hdr->dsize);
    DEBUG_PRINT("Bss section size: %x\n", hdr->bsize);
    DEBUG_PRINT("Entry pt: %x\n", hdr->entry);
    DEBUG_PRINT("Text section start: %x\n", hdr->text_start);
    DEBUG_PRINT("Data section start: %x\n", hdr->data_start);
    DEBUG_PRINT("Bss section start: %x\n", hdr->bss_start);
    DEBUG_PRINT("GPR MASK: %x\n", hdr->gprmask);
}

void ecoff_debug_print_file_header(filehdr *hdr)
{
    DEBUG_PRINT("-- Ecoff file header -- \n");
    DEBUG_PRINT("Magic: %x\n", hdr->f_magic);
    DEBUG_PRINT("Number of sections: %d\n", hdr->f_nscns);
    DEBUG_PRINT("Time date stamp: %d\n", hdr->f_timdat);
    DEBUG_PRINT("Ptr to symbolic header %x\n", hdr->f_symptr);
    DEBUG_PRINT("Size of symbolic header %x\n", hdr->f_nsyms);
    DEBUG_PRINT("Optional header size %d\n", hdr->f_opthdr);
    DEBUG_PRINT("Flags %x\n", hdr->f_flags);
}

inline static void ecoff_debug_print_section_header(scnhdr *hdr)
{
    DEBUG_PRINT("Section name: %s\n", (char *)hdr->s_name);
    DEBUG_PRINT("Section physical address: %x\n", hdr->s_paddr);
    DEBUG_PRINT("Section virtual address: %x\n", hdr->s_vaddr);
    DEBUG_PRINT("Section size: %x\n", hdr->s_size);
    DEBUG_PRINT("File ptr to section data: %x\n", hdr->s_scnptr);
    DEBUG_PRINT("Ptr to relocation: %x\n", hdr->s_relptr);
    DEBUG_PRINT("Number to gp histogram: %d\n", hdr->s_lnnoptr);
    DEBUG_PRINT("Relaction entries: %d\n", hdr->s_nreloc);
    DEBUG_PRINT("GP histogram entries: %d\n", hdr->s_nlnno);
    DEBUG_PRINT("Section flags: %x\n\n", hdr->s_flags);
}

bool ecoff_is_header_valid(void)
{
    ECOFF_LIB_CHECK;

    filehdr *ecoffFileHeader = (filehdr *)sEcoffBuffer;

    if (!sEcoffFileHeaderByteSwapped)
    {
        ecoff_byteswap_filehdr(ecoffFileHeader);
    }

    for (int i = 0; i < ECOFF_FILE_HEADER_MAGIC_NUMBERS; i++)
    {
        if (ecoffFileHeader->f_magic == sEcoffFileHeaderMagics[i])
        {
            DEBUG_PRINT("Ecoff magic found: %s\n", ecoff_file_header_magic_to_string(ecoffFileHeader->f_magic));

            return true;
        }
    }
    return false;
}

void ecoff_sections_header_read(void)
{
    ECOFF_LIB_CHECK;

    if (!sEcoffFileHeaderByteSwapped)
    {
        ecoff_byteswap_filehdr((filehdr *)sEcoffBuffer);
    }

    filehdr *fileHeader = (filehdr *)sEcoffBuffer;
    scnhdr *ecoffSections = (scnhdr *)&sEcoffBuffer[sizeof(filehdr) + sizeof(aouthdr)];

    // First we allocate the space for the number of sections
    sEcoffSectionsHeader = malloc(fileHeader->f_nscns * sizeof(*sEcoffSectionsHeader));

    if (sEcoffSectionsHeader == NULL)
    {
        DEBUG_PRINT("Couldn't allocate memory aborting!\n");
        abort();
    }

    /*
     * Now allocate a new section header and initialize it
     *       with the contents of the buffer
     */
    for (int i = 0; i < fileHeader->f_nscns; i++, ecoffSections++)
    {
        if (sEcoffDebug)
        {
            DEBUG_PRINT("Allocating\n");
        }
        sEcoffSectionsHeader[i] = malloc(sizeof(scnhdr));
        if (sEcoffDebug)
        {
            DEBUG_PRINT("Copying!\n");
        }
        *(sEcoffSectionsHeader[i]) = *ecoffSections;
        DEBUG_PRINT("Byteswaping!\n");
        ecoff_byteswap_section_header(sEcoffSectionsHeader[i]);
        DEBUG_PRINT("Printing!!\n");
        ecoff_debug_print_section_header(sEcoffSectionsHeader[i]);
    }
}

scnhdr *ecoff_get_section_header(const char *sectionName)
{
    ECOFF_LIB_CHECK;

    filehdr *fileHeader = (filehdr *)sEcoffBuffer;

    for (int i = 0; i < fileHeader->f_nscns; i++)
    {
        if (strcmp((char *)sEcoffSectionsHeader[i]->s_name, sectionName) == 0)
        {
            return sEcoffSectionsHeader[i];
        }
    }

    return NULL;
}

const char *ecoff_get_interp_name(void)
{
    ECOFF_LIB_CHECK;

    filehdr *fileHeader = (filehdr *)sEcoffBuffer;

    for (int i = 0; i < fileHeader->f_nscns; i++)
    {
        if (strcmp((char *)sEcoffSectionsHeader[i]->s_name, ".lib") == 0)
        {
            if (sEcoffSectionsHeader[i]->s_size == 48)
            {
                return "/lib/libc_s";
            }
        }
    }
    DEBUG_PRINT("Binary is static or has more than one library!\n");
    return NULL;
}

void ecoff_destroy(void)
{
    ECOFF_LIB_CHECK;

    if (sEcoffSectionsHeader == NULL)
    {
        DEBUG_PRINT("Not freeing sections because they are NULL!\n");
        return;
    }
    filehdr *fileHeader = (filehdr *)sEcoffBuffer;

    for (int i = 0; i < fileHeader->f_nscns; i++)
    {
        free(sEcoffSectionsHeader[i]);
        sEcoffSectionsHeader[i] = NULL;
    }

    free(sEcoffBuffer);

    sEcoffBuffer = NULL;
    sEcoffFileHeaderByteSwapped = false;
    sEcoffSectionsHeader = NULL;
    sEcoffReadInitialized = false;
}

int ecoff_get_data_sections_size(char *exception)
{
    static const char *sEcoffDataSectionsName[] = {".data", ".sdata", ".lit8", ".lit4", ".rdata"};
    filehdr *fileHeader = (filehdr *)sEcoffBuffer;
    int sectionsSize = 0;

    if (!sEcoffFileHeaderByteSwapped)
    {
        ecoff_byteswap_filehdr(fileHeader);
    }

    for (int i = 0; i < fileHeader->f_nscns; i++)
    {
        if (exception != NULL && (strcmp((char*)sEcoffSectionsHeader[i]->s_name, exception) == 0))
        {
            continue;
        }
        for (int j = 0; j < ARRAY_COUNT(sEcoffDataSectionsName); j++)
        {
            if (strcmp((char*)sEcoffSectionsHeader[i]->s_name, sEcoffDataSectionsName[j]) == 0)
            {
                sectionsSize += sEcoffSectionsHeader[i]->s_size;
                break;
            }
        }
    }
    assert(sectionsSize > 0);
    return sectionsSize;
}

int ecoff_get_bss_sections_size(char *exception)
{
    static const char *sEcoffDataSectionsName[] = {".sbss", ".bss"};
    filehdr *fileHeader = (filehdr *)sEcoffBuffer;
    int sectionsSize = 0;

    if (!sEcoffFileHeaderByteSwapped)
    {
        ecoff_byteswap_filehdr(fileHeader);
    }

    for (int i = 0; i < fileHeader->f_nscns; i++)
    {
        if (exception != NULL && (strcmp((char*)sEcoffSectionsHeader[i]->s_name, exception) == 0))
        {
            continue;
        }
        for (int j = 0; j < ARRAY_COUNT(sEcoffDataSectionsName); j++)
        {
            if (strcmp((char*)sEcoffSectionsHeader[i]->s_name, sEcoffDataSectionsName[j]) == 0)
            {
                sectionsSize += sEcoffSectionsHeader[i]->s_size;
                break;
            }
        }
    }
    assert(sectionsSize > 0);
    return sectionsSize;
}

scnhdr *ecoff_get_section_after_text(void)
{
    filehdr *fileHeader = (filehdr *)sEcoffBuffer;

    if (!sEcoffFileHeaderByteSwapped)
    {
        ecoff_byteswap_filehdr(fileHeader);
    }

    for (int i = 0; i < fileHeader->f_nscns; i++)
    {
        DEBUG_PRINT("sec pos: %d  sec name: %s\n", i, sEcoffSectionsHeader[i]->s_name);
    }

    int secInitPos = -1;
    for (int i = 0; i < fileHeader->f_nscns; i++)
    {
        if (strcmp((char *)sEcoffSectionsHeader[i]->s_name, ".init") == 0)
        {
            DEBUG_PRINT("Section init found at: %d\n", i);
            secInitPos = i;
            break;
        }
    }

    assert((secInitPos > 0) || ((secInitPos + 1) < fileHeader->f_nscns));
    return sEcoffSectionsHeader[secInitPos + 1];
}

bool ecoff_has_lib_section(void) {
    filehdr *fileHeader = (filehdr *)sEcoffBuffer;

    if (!sEcoffFileHeaderByteSwapped)
    {
        ecoff_byteswap_filehdr(fileHeader);
    }

    for (int i = 0; i < fileHeader->f_nscns; i++) {
        if (strcmp((char*)sEcoffSectionsHeader[i]->s_name, ".init") == 0) {
            return true;
        }
    }
    return false;
}