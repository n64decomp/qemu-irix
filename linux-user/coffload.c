/* This is the Linux kernel elf-loading code, ported into user space */
#include "qemu/osdep.h"
#include <sys/param.h>

#include <sys/resource.h>

#include "qemu.h"
#include "disas/disas.h"
#include "qemu/path.h"
#include <linux/swab.h>
#include "irix/ecoff_lib/ecoff.h"
#include "ecoffload.h"

int gGPValue;
int gEntryPt;

enum {
    ADDR_NO_RANDOMIZE = 0x0040000,      /* disable randomization of VA space */
    FDPIC_FUNCPTRS =    0x0080000,      /* userspace function ptrs point to
                                           descriptors (signal handling) */
    MMAP_PAGE_ZERO =    0x0100000,
    ADDR_COMPAT_LAYOUT = 0x0200000,
    READ_IMPLIES_EXEC = 0x0400000,
    ADDR_LIMIT_32BIT =  0x0800000,
    SHORT_INODE =       0x1000000,
    WHOLE_SECONDS =     0x2000000,
    STICKY_TIMEOUTS =   0x4000000,
    ADDR_LIMIT_3GB =    0x8000000,
};

#ifndef STACK_GROWS_DOWN
#define STACK_GROWS_DOWN 1
#endif

#define TARGET_ELF_EXEC_PAGESIZE TARGET_PAGE_SIZE
#define TARGET_ELF_PAGESTART(_v) ((_v) & \
                                  ~(abi_ulong)(TARGET_ELF_EXEC_PAGESIZE - 1))
#define TARGET_ELF_PAGEOFFSET(_v) ((_v) & (TARGET_ELF_EXEC_PAGESIZE - 1))

static void zero_bss(abi_ulong elf_bss, abi_ulong last_bss, int prot)
{
    uintptr_t host_start, host_map_start, host_end;

    last_bss = TARGET_PAGE_ALIGN(last_bss);

    /* ??? There is confusion between qemu_real_host_page_size and
       qemu_host_page_size here and elsewhere in target_mmap, which
       may lead to the end of the data section mapping from the file
       not being mapped.  At least there was an explicit test and
       comment for that here, suggesting that "the file size must
       be known".  The comment probably pre-dates the introduction
       of the fstat system call in target_mmap which does in fact
       find out the size.  What isn't clear is if the workaround
       here is still actually needed.  For now, continue with it,
       but merge it with the "normal" mmap that would allocate the bss.  */

    host_start = (uintptr_t) g2h(elf_bss);
    host_end = (uintptr_t) g2h(last_bss);
    host_map_start = REAL_HOST_PAGE_ALIGN(host_start);

    if (host_map_start < host_end) {
        void *p = mmap((void *)host_map_start, host_end - host_map_start,
                       prot, MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED) {
            perror("cannot mmap brk");
            exit(-1);
        }
    }

    /* Ensure that the bss page(s) are valid */
    if ((page_get_flags(last_bss-1) & prot) != prot) {
        page_set_flags(elf_bss & TARGET_PAGE_MASK, last_bss, prot | PAGE_VALID);
    }

    if (host_start < host_map_start) {
        memset((void *)host_start, 0, host_map_start - host_start);
    }
}

static inline void memcpy_fromfs(void *to, const void *from, unsigned long n)
{
    memcpy(to, from, n);
}

static abi_ulong copy_elf_strings(int argc, char **argv, char *scratch,
                                  abi_ulong p, abi_ulong stack_limit)
{
    char *tmp;
    int len, i;
    abi_ulong top = p;

    if (!p)
    {
        return 0; /* bullet-proofing */
    }

    if (STACK_GROWS_DOWN)
    {
        int offset = ((p - 1) % TARGET_PAGE_SIZE) + 1;
        for (i = argc - 1; i >= 0; --i)
        {
            tmp = argv[i];
            if (!tmp)
            {
                fprintf(stderr, "VFS: argc is wrong");
                exit(-1);
            }
            len = strlen(tmp) + 1;
            tmp += len;

            if (len > (p - stack_limit))
            {
                return 0;
            }
            while (len)
            {
                int bytes_to_copy = (len > offset) ? offset : len;
                tmp -= bytes_to_copy;
                p -= bytes_to_copy;
                offset -= bytes_to_copy;
                len -= bytes_to_copy;

                memcpy_fromfs(scratch + offset, tmp, bytes_to_copy);

                if (offset == 0)
                {
                    memcpy_to_target(p, scratch, top - p);
                    top = p;
                    offset = TARGET_PAGE_SIZE;
                }
            }
        }
        if (p != top)
        {
            memcpy_to_target(p, scratch + offset, top - p);
        }
    }
    else
    {
        int remaining = TARGET_PAGE_SIZE - (p % TARGET_PAGE_SIZE);
        for (i = 0; i < argc; ++i)
        {
            tmp = argv[i];
            if (!tmp)
            {
                fprintf(stderr, "VFS: argc is wrong");
                exit(-1);
            }
            len = strlen(tmp) + 1;
            if (len > (stack_limit - p))
            {
                return 0;
            }
            while (len)
            {
                int bytes_to_copy = (len > remaining) ? remaining : len;

                memcpy_fromfs(scratch + (p - top), tmp, bytes_to_copy);

                tmp += bytes_to_copy;
                remaining -= bytes_to_copy;
                p += bytes_to_copy;
                len -= bytes_to_copy;

                if (remaining == 0)
                {
                    memcpy_to_target(top, scratch, p - top);
                    top = p;
                    remaining = TARGET_PAGE_SIZE;
                }
            }
        }
        if (p != top)
        {
            memcpy_to_target(top, scratch, p - top);
        }
    }

    return p;
}

#define STACK_ALIGNMENT 16
static abi_ulong create_stack_tables_only(abi_ulong sp,
                                          int argc, int envc,
                                          struct image_info *info)
{
    abi_ulong u_argc, u_argv, u_envp;
    abi_ulong p;
    int i;
    const int n = sizeof(abi_ulong);

    /*
     * Stack grows down
     *
     * Layout:
     *   argc
     *   argv[0..argc-1]
     *   NULL
     *   envp[0..envc-1]
     *   NULL
     */

    /* Space for:
     * argc
     * argv pointers + NULL
     * envp pointers + NULL
     */
    int size = 1                 /* argc */
             + (argc + 1)        /* argv[] + NULL */
             + (envc + 1);       /* envp[] + NULL */

    size *= n;

    /* Allocate stack */
    sp = QEMU_ALIGN_DOWN(sp - size, STACK_ALIGNMENT);
    u_argc = sp;

    /* Pointers */
    u_argv = u_argc + n;
    u_envp = u_argv + (argc + 1) * n;

    /* argc */
    put_user_ual(argc, u_argc);

    /* argv[] */
    p = info->arg_strings;
    for (i = 0; i < argc; i++) {
        put_user_ual(p, u_argv);
        u_argv += n;
        p += target_strlen(p) + 1;
    }
    put_user_ual(0, u_argv); /* argv NULL */

    /* envp[] */
    p = info->env_strings;
    for (i = 0; i < envc; i++) {
        put_user_ual(p, u_envp);
        u_envp += n;
        p += target_strlen(p) + 1;
    }
    put_user_ual(0, u_envp); /* envp NULL */

    /* Save for register setup */
    info->arg_start = u_argv - argc * n;
    info->arg_end   = u_argv - n;

    return sp;
}


/* Older linux kernels provide up to MAX_ARG_PAGES (default: 32) of
 * argument/environment space. Newer kernels (>2.6.33) allow more,
 * dependent on stack size, but guarantee at least 32 pages for
 * backwards compatibility.
 */
#define STACK_LOWER_LIMIT (32 * TARGET_PAGE_SIZE)

static abi_ulong setup_arg_pages(struct linux_binprm *bprm,
                                 struct image_info *info)
{
    abi_ulong size, error, guard;

    size = guest_stack_size;
    if (size < STACK_LOWER_LIMIT)
    {
        size = STACK_LOWER_LIMIT;
    }
    guard = TARGET_PAGE_SIZE;
    if (guard < qemu_real_host_page_size)
    {
        guard = qemu_real_host_page_size;
    }

#ifdef TARGET_ABI_IRIX
    error = target_mmap(0x7fff8000 - size - guard, size + guard, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
#else
    error = target_mmap(0, size + guard, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
#endif
    if (error == -1)
    {
        perror("mmap stack");
        exit(-1);
    }

    /* We reserve one extra page at the top of the stack as guard.  */
    if (STACK_GROWS_DOWN)
    {
        target_mprotect(error, guard, PROT_NONE);
        info->stack_limit = error + guard;
        return info->stack_limit + size - sizeof(void *);
    }
    else
    {
        target_mprotect(error + size, guard, PROT_NONE);
        info->stack_limit = error + size;
        return error;
    }
}

void map_ecoff_text_segment(int imageFd, const char *imageName, scnhdr *text, struct image_info *info)
{
    mmap_lock();

    abi_ulong vaddr = text->s_vaddr;
    abi_ulong filesz = text->s_size;
    abi_ulong file_offset = text->s_scnptr;

    abi_ulong vaddr_po = TARGET_ELF_PAGEOFFSET(vaddr);
    abi_ulong vaddr_ps = TARGET_ELF_PAGESTART(vaddr);

    abi_long error = target_mmap(vaddr_ps, filesz + vaddr_po,
                                 PROT_READ | PROT_EXEC, MAP_PRIVATE | MAP_FIXED,
                                 imageFd, file_offset - vaddr_po);

    if (error == -1)
    {
        char *errmsg = strerror(errno);
        printf("MMAP allocation memory block request failed!\n");
        fprintf(stderr, "%s: %s\n", imageName, errmsg);
        exit(-1);
    }
    mmap_unlock();

    info->load_bias = 0;
    info->load_addr = text->s_scnptr;
    info->entry = text->s_vaddr + info->load_bias;
    info->start_code = text->s_vaddr;

    if (ecoff_get_section_header(".init"))
    {
        info->end_code = text->s_vaddr + text->s_size + ecoff_get_section_header(".init")->s_size;
    }
    else
    { // Libraries and object files
        info->end_code = text->s_vaddr + text->s_size;
    }
}

void map_ecoff_interp_data_segment(int imageFd, const char *imageName, struct image_info *info)
{
    scnhdr *data = ecoff_get_section_header(".data");
    scnhdr *rodata = ecoff_get_section_header(".rdata");
    scnhdr *bss = ecoff_get_section_header(".bss");

    mmap_lock();

    abi_ulong vaddr = data->s_vaddr;
    abi_ulong filesz = data->s_size + rodata->s_size;
    abi_ulong file_offset = data->s_scnptr;

    abi_ulong vaddr_po = TARGET_ELF_PAGEOFFSET(vaddr);
    abi_ulong vaddr_ps = TARGET_ELF_PAGESTART(vaddr);



    abi_long error = target_mmap(vaddr_ps, filesz + vaddr_po,
                                 PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_FIXED,
                                 imageFd, file_offset - vaddr_po);

    abi_ulong vaddr_ef = vaddr + filesz;
    abi_ulong vaddr_em = vaddr + (filesz + bss->s_size);

    zero_bss(vaddr_ef, vaddr_em, PROT_READ | PROT_WRITE);

    if (error == -1)
    {
        char *errmsg = strerror(errno);
        printf("MMAP allocation memory block request failed!\n");
        fprintf(stderr, "%s: %s\n", imageName, errmsg);
        exit(-1);
    }
    mmap_unlock();

    info->start_data = data->s_vaddr;
    info->end_data = data->s_vaddr + filesz;
    info->brk = data->s_vaddr + filesz + bss->s_size;
}

void map_ecoff_data_segment(int imageFd, const char *imageName, struct image_info *info, bool isInterp)
{
    abi_ulong vaddr;
    abi_ulong filesz;
    abi_ulong dataSize;
    abi_ulong file_offset;
    char* sectionAfterInitName;
    scnhdr* currentSection;

    if (isInterp)
    {
        map_ecoff_interp_data_segment(imageFd, imageName, info);
        return;
    }

    currentSection = ecoff_get_section_after_text(); // rdata
    file_offset = currentSection->s_scnptr;
    sectionAfterInitName = currentSection->s_name;
    vaddr = currentSection->s_vaddr;
    dataSize = filesz = currentSection->s_size;

    filesz = dataSize += ecoff_get_data_sections_size((char*)currentSection->s_name);
    filesz += ecoff_get_bss_sections_size((char*)currentSection->s_name);

    scnhdr* bss = ecoff_get_section_header(".bss");
    scnhdr* sbss = ecoff_get_section_header(".sbss");
    assert(bss != NULL && sbss != NULL);

    mmap_lock();

    abi_ulong vaddr_po = TARGET_ELF_PAGEOFFSET(vaddr);
    abi_ulong vaddr_ps = TARGET_ELF_PAGESTART(vaddr);

    abi_long error = target_mmap(vaddr_ps, filesz + vaddr_po,
                                 PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_FIXED,
                                 imageFd, file_offset - vaddr_po);

    if (error == -1)
    {
        char *errmsg = strerror(errno);
        printf("MMAP allocation memory block request failed!\n");
        fprintf(stderr, "%s: %s\n", imageName, errmsg);
        exit(-1);
    }
    abi_ulong vaddr_ef = sbss->s_vaddr;
    abi_ulong vaddr_em = sbss->s_vaddr + sbss->s_size + bss->s_size;

    zero_bss(vaddr_ef, vaddr_em, PROT_READ | PROT_WRITE);
    mmap_unlock();

    info->start_data = vaddr;
    info->end_data = vaddr + dataSize;
    info->brk = vaddr + dataSize + sbss->s_size + bss->s_size;
}

void load_ecoff_image(const char *image_name, int image_fd,
                      struct image_info *info, char **pinterp_name,
                      char bprm_buf[BPRM_BUF_SIZE], bool isInterp)
{
    ecoff_init(bprm_buf, BPRM_BUF_SIZE);
    filehdr *ecoffFileHeader = ecoff_get_file_header();
    ecoff_debug_print_file_header(ecoffFileHeader);

    aouthdr *ecoffAoutHeader = ecoff_get_aout_header();
    ecoff_debug_print_aout_header(ecoffAoutHeader);

    ecoff_sections_header_read();

    scnhdr *text = ecoff_get_section_header(".text");

    if (text == NULL)
    {
        printf("Couldn't get text section aborting!!!\n");
        exit(EXIT_FAILURE);
    }

    // Map text
    //printf("MMAP\n");
    map_ecoff_text_segment(image_fd, image_name, text, info);
    map_ecoff_data_segment(image_fd, image_name, info, isInterp);
    ecoff_destroy();
}

static void load_ecoff_interp(const char *filename, struct image_info *info,
                              char bprm_buf[BPRM_BUF_SIZE])
{

    int fd = open(path(filename), O_RDONLY);
    if (fd < 0)
    {
        goto exit_perror;
    }

    int retval = read(fd, bprm_buf, BPRM_BUF_SIZE);
    if (retval < 0)
    {
        goto exit_perror;
    }
    if (retval < BPRM_BUF_SIZE)
    {
        memset(bprm_buf + retval, 0, BPRM_BUF_SIZE - retval);
    }

    load_ecoff_image(filename, fd, info, NULL, bprm_buf, true);
    return;

exit_perror:
    fprintf(stderr, "%s: %s\n", filename, strerror(errno));
    exit(-1);
}

int load_ecoff_binary(struct linux_binprm *bprm, struct image_info *info, char *interpName, bool isStatic)
{
    struct image_info interp_info;
    char *scratch;
    abi_ulong top;

    info->start_mmap = (abi_ulong)0x80000000; // ELF_MAP

    // First load the image
    aouthdr *aoutHeader = (aouthdr *)&bprm->buf[sizeof(filehdr)];
    gGPValue = __swab32(aoutHeader->gp_value);
    gEntryPt = __swab32(aoutHeader->entry);


    load_ecoff_image(bprm->filename, bprm->fd, info,
                     NULL, bprm->buf, false);

    /* Do this so that we can load the interpreter, if need be.  We will
   change some of these later */
    bprm->p = top = setup_arg_pages(bprm, info);

    scratch = g_new0(char, TARGET_PAGE_SIZE);
    if (STACK_GROWS_DOWN)
    {
        bprm->p = copy_elf_strings(1, &bprm->filename, scratch,
                                   bprm->p, info->stack_limit);
        info->file_string = bprm->p;
        bprm->p = copy_elf_strings(bprm->envc, bprm->envp, scratch,
                                   bprm->p, info->stack_limit);
        info->env_strings = bprm->p;
        bprm->p = copy_elf_strings(bprm->argc, bprm->argv, scratch,
                                   bprm->p, info->stack_limit);
        info->arg_strings = bprm->p;
    }
    else
    {
        info->arg_strings = bprm->p;
        bprm->p = copy_elf_strings(bprm->argc, bprm->argv, scratch,
                                   bprm->p, info->stack_limit);
        info->env_strings = bprm->p;
        bprm->p = copy_elf_strings(bprm->envc, bprm->envp, scratch,
                                   bprm->p, info->stack_limit);
        info->file_string = bprm->p;
        bprm->p = copy_elf_strings(1, &bprm->filename, scratch,
                                   bprm->p, info->stack_limit);
    }

    g_free(scratch);

    if (!bprm->p)
    {
        fprintf(stderr, "%s: %s\n", bprm->filename, strerror(E2BIG));
        exit(-1);
    }

    /* page alignment */
    if (bprm->p % TARGET_PAGE_SIZE)
    {
        int o = bprm->p % TARGET_PAGE_SIZE;
        int l = top - bprm->p;
        int p = bprm->p - o;
        char *ptr = lock_user(VERIFY_WRITE, p, l + o, 0);
        if (!ptr)
        {
            fprintf(stderr, "%s: %s\n", bprm->filename, strerror(EFAULT));
            exit(-1);
        }
        memmove(ptr, ptr + o, l);
        unlock_user(ptr, p, 1);
        /* adjust pointers by alignment offset */
        bprm->p -= o;
        info->file_string -= o;
        info->arg_strings -= o;
        info->env_strings -= o;
    }

    if (!isStatic) {
        load_ecoff_interp(interpName, &interp_info, bprm->buf);
    }

    //info->personality = 0x0001 | STICKY_TIMEOUTS | MMAP_PAGE_ZERO;
    // Imitate SVR4 behaviour
    target_mmap(0, qemu_host_page_size, PROT_READ | PROT_EXEC,
                MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    info->start_stack = bprm->p = create_stack_tables_only(bprm->p, bprm->argc, bprm->envc, info);

    info->load_bias = 0;
    info->entry = aoutHeader->entry;

    target_mmap(
        0x05c00000,
        0x00200000, // 2 MB
        PROT_READ | PROT_WRITE,
        MAP_FIXED | MAP_PRIVATE | MAP_ANON,
        -1,
        0);


        //printf("ARGC: %d\n", bprm->argc);
        //printf("ARGV: %s\n", *bprm->argv);
    return 0;
}