#ifndef ECOFFLOAD_H
#define ECOFFLOAD_H

int load_ecoff_binary(struct linux_binprm *bprm, struct image_info *info, char* interpName, bool isStatic);
static void load_ecoff_image(const char *image_name, int image_fd,
                             struct image_info *info, char **pinterp_name,
                             char bprm_buf[BPRM_BUF_SIZE], bool isInterp);
#endif /* ECOFFLOAD_H */