#include <assert.h>
#include <elf.h>
#include <fcntl.h>
#include <libelf.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "elfin.h"

#define MAX_FILENAME_LEN 256

static bool strips_check_magic(Elf *elf) {
    if (!elf) {
        return true;
    }

    Elf64_Ehdr *ehdr;
    if ((ehdr = elf64_getehdr(elf)) == NULL) {
        fprintf(stderr, "%s\n", elf_errmsg(elf_errno()));
        return true;
    }

    unsigned char *e_ident = ehdr->e_ident;
    if (e_ident[EI_MAG0] != ELFMAG0 || e_ident[EI_MAG1] != ELFMAG1 ||
        e_ident[EI_MAG2] != ELFMAG2 || e_ident[EI_MAG3] != ELFMAG3) {
        fprintf(stderr, "bad elf magic\n");
        return true;
    }

    if (e_ident[EI_CLASS] != ELFCLASS32 && e_ident[EI_CLASS] != ELFCLASS64) {
        fprintf(stderr, "bad elf class\n");
        return true;
    }

    if (ehdr->e_ehsize < sizeof(Elf64_Ehdr)) {
        fprintf(stderr, "bad elf format\n");
        return true;
    }

    if (ehdr->e_shnum == 0 || ehdr->e_shoff == 0) {
        fprintf(stderr, "bad section table\n");
        return true;
    }

    if (ehdr->e_phnum == 0 || ehdr->e_phoff == 0) {
        fprintf(stderr, "bad program header table\n");
    }

    size_t shstrndx;
    if (elf_getshdrstrndx(elf, &shstrndx) != 0) {
        fprintf(stderr, "bad section header string index\n");
    }

    return false;
}

static ELFIN_ERROR elfin_get_interp(Elf *elf, char *output) {
    assert(elf);

    size_t phdr_num;
    if (elf_getphdrnum(elf, &phdr_num) != 0) {
        printf("Failed to get program header count: %s\n",
               elf_errmsg(elf_errno()));
        return ELFIN_FAILURE;
    }

    Elf64_Phdr *phdr_entries = NULL;
    if ((phdr_entries = elf64_getphdr(elf)) == NULL) {
        return ELFIN_FAILURE;
    }

    for (size_t i = 0; i < phdr_num; ++i) {
        if (phdr_entries[i].p_type != PT_INTERP) {
            continue;
        }
        Elf_Scn *scn = NULL;
        Elf_Data *data = NULL;

        while ((scn = elf_nextscn(elf, scn)) != NULL) {
            Elf64_Shdr *shdr = NULL;
            if ((shdr = elf64_getshdr(scn)) == NULL) {
                fprintf(stderr, "getshdr failed: %s\n",
                        elf_errmsg(elf_errno()));
                return ELFIN_SHDR_FAILURE;
            }

            if (shdr->sh_offset <= phdr_entries[i].p_offset &&
                shdr->sh_offset + shdr->sh_size >=
                    phdr_entries[i].p_offset + phdr_entries[i].p_filesz) {
                data = elf_getdata(scn, NULL);
                if (data && data->d_buf) {
                    strcpy(output,
                           (char *)data->d_buf +
                               (phdr_entries[i].p_offset - shdr->sh_offset));
                    break;
                }
            }
        }
    }
    return ELFIN_OK;
}

static ELFIN_ERROR elfin_set_interp(Elf *elf, const char *interp) {
    assert(elf);

    size_t phdr_num;
    if (elf_getphdrnum(elf, &phdr_num) != 0) {
        printf("Failed to get program header count: %s\n",
               elf_errmsg(elf_errno()));
        return ELFIN_FAILURE;
    }

    Elf64_Phdr *phdr_entries = NULL;
    if ((phdr_entries = elf64_getphdr(elf)) == NULL) {
        return ELFIN_FAILURE;
    }

    Elf64_Phdr *last_load = NULL;
    for (size_t i = 0; i < phdr_num; ++i) {
        if (phdr_entries[i].p_type == PT_INTERP) {
            last_load = &phdr_entries[i];
        }
    }

    if (last_load == NULL) {
        return ELFIN_PHDR_FAILURE;
    }

    size_t new_interp_len = strlen(interp) + 1;

    if (last_load->p_filesz >= new_interp_len) { // no need to relocate
        Elf_Scn *scn = NULL;
        while ((scn = elf_nextscn(elf, scn)) != NULL) {
            Elf64_Shdr *shdr = NULL;
            if ((shdr = elf64_getshdr(scn)) == NULL) {
                fprintf(stderr, "getshdr failed: %s\n",
                        elf_errmsg(elf_errno()));
                return ELFIN_SHDR_FAILURE;
            }

            if (shdr->sh_offset <= last_load->p_offset &&
                shdr->sh_offset + shdr->sh_size >=
                    last_load->p_offset + last_load->p_filesz) {
                Elf_Data *data = elf_getdata(scn, NULL);
                if (data && data->d_buf) {
                    strncpy((char *)data->d_buf +
                                (last_load->p_offset - shdr->sh_offset),
                            interp, new_interp_len);
                    memset((char *)data->d_buf +
                               (last_load->p_offset - shdr->sh_offset) +
                               new_interp_len,
                           0, data->d_size - new_interp_len);
                    elf_flagdata(data, ELF_C_SET, ELF_F_DIRTY);
                    break;
                }
            }
        }
    } else {
        fprintf(stderr, "can't rename with string of larger size\n");
        return ELFIN_FAILURE;
    }

    return ELFIN_OK;
}

static ELFIN_ERROR elfin_get_rpath(Elf *elf, char *output) {
    assert(elf);

    size_t shdrstr_idx;
    if (elf_getshdrstrndx(elf, &shdrstr_idx) != 0) {
        return ELFIN_SHDR_FAILURE;
    }

    Elf_Scn *scn = NULL;
    while ((scn = elf_nextscn(elf, scn)) != NULL) {
        Elf64_Shdr *shdr = NULL;
        if ((shdr = elf64_getshdr(scn)) == NULL) {
            fprintf(stderr, "getshdr failed: %s\n", elf_errmsg(elf_errno()));
            continue;
        }

        if (shdr->sh_type == SHT_DYNAMIC) {
            break;
        }
    }

    if (scn == NULL) {
        return ELFIN_SCN_FAILURE;
    }

    Elf_Data *dynamic_data = NULL;
    if ((dynamic_data = elf_getdata(scn, dynamic_data)) == NULL) {
        return ELFIN_SCN_FAILURE;
    }

    Elf64_Dyn *dyn_entries = (Elf64_Dyn *)dynamic_data->d_buf;
    size_t count = dynamic_data->d_size / sizeof(Elf64_Dyn);
    Elf64_Addr rpath_offt = 0;
    Elf64_Addr strtab_addr = 0;
    for (size_t i = 0; i < count; ++i) {
        if (dyn_entries[i].d_tag == DT_STRTAB) {
            strtab_addr = dyn_entries[i].d_un.d_ptr;
        }
        if (dyn_entries[i].d_tag == DT_RPATH ||
            dyn_entries[i].d_tag == DT_RUNPATH) {
            rpath_offt = dyn_entries[i].d_un.d_val;
        }
    }

    if (rpath_offt == 0 || strtab_addr == 0) {
        fprintf(stderr, "dynamic entry for rpath of strtab is NULL\n");
        output[0] = '\0';
        return ELFIN_OK;
    }

    scn = NULL;
    while ((scn = elf_nextscn(elf, scn)) != NULL) {
        Elf64_Shdr *shdr = NULL;
        if ((shdr = elf64_getshdr(scn)) == NULL) {
            fprintf(stderr, "getshdr failed: %s\n", elf_errmsg(elf_errno()));
            continue;
        }

        if (shdr->sh_addr <= strtab_addr &&
            strtab_addr < shdr->sh_addr + shdr->sh_size) {
            break;
        }
    }

    Elf_Data *data = NULL;
    if ((data = elf_getdata(scn, data)) == NULL) {
        fprintf(stderr, "can't get .strtab data\n");
        return ELFIN_SCN_FAILURE;
    }
    if (data->d_size <= rpath_offt) {
        fprintf(stderr, "offset is outside of section bounds\n");
        return ELFIN_SCN_FAILURE;
    }

    strcpy(output, (char *)data->d_buf + rpath_offt);

    return ELFIN_OK;
}

static ELFIN_ERROR elfin_set_rpath(Elf *elf, const char *rpath) {
    assert(elf);

    size_t shdrstr_idx;
    if (elf_getshdrstrndx(elf, &shdrstr_idx) != 0) {
        return ELFIN_SHDR_FAILURE;
    }

    Elf_Scn *scn = NULL;
    while ((scn = elf_nextscn(elf, scn)) != NULL) {
        Elf64_Shdr *shdr = NULL;
        if ((shdr = elf64_getshdr(scn)) == NULL) {
            fprintf(stderr, "getshdr failed: %s\n", elf_errmsg(elf_errno()));
            continue;
        }

        if (shdr->sh_type == SHT_DYNAMIC) {
            break;
        }
    }

    if (scn == NULL) {
        return ELFIN_SCN_FAILURE;
    }

    Elf_Data *dynamic_data = NULL;
    if ((dynamic_data = elf_getdata(scn, dynamic_data)) == NULL) {
        return ELFIN_SCN_FAILURE;
    }

    Elf64_Dyn *dyn_entries = (Elf64_Dyn *)dynamic_data->d_buf;
    size_t count = dynamic_data->d_size / sizeof(Elf64_Dyn);
    Elf64_Addr rpath_offt = 0;
    Elf64_Addr strtab_addr = 0;
    for (size_t i = 0; i < count; ++i) {
        if (dyn_entries[i].d_tag == DT_STRTAB) {
            strtab_addr = dyn_entries[i].d_un.d_ptr;
        }
        if (dyn_entries[i].d_tag == DT_RPATH ||
            dyn_entries[i].d_tag == DT_RUNPATH) {
            rpath_offt = dyn_entries[i].d_un.d_val;
        }
    }

    if (rpath_offt == 0 || strtab_addr == 0) {
        fprintf(stderr, "dynamic entry for rpath of strtab is NULL\n");
        return ELFIN_OK;
    }

    scn = NULL;
    while ((scn = elf_nextscn(elf, scn)) != NULL) {
        Elf64_Shdr *shdr = NULL;
        if ((shdr = elf64_getshdr(scn)) == NULL) {
            fprintf(stderr, "getshdr failed: %s\n", elf_errmsg(elf_errno()));
            continue;
        }

        if (shdr->sh_addr <= strtab_addr &&
            strtab_addr < shdr->sh_addr + shdr->sh_size) {
            break;
        }
    }

    Elf_Data *data = NULL;
    if ((data = elf_getdata(scn, data)) == NULL) {
        fprintf(stderr, "can't get .strtab data\n");
        return ELFIN_SCN_FAILURE;
    }
    if (data->d_size <= rpath_offt) {
        fprintf(stderr, "offset is outside of section bounds\n");
        return ELFIN_SCN_FAILURE;
    }

    strcpy((char *)data->d_buf + rpath_offt, rpath);

    elf_flagdata(data, ELF_C_SET, ELF_F_DIRTY);

    return ELFIN_OK;
}

ELFIN_ERROR elfin_process_file(const char *filename,
                               const elfin_policy_t policy, char output[]) {
    if (elf_version(EV_CURRENT) == EV_NONE) {
        ERROR("ELF library version mismatch");
    }

    int fd = open(filename, O_RDWR);
    if (fd < 0) {
        perror("Can't open input file decriptor");
        ERROR("open failed\n");
    }

    Elf *elf = elf_begin(fd, ELF_C_RDWR, NULL);
    if (elf == NULL) {
        perror(elf_errmsg(elf_errno()));
        ERROR("elf_begin failed\n", close(fd));
    }
    if (elf_flagelf(elf, ELF_C_SET, ELF_F_LAYOUT) < 0) {
        fprintf(stderr, "failed to set layout flags: %s\n", elf_errmsg(-1));
    }

    if (strips_check_magic(elf)) {
        return ELFIN_FAILURE;
    }

    if (policy.set_rpath) {
        ELFIN_ERROR_HANDLE(elfin_set_rpath(elf, policy.rpath));
    }
    if (policy.set_interp) {
        ELFIN_ERROR_HANDLE(elfin_set_interp(elf, policy.interpreter));
    }
    if (policy.print_rpath) {
        ELFIN_ERROR_HANDLE(elfin_get_rpath(elf, output));
    }
    if (policy.print_interp) {
        ELFIN_ERROR_HANDLE(elfin_get_interp(elf, output));
    }

    if (elf_update(elf, ELF_C_WRITE) < 0) {
        ERROR("elf_update failed\n", elf_end(elf), close(fd));
    }

    elf_end(elf);
    close(fd);
    return ELFIN_OK;
}

#define CASE_ENUM_TO_STRING_(error)                                            \
    case error:                                                                \
        return #error
const char *elfin_strerror(const ELFIN_ERROR error) {
    switch (error) {
        CASE_ENUM_TO_STRING_(ELFIN_OK);
        CASE_ENUM_TO_STRING_(ELFIN_FAILURE);
        CASE_ENUM_TO_STRING_(ELFIN_EHDR_FAILURE);
        CASE_ENUM_TO_STRING_(ELFIN_SHDR_FAILURE);
        CASE_ENUM_TO_STRING_(ELFIN_PHNUM_FAILURE);
        CASE_ENUM_TO_STRING_(ELFIN_PHDR_FAILURE);
        CASE_ENUM_TO_STRING_(ELFIN_SCN_FAILURE);
    default:
        return "UNKNOWN_ELFIN_ERROR";
    }
    return "UNKNOWN_ELFIN_ERROR";
}
#undef CASE_ENUM_TO_STRING_
