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
        Elf_Scn *scn = NULL; // Start from first section
        Elf_Data *data = NULL;

        // Find the section containing this segment
        while ((scn = elf_nextscn(elf, scn)) != NULL) {
            Elf64_Shdr *shdr = NULL;
            if ((shdr = elf64_getshdr(scn)) == NULL) {
                fprintf(stderr, "getshdr failed: %s\n",
                        elf_errmsg(elf_errno()));
                continue;
            }

            // Check if this section contains the interpreter data
            if (shdr->sh_offset <= phdr_entries[i].p_offset &&
                shdr->sh_offset + shdr->sh_size >=
                    phdr_entries[i].p_offset + phdr_entries[i].p_filesz) {
                data = elf_getdata(scn, NULL);
                if (data && data->d_buf) {
                    // *output = (char *)data->d_buf +
                    //           (phdr_entries[i].p_offset - shdr->sh_offset);
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

static ELFIN_ERROR elfin_get_rpath(Elf *elf, char output[]) {
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
        return ELFIN_SHDR_FAILURE;
    }

    Elf_Data *data = NULL;
    if ((data = elf_getdata(scn, data)) == NULL) {
        return ELFIN_SCN_FAILURE;
    }

    Elf64_Dyn *dyn_entries = (Elf64_Dyn *)data->d_buf;
    size_t count = data->d_size / sizeof(Elf64_Dyn);
    Elf64_Dyn *rpath_dyn = NULL;
    for (size_t i = 0; i < count; ++i) {

        if (dyn_entries[i].d_tag == DT_RPATH ||
            dyn_entries[i].d_tag == DT_RUNPATH) {
            rpath_dyn = &dyn_entries[i];
            break;
        }
    }

    if (rpath_dyn == NULL) {
        output[0] = '\0';
        return ELFIN_OK;
    }
    size_t offset = rpath_dyn->d_un.d_val;

    while ((scn = elf_nextscn(elf, scn)) != NULL) {
        Elf64_Shdr *shdr = NULL;
        if ((shdr = elf64_getshdr(scn)) == NULL) {
            fprintf(stderr, "getshdr failed: %s\n", elf_errmsg(elf_errno()));
            continue;
        }

        if (shdr->sh_type == SHT_STRTAB &&
            (shdr->sh_flags & SHF_ALLOC)) { // .dynstr has ALLOC flag
            Elf_Data *data = elf_getdata(scn, NULL);
            if (data && offset < data->d_size) {
                strcpy(output, (char *)data->d_buf + offset);
                break;
            }
        }
    }

    return ELFIN_OK;
}

// static ELFIN_ERROR elfin_set_rpath(Elf *elf, char *rpath) {
//     size_t shdrstr_idx;
//     if (elf_getshdrstrndx(elf, &shdrstr_idx) != 0) {
//         return ELFIN_SHDR_FAILURE;
//     }

//     Elf_Scn *scn = NULL;
//     while ((scn = elf_nextscn(elf, scn)) != NULL) {
//         Elf64_Shdr *shdr = NULL;
//         if ((shdr = elf64_getshdr(scn)) == NULL) {
//             fprintf(stderr, "getshdr failed: %s\n", elf_errmsg(elf_errno()));
//             continue;
//         }

//         if (shdr->sh_type == SHT_DYNAMIC) {
//             break;
//         }
//     }

//     if (scn == NULL) {
//         return ELFIN_SHDR_FAILURE;
//     }

//     Elf_Data *data = NULL;
//     if ((data = elf_getdata(scn, data)) == NULL) {
//         return ELFIN_SCN_FAILURE;
//     }

//     size_t count = data->d_size / sizeof(Elf64_Dyn);
//     Elf64_Dyn *dyn_entries = (Elf64_Dyn *)data->d_buf;

//     // Find the DT_NULL terminator
//     Elf64_Dyn *null_entry = NULL;
//     for (size_t i = 0; i < count; ++i) {
//         if (dyn_entries[i].d_tag == DT_NULL) {
//             null_entry = &dyn_entries[i];
//             break;
//         }
//     }

//     if (!null_entry) {
//         printf("No DT_NULL terminator found - dynamic section may be
//         full\n"); return ELFIN_SCN_FAILURE;
//     }

//     // Check if we have space for a new entry
//     // We need to replace DT_NULL with our entry AND add a new DT_NULL

//     // For now, let's just replace the DT_NULL (simpler approach)
//     null_entry->d_tag = DT_RPATH;
//     null_entry->d_un.d_val = /* string table offset of your new rpath */;

//     printf("Added new %s entry\n", use_runpath ? "DT_RUNPATH" : "DT_RPATH");
//     return null_entry;
// }

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
    if (elf_flagelf(elf, ELF_C_SET, ELF_F_LAYOUT) == 0) {
        fprintf(stderr, "Failed to set LAYOUT flag for ELF file: %s\n",
                elf_errmsg(-1));
        return ELFIN_FAILURE;
    }

    if (policy.set_rpath) {
        // ELFIN_ERROR_HANDLE(elfin_set_rpath(elf, policy.rpath));
    }
    if (policy.set_interp) {
    }
    if (policy.print_rpath) {
        ELFIN_ERROR_HANDLE(elfin_get_rpath(elf, output));
    }
    if (policy.print_interp) {
        ELFIN_ERROR_HANDLE(elfin_get_interp(elf, output));
    }

    // ELFIN_ERROR_HANDLE(elfin_edit_sections(elf, policy));

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