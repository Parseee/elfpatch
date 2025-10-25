#pragma once

#include <elf.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define ELFIN_ERROR_HANDLE(call_func, ...)                                     \
    do {                                                                       \
        ELFIN_ERROR error_handler = call_func;                                 \
        if (error_handler) {                                                   \
            fprintf(stderr,                                                    \
                    "Error calling " #call_func " on line %d,"                 \
                    " file %s. error is %s\n",                                 \
                    __LINE__, __FILE__, elfin_strerror(error_handler));        \
            __VA_ARGS__;                                                       \
            return error_handler;                                              \
        }                                                                      \
    } while (0)

#define ERROR(msg, ...)                                                        \
    do {                                                                       \
        fprintf(stderr, msg);                                                  \
        __VA_ARGS__;                                                           \
        return ELFIN_FAILURE;                                                  \
    } while (0)

typedef enum {
    ELFIN_OK,
    ELFIN_FAILURE,
    ELFIN_EHDR_FAILURE,
    ELFIN_SHDR_FAILURE,
    ELFIN_PHNUM_FAILURE,
    ELFIN_PHDR_FAILURE,
    ELFIN_SCN_FAILURE
} ELFIN_ERROR;

typedef struct {
    bool set_rpath;
    bool set_interp;
    bool print_rpath;
    bool print_interp;
    char *rpath;
    char *interpreter;
} elfin_policy_t;

bool elfin_check_magic(Elf32_Ehdr *hdr);

ELFIN_ERROR elfin_process_file(const char *filename,
                               const elfin_policy_t policy, char output[]);

const char *elfin_strerror(const ELFIN_ERROR error);
