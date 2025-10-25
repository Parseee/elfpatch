#include <getopt.h>
#include <memory.h>
#include <stdbool.h>
#include <stdio.h>

#include "elfin/lib_elfin.h"

void print_usage(void) {
    fprintf(stderr, "usage: elfpatch "
                    "[--set-rpath <file> <rpath>] \n"
                    "| [--set-interpreter <file> <interpreter>]\n"
                    "| [--print-rpath <file>]\n"
                    "| [--print-interpreter <file>]\n");
}

elfin_policy_t manage_options(int argc, char **argv, char **filename) {
    elfin_policy_t policy = {
        .set_rpath = false,
        .set_interp = false,
        .print_rpath = false,
        .print_interp = false,
        .rpath = NULL,
        .interpreter = NULL,
    };

    static struct option long_options[] = {
        {"set-rpath", no_argument, 0, 'r'},
        {"set-interpreter", no_argument, 0, 'i'},
        {"print-rpath", no_argument, 0, 'p'},
        {"print-interpreter", no_argument, 0, 't'},
        {0, 0, 0, 0}};

    if (argc < 2) {
        print_usage();
        exit(EXIT_FAILURE);
    }

    int opt;
    int option_index = 0;

    opt = getopt_long(argc, argv, "ript", long_options, &option_index);
    if (opt == -1) {
        print_usage();
        exit(EXIT_FAILURE);
    }

    switch (opt) {
    case 'r': // --set-rpath
        if (optind + 1 >= argc) {
            fprintf(stderr, "Error: --set-rpath requires <file> and <rpath>\n");
            print_usage();
            exit(EXIT_FAILURE);
        }
        policy.set_rpath = true;
        *filename = argv[optind];
        policy.rpath = argv[optind + 1];
        break;

    case 'i': // --set-interpreter
        if (optind + 1 >= argc) {
            fprintf(
                stderr,
                "Error: --set-interpreter requires <file> and <interpreter>\n");
            print_usage();
            exit(EXIT_FAILURE);
        }
        policy.set_interp = true;
        *filename = argv[optind];
        policy.interpreter = argv[optind + 1];
        break;

    case 'p': // --print-rpath
        if (optind >= argc) {
            fprintf(stderr, "Error: --print-rpath requires <file>\n");
            print_usage();
            exit(EXIT_FAILURE);
        }
        policy.print_rpath = true;
        *filename = argv[optind];
        break;

    case 't': // --print-interpreter
        if (optind >= argc) {
            fprintf(stderr, "Error: --print-interpreter requires <file>\n");
            print_usage();
            exit(EXIT_FAILURE);
        }
        policy.print_interp = true;
        *filename = argv[optind];
        break;

    default:
        print_usage();
        exit(EXIT_FAILURE);
    }

    return policy;
}

int main(int argc, char **argv) {
    char *filename = NULL;
    elfin_policy_t policy = manage_options(argc, argv, &filename);

    char output[4096];
    memset(output, 0, 4096);
    ELFIN_ERROR_HANDLE(elfin_process_file(filename, policy, output));

    if (policy.print_interp || policy.print_rpath) {
        printf("%s\n", output);
    }
}
