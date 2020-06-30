#include <stdio.h> //printf
#include <string.h> //strcpy
#include <getopt.h> //getopt

#include "seng_netfilter_api.h"


/// Prints some help.
void print_help() {
    printf(""
           "\n"
           "SENG application - usage: \n"
           "========================= \n"
           "-h / --help\n"
           "    prints this help\n"
           "\n"
           "-t / --test\n"
           "    runs a test \n"
           "\n"
           "-f / --flush\n"
           "    sends the flush signal to the kernel, clearing all data inside the module\n"
           "\n");
}

int run_test(void) {
    printf("Running tests...\n\n");
    printf("Checkpoint a\n");
    add_enclave_ack(134744072, "app_hash_a", 134744072, "category_a");
    printf("Checkpoint b\n");
    add_enclave_ack(3232235564, "app_hash_a", 134744072, "category_a");
    printf("Checkpoint c\n");
    add_enclave_ack(2130706433, "app_hash_b", 134744072, "category_a");
    printf("Checkpoint d\n");
    cat_to_app_ack("app_hash_a", "category_b");
    printf("Checkpoint e\n");
    remove_cat_from_app_ack("app_hash_b", "category_a");
    printf("Checkpoint f\n");
    remove_enclave_ack(2130706433);
    printf("Checkpoint g\n");
    remove_enclave_ack(3232235564);
    printf("Checkpoint h\n");
    printf("\nRemember to flush :)\n");
    return 0;
}

/**
 * @brief app main function
 *
 * First parses the command line arguments.
 *
 * Options are (ordered by priority) :
 * + - --help / -h for help (aborts after printing help)
 * + - --flush / -f to send a flush signal (aborts after sending signal)
 * + - --test / -t  to run a test
 *
 * @param[in] argc amount of command line arguments
 * @param[in] argv array of command line arguments
 * @return EXIT_SUCCESS or EXIT_FAILURE
 * */
int main(int argc, char* argv[]) {

    /* Parse command line input. */

    static const struct option long_options[] =
            {
                    { "test", no_argument, 0, 't' },
                    { "flush", no_argument, 0, 'f' },
                    { "help", no_argument, 0, 'h' },
                    0
            };

    char help = 0;
    char flush = 0;
    char test = 0;

    while (1) {
        int index = -1;
        struct option * opt = 0;
        int result = getopt_long(argc, argv, "tfh", long_options, &index);
        if (result == -1) break; /* end of list */
        switch (result) {
            case 'h': /* help */
                help = 1;
                break;
            case 't': /* database <path> */
                test = 1;
                break;
            case 'f': /* flush */
                flush = 1;
                break;
            default: /* unknown */
                break;
        }
    }

    if (help) {
        print_help();
        return 0;
    }

    if (flush) {
        int ret;
        prep_nl_sock();
        ret = flush_module();
        cleanup_nl_sock();
        return ret;
    }

    if (test) {
        prep_nl_sock();
        run_test();
        cleanup_nl_sock();
        return 0;
    }

    printf("SENG: specify something... Maybe try ./seng_app -h\n");

    return 0;

}
