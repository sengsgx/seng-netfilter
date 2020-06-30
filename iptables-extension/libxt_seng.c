#include <xtables.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <errno.h>

#include "xt_seng.h"

/**
 * @brief command-line options for ip_tables extension
 *
 * Contains all possible command-line options for the ip_tables extension.
 * Will be parsed using getopt.
 * */
static const struct option seng_mt_opts[] = {
	{.name = "src-cat", .has_arg = true, .val = '1'},    ///< category name as source
	{.name = "src-app", .has_arg = true, .val = '2'},    ///< app hash as source
    {.name = "src-host", .has_arg = true, .val = '3'},   ///< host ip as source
    {.name = "dst-cat", .has_arg = true, .val = '4'},    ///< category name as destination
    {.name = "dst-app", .has_arg = true, .val = '5'},    ///< app hash as destination
    {.name = "dst-host", .has_arg = true, .val = '6'},   ///< host ip as destination
	{NULL},
};

/**
 * @brief initializes the match
 *
 * Called to initialize the match, e.g. for standardized values. Does nothing in our case.
 *
 * @param[in] match       The match to be initialized.
 * */
void seng_mt_init(struct xt_entry_match *match){
    //EMPTY
}

/**
 * @brief saves the match in parsable form
 *
 * Called to save the match to stdout in parsable form.
 *
 * @param[in] entry     pointer to the entry (e.g. of type ipt_entry)
 * @param[in] match     contains the actual match to be saved
 * */
void seng_mt4_save(const void *entry, const struct xt_entry_match *match) {
	const struct seng_mt_info *info = (const void *)match->data;

	if (info ->flags & XT_SENG_CAT_SRC) {
		if (info->flags & XT_SENG_CAT_SRC_INV)
			printf("! ");

		printf(" --src-cat %s", info->category_name_src);
	}

	if (info->flags & XT_SENG_APP_SRC) {
		if (info->flags & XT_SENG_APP_SRC_INV)
			printf("! ");

		printf(" --src-app ");
        for (int i=0; i<SGX_HASH_SIZE; i++) {
            printf("%02x", info->app_hash_src[i]);
        }
	}

    if (info->flags & XT_SENG_HOST_SRC) {
        if (info->flags & XT_SENG_HOST_SRC_INV)
            printf("! ");

        printf(" --src-host %s/%d ", xtables_ipaddr_to_numeric(&info->host_src.in), xtables_ipmask_to_cidr(&info->src_subnet.in));
    }

    if (info ->flags & XT_SENG_CAT_DST) {
        if (info->flags & XT_SENG_CAT_DST_INV)
            printf("! ");

        printf(" --dst-cat %s", info->category_name_dst);
    }

    if (info->flags & XT_SENG_APP_DST) {
        if (info->flags & XT_SENG_APP_DST_INV)
            printf("! ");

        printf(" --dst-app");
        for (int i=0; i<SGX_HASH_SIZE; i++) {
            printf("%02x", info->app_hash_dst[i]);
        }
    }

    if (info->flags & XT_SENG_HOST_DST) {
        if (info->flags & XT_SENG_HOST_DST_INV)
            printf("! ");

        printf(" --dst-host %s/%d ", xtables_ipaddr_to_numeric(&info->host_dst.in), xtables_ipmask_to_cidr(&info->dst_subnet.in));
    }
}

/**
 * @brief prints out the match
 *
 * Called to print out the match in human-readable form.
 *
 * @param[in] entry     pointer to the entry (e.g. of type ipt_entry)
 * @param[in] match     contains the actual match to be saved
 * @param[in] numeric   some number
 * */
void seng_mt4_print(const void *entry, const struct xt_entry_match *match, int numeric) {

	const struct seng_mt_info *info = (const void *)match->data;

	if (info->flags & XT_SENG_HOST_SRC) {
		printf(" seng src host IP");

		if (info->flags & XT_SENG_HOST_SRC_INV)
			printf(" !");

        if (numeric) {
		    	printf(" %s%s", xtables_ipaddr_to_numeric(&info->host_src.in), xtables_ipmask_to_numeric(&info->src_subnet.in));
        } else {
		    	printf(" %s%d", xtables_ipaddr_to_anyname(&info->host_src.in), xtables_ipmask_to_cidr(&info->src_subnet.in));
        }
	}

    if (info ->flags & XT_SENG_CAT_SRC) {
        printf(" seng src category");

        if (info->flags & XT_SENG_CAT_SRC_INV)
            printf(" !");

        printf(" %s", info->category_name_src);
    }

    if (info->flags & XT_SENG_APP_SRC) {
        printf(" seng src application");

        if (info->flags & XT_SENG_APP_SRC_INV)
            printf(" !");

        printf(" ");
        for (int i=0; i<SGX_HASH_SIZE; i++) {
            printf("%02x", info->app_hash_src[i]);
        }
    }

    if (info->flags & XT_SENG_HOST_DST) {
        printf(" seng dst host IP");

        if (info->flags & XT_SENG_HOST_DST_INV)
            printf(" !");

        if (numeric) {
        	printf(" %s%s", xtables_ipaddr_to_numeric(&info->host_dst.in), xtables_ipmask_to_numeric(&info->dst_subnet.in));
        } else {
        	printf(" %s%d", xtables_ipaddr_to_anyname(&info->host_dst.in), xtables_ipmask_to_cidr(&info->dst_subnet.in));
        }
    }

    if (info ->flags & XT_SENG_CAT_DST) {
        printf(" seng dst category");

        if (info->flags & XT_SENG_CAT_DST_INV)
            printf(" !");

        printf(" %s", info->category_name_dst);
    }

    if (info->flags & XT_SENG_APP_DST) {
        printf(" seng dst application");

        if (info->flags & XT_SENG_APP_DST_INV)
            printf(" !");

        printf(" ");
        for (int i=0; i<SGX_HASH_SIZE; i++) {
            printf("%02x", info->app_hash_dst[i]);
        }
    }

}

/**
 * @brief parses command-line input
 *
 * Called to parse the command-line input, specified via ip_tables/x_tables.
 *
 * @param[in] c             option value
 * @param[in] argv          arguments
 * @param[in] invert        rule inverter
 * @param[in,out] flags     flags that have already been parsed
 * @param[in] entry         pointer to the entry
 * @param[in,out] match     match, containing what already has been parsed
 *
 * @return true if the function parsed something correctly, false otherwise
 * */
int seng_mt4_parse(int c, char ** argv, int invert, unsigned int * flags, const void * entry, struct xt_entry_match ** match) {
	struct seng_mt_info *info = (void *)(*match)->data;
	struct in_addr *addrs, mask;
	unsigned int naddrs;

	switch (c) {
		case '1': /* --src-cat */
			if (*flags & XT_SENG_CAT_SRC)
				xtables_error(PARAMETER_PROBLEM, "xt_seng: Only use \"--src-cat\" once!");

			*flags |= XT_SENG_CAT_SRC;
			info->flags |= XT_SENG_CAT_SRC;

            if (invert) {
                *flags |= XT_SENG_CAT_SRC_INV;
                info->flags |= XT_SENG_CAT_SRC_INV;
            }

            strncpy(info->category_name_src, optarg, 20);
            info->category_name_src[20] = 0;

			return true;

		case '2': /* --src-app */
            if (*flags & XT_SENG_APP_SRC)
                xtables_error(PARAMETER_PROBLEM, "xt_seng: Only use \"--src-app\" once!");

            if (strlen(optarg) != 64)
                xtables_error(PARAMETER_PROBLEM, "xt_seng: Measurements must be specified as hex strings (64 chars)!");

            *flags |= XT_SENG_APP_SRC;
            info->flags |= XT_SENG_APP_SRC;

            if (invert) {
                *flags |= XT_SENG_APP_SRC_INV;
                info->flags |= XT_SENG_APP_SRC_INV;
            }

            // Convert the 64 chars hex string to 32 binary array
            // (note: strtol() would be better, but parses little endian-aware)
            for (int i=0; i<(SENG_HASH_SIZE-2); i+=2) {
                char tmp[2];
                memcpy(tmp, &optarg[i], 2);
                errno = 0;
                info->app_hash_src[i/2] = strtol(tmp, NULL, 16);
                if (errno != 0)
                    xtables_error(PARAMETER_PROBLEM, "Failed to parse measurement hex string!");
            }

			return true;

	    case '3': /* --src-host */
            if (*flags & XT_SENG_HOST_SRC)
                xtables_error(PARAMETER_PROBLEM, "xt_seng: Only use \"--src-host\" once!");

            *flags |= XT_SENG_HOST_SRC;
            info->flags |= XT_SENG_HOST_SRC;

            if (invert) {
                *flags |= XT_SENG_HOST_SRC_INV;
                info->flags |= XT_SENG_HOST_SRC_INV;
            }

            xtables_ipparse_any(optarg, &addrs, &mask, &naddrs);

            if (addrs == NULL)
                xtables_error(PARAMETER_PROBLEM, "Parse error at %s\n", optarg);

            memcpy(&info->host_src.in, addrs, sizeof(*addrs));

            memcpy(&info->src_subnet.in, &mask, sizeof(mask));

            return true;

        case '4': /* --dst-cat */
            if (*flags & XT_SENG_CAT_DST)
                xtables_error(PARAMETER_PROBLEM, "xt_seng: Only use \"--dst-cat\" once!");

            *flags |= XT_SENG_CAT_DST;
            info->flags |= XT_SENG_CAT_DST;

            if (invert) {
                *flags |= XT_SENG_CAT_DST_INV;
                info->flags |= XT_SENG_CAT_DST_INV;
            }

            strncpy(info->category_name_dst, optarg, 20);
            info->category_name_dst[20] = 0;

            return true;

        case '5': /* --dst-app */
            if (*flags & XT_SENG_APP_DST)
                xtables_error(PARAMETER_PROBLEM, "xt_seng: Only use \"--dst-app\" once!");

            if (strlen(optarg) != 64)
                xtables_error(PARAMETER_PROBLEM, "xt_seng: Measurements must be specified as hex strings (64 chars)!");

            *flags |= XT_SENG_APP_DST;
            info->flags |= XT_SENG_APP_DST;

            if (invert) {
                *flags |= XT_SENG_APP_DST_INV;
                info->flags |= XT_SENG_APP_DST_INV;
            }

            // Convert the 64 chars hex string to 32 binary array
            // (note: strtol() would be better, but parses little endian-aware)
            for (int i=0; i<(SENG_HASH_SIZE-2); i+=2) {
                char tmp[2];
                memcpy(tmp, &optarg[i], 2);
                errno = 0;
                info->app_hash_dst[i/2] = strtol(tmp, NULL, 16);
                if (errno != 0)
                    xtables_error(PARAMETER_PROBLEM, "Failed to parse measurement hex string!");
            }

            return true;

        case '6': /* --dst-host */
            if (*flags & XT_SENG_HOST_DST)
                xtables_error(PARAMETER_PROBLEM, "xt_seng: Only use \"--dst-host\" once!");

            *flags |= XT_SENG_HOST_DST;
            info->flags |= XT_SENG_HOST_DST;

            if (invert) {
                *flags |= XT_SENG_HOST_DST_INV;
                info->flags |= XT_SENG_HOST_DST_INV;
            }

            xtables_ipparse_any(optarg, &addrs, &mask, &naddrs);

            if (addrs == NULL)
                xtables_error(PARAMETER_PROBLEM, "Parse error at %s\n", optarg);

            memcpy(&info->host_dst.in, addrs, sizeof(*addrs));

            memcpy(&info->dst_subnet.in, &mask, sizeof(mask));

            return true;

	}
	return false;
}

/**
 * @brief final check
 *
 * Called to do a final check on a match, that has already been parsed.
 *
 * @param[in] flags     flags of the match to be checked
 * */
void seng_mt_check(unsigned int flags) {
    if (flags == 0)
        xtables_error(PARAMETER_PROBLEM, "xt_seng: You need to specify something.");

    uint8_t src_counter = 0;
    uint8_t dst_counter = 0;

    if (flags & XT_SENG_CAT_SRC) src_counter += 1;
    if (flags & XT_SENG_CAT_DST) dst_counter += 1;
    if (flags & XT_SENG_APP_SRC) src_counter += 1;
    if (flags & XT_SENG_APP_DST) dst_counter += 1;
    if (flags & XT_SENG_HOST_SRC) src_counter += 1;
    if (flags & XT_SENG_HOST_DST) dst_counter += 1;

    if (src_counter == 0 && dst_counter == 0) xtables_error(PARAMETER_PROBLEM, "xt_seng: You need to specify something.");

}

/**
 * @brief prints usage info
 *
 * Called to print usage info for the extension.
 * */
void seng_mt_help(void) {
	printf(
			"    seng match options:\n"
			"    [!] --src-cat  <name>      Match seng category name on src ip\n"
			"    [!] --src-app  <hash>      Match seng app hash on src ip\n"
            "    [!] --src-host <addr>      Match seng host ipv4 address on src ip\n"
            "    [!] --dst-cat  <name>      Match seng category name on dst ip\n"
            "    [!] --dst-app  <hash>      Match seng app hash on dst ip\n"
            "    [!] --dst-host <addr>      Match seng host ipv4 address on dst ip\n"
            "\n"
    );
}

/**
 * @brief struct to register against ip_tables/x_tables
 *
 * This struct is used to register against ip_tables/x_tables.
 * */
static struct xtables_match seng_mt_reg = {
        .version = XTABLES_VERSION,                                 ///< x_tables version
        .name = "seng",                                             ///< extension name
        .revision = 0,                                              ///< extension version
        .family = NFPROTO_IPV4,                                     ///< family (here: ipv4)
        .size = XT_ALIGN(sizeof(struct seng_mt_info)),              ///< rule size in kernel module
        .userspacesize = XT_ALIGN(sizeof(struct seng_mt_info)),     ///< rule size in user space (e.g. this library)
        .help = seng_mt_help,                                       ///< function which prints out usage info
        .init = seng_mt_init,                                       ///< function which initializes the match
        .parse = seng_mt4_parse,                                    ///< function which parses command-line input
        .final_check = seng_mt_check,                               ///< function which does the final check
        .print = seng_mt4_print,                                    ///< function which prints out the match
        .save = seng_mt4_save,                                      ///< function that saves the match in parsable form to stdout
        .extra_opts = seng_mt_opts,                                 ///< pointer to list of additional command-line options
};

/**
 * @brief registers matching library against ip_tables/x_tables
 * */
void _init(void) {
	xtables_register_match(&seng_mt_reg);
}
