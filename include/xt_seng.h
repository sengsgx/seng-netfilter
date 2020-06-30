#ifndef SENG_XT_SENG_H
#define SENG_XT_SENG_H

#include <linux/netfilter.h>

/**
 * @def DEBUG_SENGMOD
 * @brief enables debugging prints to dmesg
 * */
#define DEBUG_SENGMOD

/**
 * @mainpage General
 *
 * This project is a proof of concept to integrate SENG into netfilter/xtables and iptables.
 * The Doxygen documentation provides an API overview and detailed per-function descriptions.
 * See the README file for general information (compilation, usage) and a high-level description
 * of the project.
 * */
 
/**
 * @def SENG_HASH_SIZE
 * @brief maximum hash length
 *
 * Used internally, because @link seng_mt_info @endlink is of static size.
 *
 * @def MAX_CAT_NAME_LENGTH
 * @brief maximum category name length
 *
 * Used internally, because @link seng_mt_info @endlink is of static size.
 * */
#define SENG_HASH_SIZE (64 + 1)
#define SGX_HASH_SIZE 32 // TODO: include <sgx_report.h>
#define MAX_CAT_NAME_LENGTH (20 + 1)
//TODO: remove this


/**
 * @brief flags used by the ip_tables rules
 *
 * These flag are used in by @link seng_mt_info @endlink, to indicate the content of the rule created by ip_tables, that is then passed to the kernel module.
 *
 * Uses 7 bits.
 * */
enum flags {
    XT_SENG_APP_SRC       = 1 << 0, ///< rule has source app hash set
    XT_SENG_APP_SRC_INV   = 1 << 1, ///< source app hash inverter
    XT_SENG_CAT_SRC       = 1 << 2, ///< rule has source category name set
    XT_SENG_CAT_SRC_INV   = 1 << 3, ///< source category name inverter
    XT_SENG_HOST_SRC      = 1 << 4, ///< rule has source host ip set
    XT_SENG_HOST_SRC_INV  = 1 << 5, ///< source host ip inverter
    XT_SENG_APP_DST       = 1 << 6, ///< rule has destination app hash set
    XT_SENG_APP_DST_INV   = 1 << 7, ///< destination app hash inverter
    XT_SENG_CAT_DST       = 1 << 8, ///< rule has destination category name set
    XT_SENG_CAT_DST_INV   = 1 << 9, ///< destination category inverter
    XT_SENG_HOST_DST      = 1 << 10, ///< rule has destination host ip set
    XT_SENG_HOST_DST_INV  = 1 << 11, ///< destination host ip inverter
};

/**
 * @brief rule info
 *
 * This struct contains rule info, that is created by the ip_tables library and then passed to the kernel module.
 * */
struct seng_mt_info {
    uint8_t app_hash_src[SGX_HASH_SIZE];             ///< source app hash
    char category_name_src[MAX_CAT_NAME_LENGTH];   ///< source category name
    union nf_inet_addr host_src;                   ///< source host ip
    union nf_inet_addr src_subnet;                 ///< source subnet

    uint8_t app_hash_dst[SGX_HASH_SIZE];             ///< destination app hash
    char category_name_dst[MAX_CAT_NAME_LENGTH];   ///< destination category name
    union nf_inet_addr host_dst;                   ///< destination host ip
    union nf_inet_addr dst_subnet;                 ///< destination subnet

    uint16_t flags;                                 ///< flags that indicate, which info is contained in this struct
};

#endif
