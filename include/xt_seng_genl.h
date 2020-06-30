#ifndef SENG_XT_SENG_GENL_H
#define SENG_XT_SENG_GENL_H

/**
 * @def GENL_SENG_MCGRP_NAME
 * @brief generic netlink multicast group name
 *
 * Used by generic netlink to send messages to application.
 *
 * @def GENL_SENG_FAMILY_NAME
 * @brief generic netlink family name
 *
 * Used by generic netlink to send messages to application.
 * */
#define GENL_SENG_MCGRP_NAME "seng_mcgrp"
#define GENL_SENG_FAMILY_NAME "seng_family"

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
#define SENG_HASH_SIZE (64 + 1) //256 bit -> uint8_t [32]
#define SGX_HASH_SIZE 32 // TODO: use sgx header
#define MAX_CAT_NAME_LENGTH (20 + 1)


/**
 * @brief used to define different message types for different callback functions etc.
 *
 * Here we only use one.
 * */
enum {
    GENL_XT_SENG_UNSPEC,		///< must not use element 0
    GENL_XT_SENG_MSG,           ///< normal message protocol
};

/**
 * @brief generic netlink attributes
 *
 * Used by generic netlink structure messages.
 * No operation flag set implies the add operation.
 *
 * */
enum genl_seng_attrs {
    XT_SENG_ATTR_UNSPEC,		///< unused - must not use element 0
    XT_SENG_ATTR_APP,           ///< contains app identifier
    XT_SENG_ATTR_CAT,           ///< contains category identifier
    XT_SENG_ATTR_HOST,          ///< contains host identifier
    XT_SENG_ATTR_ENC,           ///< contains enclave identifier
    XT_SENG_ATTR_ADD,           ///< operation add - will add given entry
    XT_SENG_ATTR_RMV,           ///< operation remove - will remove given entry
    XT_SENG_ATTR_FLUSH,         ///< signal - operation flush - will flush all enclave entries
    __XT_SENG_ATTR__MAX,        ///< used to calculate amount of attributes
};

///Total amount of generic netlink attributes
#define XT_SENG_ATTR_MAX (__XT_SENG_ATTR__MAX - 1)

/**
 * @brief defines all generic netlink multicast groups
 * */
enum genl_seng_multicast_groups {
    GENL_SENG_MCGRP0,   ///< the single multicast group in our case
};

#endif
