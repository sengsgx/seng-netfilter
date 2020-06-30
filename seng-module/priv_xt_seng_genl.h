#ifndef SENG_PRIV_XT_SENG_GENL_H
#define SENG_PRIV_XT_SENG_GENL_H

#include "xt_seng_genl.h"
#include <net/netlink.h> // struct nla_policy

/**
 * @brief genl kernel module callback function
 *
 * Will be executed, when the kernel module receives a generic netlink message.
 * Handles one of those scenarios, depending on the flags that are set:
 * * adds/removes enclaves
 * * flushes all entries
 * * sets the database_ready variable to ready
 * * sets the database_ready variable to not ready
 *
 * @param[in] skb   socket buffer
 * @param[in] info  message info
 *
 * @return netlink status code
 * */
int seng_nl_recv_msg(struct sk_buff *skb, struct genl_info* info);

extern struct genl_family genl_seng_family;

/**
 * @brief generic netlink policy
 *
 * This policy defines size and type of the different @link genl_seng_attrs generic netlink attributes @endlink,
 * that are used by the generic netlink communication between seng_app and the kernel module.
*/
extern struct nla_policy genl_seng_policy[XT_SENG_ATTR_MAX+1];

#endif
