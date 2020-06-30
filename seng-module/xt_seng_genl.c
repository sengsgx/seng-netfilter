#include <linux/kernel.h>
#include <linux/module.h>

#include <linux/netlink.h>
#include <net/genetlink.h>

#include "xt_seng.h"
#include "xt_seng_metadb.h"
#include "priv_xt_seng_genl.h"

struct nla_policy genl_seng_policy[XT_SENG_ATTR_MAX+1] = {

    [XT_SENG_ATTR_APP] = {
        .type = NLA_BINARY,
        .len = SGX_HASH_SIZE
    },

    [XT_SENG_ATTR_HOST] = {
        .type = NLA_U32,
        .len = sizeof(uint32_t)
    },

    [XT_SENG_ATTR_CAT] = {
        .type = NLA_STRING,
        .len = MAX_CAT_NAME_LENGTH
    },

    [XT_SENG_ATTR_ENC] = {
        .type = NLA_U32,
        .len = sizeof(uint32_t)
    },
};

/**
 * @brief defines generic netlink callbacks
 *
 * This struct defines callbacks and a policy for everything that matches .cmd .
 * */
const struct genl_ops genl_seng_ops[] = {
        {
                .cmd = GENL_XT_SENG_MSG,
                //.policy = genl_seng_policy,     ///< policy
                .doit = seng_nl_recv_msg,       ///< generic netlink callback function to receive messages
                .dumpit = NULL,
        },
};

/**
 * @brief defines a generic netlink multicast group to communicate via generic netlink
 * */
const struct genl_multicast_group genl_seng_mcgrps[] = {
        [GENL_SENG_MCGRP0] = { .name = GENL_SENG_MCGRP_NAME, },
};

struct genl_family genl_seng_family = {
        .name = GENL_SENG_FAMILY_NAME,              ///< family name
        .version = 1,                               ///< family version
        .maxattr = XT_SENG_ATTR_MAX,                ///< amount of attributes
        .netnsok = false,
        .module = THIS_MODULE,                      ///< this module
        .ops = genl_seng_ops,                       ///< operations = callback functions and policy
        .n_ops = ARRAY_SIZE(genl_seng_ops),         ///< amount of operations
        .mcgrps = genl_seng_mcgrps,                 ///< all multicast groups
        .n_mcgrps = ARRAY_SIZE(genl_seng_mcgrps),   ///< amount of multicast groups
};

/**
 * @brief multicasts a given signal via generic netlink
 *
 * Multicasts a given signal to the multicast group via generic netlink.
 *
 * @param[in] signal    the signal to be sent
 *
 * @return 0 for success, all other values for failure
 * */
int send_mc_signal (int signal) {
    void *hdr;
    int res;
    struct sk_buff* skb = genlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);

    if (!skb) {
        printk(KERN_ERR "xt_seng: Unable to allocate skb!");
        return -1;
    }

    hdr = genlmsg_put(skb, 0, 0, &genl_seng_family, GFP_KERNEL, GENL_XT_SENG_MSG);
    if (!hdr) {
        printk(KERN_ERR "xt_seng: Unable to generate msg!");
        goto fail;
    }

    res = nla_put_flag(skb, signal);
    if (res) {
        printk(KERN_ERR "xt_seng: Error setting flag!");
        goto fail;
    }

    genlmsg_end(skb, hdr);
    genlmsg_multicast(&genl_seng_family, skb, 0, 0, GFP_KERNEL);

    if (res < 0) printk(KERN_ERR "xt_seng: Error while sending!\n");

    return 0;

    fail:
        genlmsg_cancel(skb, hdr);
        nlmsg_free(skb);
        return -1;
}

int seng_nl_recv_msg(struct sk_buff *skb, struct genl_info* info) {
    bool status;

    if (info->attrs[XT_SENG_ATTR_ENC] && info->attrs[XT_SENG_ATTR_APP] && info->attrs[XT_SENG_ATTR_HOST] && info->attrs[XT_SENG_ATTR_ADD]) {

        struct enclave* e;
        uint32_t * host_ptr;
        uint32_t * enc_ptr;

        enc_ptr = (uint32_t *) nla_data(info->attrs[XT_SENG_ATTR_ENC]);
        if (!enc_ptr) goto error;

        host_ptr = (uint32_t *) nla_data(info->attrs[XT_SENG_ATTR_HOST]);
        if (!host_ptr) goto error;

        e = add_enclave(*enc_ptr, nla_data(info->attrs[XT_SENG_ATTR_APP]), *host_ptr);


        if (!e) {
            printk(KERN_DEBUG "xt_seng: Something went wrong while adding enclave!");
            goto error;
        }

        if (info->attrs[XT_SENG_ATTR_CAT] && e) {
            status = add_cat_to_app(e->a, (char *) nla_data(info->attrs[XT_SENG_ATTR_CAT]));
            if (!status) {
                printk(KERN_DEBUG "xt_seng: Something went wrong while adding category!");
                goto error;
            }
            #ifdef DEBUG_SENGMOD
            printk(KERN_DEBUG "xt_seng: Added - %i , %i, %s, %s", *enc_ptr, *host_ptr, (char *) nla_data(info->attrs[XT_SENG_ATTR_APP]), (char *) nla_data(info->attrs[XT_SENG_ATTR_CAT]));
            #endif
        } else {
            #ifdef DEBUG_SENGMOD
            printk(KERN_DEBUG "xt_seng: Added - %i , %i, %s", *enc_ptr, *host_ptr, (char *) nla_data(info->attrs[XT_SENG_ATTR_APP]));
            #endif
        }

        goto success;

    } else if (info->attrs[XT_SENG_ATTR_ENC]) {

        if (info->attrs[XT_SENG_ATTR_RMV]) {
            uint32_t * enc_ptr = (uint32_t *) nla_data(info->attrs[XT_SENG_ATTR_ENC]);
            if (!enc_ptr) goto error;

            del_enclave(*enc_ptr);
            #ifdef DEBUG_SENGMOD
            printk(KERN_DEBUG "xt_seng: enclave entry removed - %i \n", *enc_ptr);
            #endif
        } else {
            printk(KERN_DEBUG "xt_seng: unknown operation");
            goto error;
        }
        goto success;

    } else if (info->attrs[XT_SENG_ATTR_APP] && info->attrs[XT_SENG_ATTR_CAT]) {

        struct app* a;
        a = lookup_app_hash(nla_data(info->attrs[XT_SENG_ATTR_APP]));
        status = false;

        if (info->attrs[XT_SENG_ATTR_RMV] && a) {
            status = del_cat_from_app(a, (char *) nla_data(info->attrs[XT_SENG_ATTR_CAT]));
            #ifdef DEBUG_SENGMOD
            printk(KERN_DEBUG "xt_seng: Removed - %s, %s", (char *) nla_data(info->attrs[XT_SENG_ATTR_APP]), (char *) nla_data(info->attrs[XT_SENG_ATTR_CAT]));
            #endif
        } else if (info->attrs[XT_SENG_ATTR_ADD] && a) {
            status = add_cat_to_app(a, (char *) nla_data(info->attrs[XT_SENG_ATTR_CAT]));
            #ifdef DEBUG_SENGMOD
            printk(KERN_DEBUG "xt_seng: Added - %s, %s", (char *) nla_data(info->attrs[XT_SENG_ATTR_APP]), (char *) nla_data(info->attrs[XT_SENG_ATTR_CAT]));
            #endif
        }

        if (!status) {
            printk(KERN_DEBUG "xt_seng: Something went wrong while adding/deleting a category");
            goto error;
        }

        goto success;
    } else if (info->attrs[XT_SENG_ATTR_FLUSH]) {
        //flush all entries upon flush signal
        del_all_enclaves();
        printk(KERN_DEBUG "xt_seng: flushed all entries!");
        goto success;
    }

    success:
        return 0;

    error:
        return -EINVAL;
}
