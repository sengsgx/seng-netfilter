#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/module.h>

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter/x_tables.h>

#include <linux/netlink.h>
#include <net/genetlink.h>

#include <linux/ip.h> //iphdr
#include <linux/slab.h> //kmalloc
#include <linux/string.h> //strcmp, strcpy

#include "xt_seng.h"
#include "priv_xt_seng_genl.h"
#include "xt_seng_metadb.h"

MODULE_LICENSE("AGPL");
MODULE_AUTHOR("Leon Trampert <leon.trampert@cispa.saarland>"); // student assistant
MODULE_AUTHOR("Fabian Schwarz <fabian.schwarz@cispa.saarland>"); // lead author
MODULE_AUTHOR("Christian Rossow <christian.rossow@cispa.saarland>"); // supervisor
MODULE_DESCRIPTION("SENG extension for iptables");

/**
 * @brief decides if a packet matches a rule (match) or not
 *
 * Will be called with packet and rule info to decide, if the packet matches the rule or not. Does a lookup
 * of the destination and source ip of the arriving packet in the hash table. If the database is currently not ready,
 * the incoming packets will be dropped by this function.
 *
 * By setting hotdrop in the xt_action_param to true, the packet will be dropped.
 *
 * @param[in] skb       socket buffer containing the arriving packet
 * @param[in,out] xap   contains the rule info and provides the hotdrop functionality
 *
 * @return true upon match, false otherwise
 * */
bool seng_mt (const struct sk_buff *skb, struct xt_action_param* xap) {
    const struct iphdr *iph;
    const struct seng_mt_info *info;
    struct enclave *src_enc, *dst_enc;
    struct app *src_app, *dst_app;
    uint8_t searched = 0;
    uint8_t found = 0;
    uint8_t match = 0;
    uint32_t inv_flag = 0;

    //get rule info
     info = xap->matchinfo;

    //setting hotdrop to true will drop the packet
    if(!skb) {
        printk(KERN_ERR "xt_seng: No skb!");
        xap->hotdrop = true;
        return false;
    }

    //get packet
     iph = ip_hdr(skb);

    //find enclaves
    src_enc = find_enclave(iph->saddr);
    dst_enc = find_enclave(iph->daddr);

    src_app = NULL;
    dst_app = NULL;

    if (src_enc)
        src_app = src_enc->a;
    if (dst_enc)
        dst_app = dst_enc->a;

    /* Search the enclave entry for the stuff specified in the rule. */
    if (info->flags & XT_SENG_APP_SRC) {
        searched += 1;
        if (src_app) {
            match = match_app(src_app, info->app_hash_src);
            inv_flag = !!(XT_SENG_APP_SRC_INV & info->flags);
            if ((match && !inv_flag) || (!match && inv_flag)) found += 1;
        }
    }

    if (info->flags & XT_SENG_APP_DST) {
        searched += 1;
        if (dst_app) {
            match = match_app(dst_app, info->app_hash_dst);
            inv_flag = !!(XT_SENG_APP_DST_INV & info->flags);
            if ((match && !inv_flag) || (!match && inv_flag)) found += 1;
        }
    }

    if (info->flags & XT_SENG_CAT_SRC) {
        searched += 1;
        if (src_app) {
            match = match_category(src_app, info->category_name_src);
            inv_flag = !!(XT_SENG_CAT_SRC_INV & info->flags);
            if ((match && !inv_flag) || (!match && inv_flag)) found += 1;
        }
    }

    if (info->flags & XT_SENG_CAT_DST) {
        searched += 1;
        if (dst_app) {
            match = match_category(dst_app, info->category_name_dst);
            inv_flag = !!(XT_SENG_CAT_DST_INV & info->flags);
            if ((match && !inv_flag) || (!match && inv_flag)) found += 1;
        }
    }

    if (info->flags & XT_SENG_HOST_SRC) {
        searched += 1;
        if (src_enc) {
            match = (info->host_src.ip & info->src_subnet.ip) == (src_enc->host_ip & info->src_subnet.ip);
            inv_flag = !!(XT_SENG_HOST_SRC_INV & info->flags);
            if ((match && !inv_flag) || (!match && inv_flag)) {
                found += 1;
            }
        }
    }

    if (info->flags & XT_SENG_HOST_DST) {
        searched += 1;
        if (dst_enc) {
            match = (info->host_dst.ip & info->dst_subnet.ip) == (dst_enc->host_ip & info->dst_subnet.ip);
            inv_flag = !!(XT_SENG_HOST_DST_INV & info->flags);
            if ((match && !inv_flag) || (!match && inv_flag)) {
                found += 1;
            }
        }
    }

    //positive check: all found and positive rule -> packet matches
    if (searched == found) {
        return true;
    }

    //packet does not match rule
    return false;
}

/**
 * @brief checks a newly added rule
 *
 * Will be called to check a newly added rule for correctness.
 * Rejects if not a single flag is set in the rule info.
 *
 * @param[in] xmp   contains the rule info
 *
 * @return 0 accepts the rule, any other value rejects the rule
 * */
int seng_mt_check(const struct xt_mtchk_param * xmp) {
    const struct seng_mt_info *info = xmp->matchinfo;

    printk(KERN_DEBUG "xt_seng: Added a rule with -m seng in the %s table\n", xmp->table);

    //check for useless input -> no relevant flag set
    if (!(info->flags & (XT_SENG_APP_DST | XT_SENG_CAT_DST | XT_SENG_HOST_DST | XT_SENG_APP_SRC | XT_SENG_CAT_SRC | XT_SENG_HOST_SRC))) {
        printk(KERN_INFO "xt_seng: Useless, thus not added");
        return -EINVAL;
    }

    return 0;
}

/**
 * @brief called upon rule removal
 *
 * Will be called, once a rule with match in this module was removed in ip_tables.
 * Does nothing but a debug print.
 *
 * @param[in] xmp   contains the rule info
 * */
void seng_mt_destroy(const struct xt_mtdtor_param * xmp) {
    printk(KERN_DEBUG "xt_seng: Some rule with seng match was removed.");
}

/**
 * @brief struct used to register against ip_tables
 *
 * This struct is used to register the kernel module against ip_tables.
 * */
struct xt_match seng_mt4_reg = {
        .name 			= "seng",                                ///< extension name
        .revision 	    = 0,                                     ///< extension version
        .family 		= AF_INET,                               ///< family (here: ipv4)
        .match 			= seng_mt,                               ///< match function, called to see if packet matches rule
        .checkentry     = seng_mt_check,                         ///< check function, called upon addition of seng rules
        .destroy 		= seng_mt_destroy,                       ///< destroy function, called upon removal of seng rules
        .me 			= THIS_MODULE,                           ///< module identifier
        .matchsize	    = XT_ALIGN(sizeof(struct seng_mt_info)), ///< rule size
};

/**
 * @brief kernel module init
 *
 * Called upon module insertion. Registers against ip_tables and generic netlink.
 *
 * @return status code
 * */
int seng_mt_init(void) {
    int result;
    if ((result = xt_register_match(&seng_mt4_reg)) < 0) printk(KERN_ERR "xt_seng: Registering against ip_tables failed.\n");
    genl_register_family(&genl_seng_family);
    printk(KERN_INFO "xt_seng: Insertion successful.\n");
    return result;
}

/**
 * @brief kernel module exit
 *
 * Called upon module removal. Unregisters against ip_tables and generic netlink.
 * Also cleans up the remainings of the hash table.
 * */
void seng_mt_exit(void) {
    xt_unregister_match(&seng_mt4_reg);
    genl_unregister_family(&genl_seng_family);
    del_all_enclaves();
    printk(KERN_INFO "xt_seng: Removal successful.\n");
}

///kernel module init
module_init(seng_mt_init);
///kernel module exit
module_exit(seng_mt_exit);
