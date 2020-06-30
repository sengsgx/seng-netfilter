#include "seng_netfilter.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <unistd.h>
#include <assert.h>

#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

struct cb_data {
    unsigned int removed;
    uint32_t enclave_ip;
};

static int cb(enum nf_conntrack_msg_type type,
              struct nf_conntrack *ct,
              void *data)
{
    int ret;
    struct cb_data *dp = (struct cb_data *)data;
    struct nfct_handle *h;

    uint32_t src_ip = nfct_get_attr_u32(ct, ATTR_IPV4_SRC);
    uint32_t dst_ip = nfct_get_attr_u32(ct, ATTR_IPV4_DST);

    if (src_ip != dp->enclave_ip && dst_ip != dp->enclave_ip)
        goto end;

    h = nfct_open(CONNTRACK, 0);
    if (!h) {
        perror("nfct_open");
        return -1;
    }

    // TODO: re-using query handle worked, but returned -1
    ret = nfct_query(h, NFCT_Q_DESTROY, ct);
    if (ret == -1)
        printf("SENG: error in deletion of conntrack entries for %d : (%d)(%s)\n", dp->enclave_ip, ret, (char *) strerror(errno));
    else
        dp->removed += 1;

    nfct_close(h);

end:
    return NFCT_CB_CONTINUE;
}

static int change_privs(uid_t new_euid, gid_t new_egid, bool drop) {
    uid_t old_euid = geteuid();
    gid_t old_egid = getegid();
    // already done
    if (old_euid == new_euid && old_egid == new_egid) return 0;

//    printf("change_privs: %d,%d --> %d,%d\n", old_euid, old_egid, new_euid, new_egid);
    if (!drop) {
        if( seteuid(new_euid) < 0 ) { fprintf(stderr, "Failed to swap privs to %d", new_euid); return -1; }
        if( setegid(new_egid) < 0 ) { int ret; do {ret = seteuid(old_euid); perror("change_privs");} while(ret < 0); return -1; }
    } else {
        if( setegid(new_egid) < 0 ) { fprintf(stderr, "Failed to drop privs to %d", new_egid); return -1; }
        if( seteuid(new_euid) < 0 ) { int ret; do {ret = setegid(old_egid); perror("change_privs");} while(ret < 0); return -1; }
    }
    return 0;
}

static int _delete_conntrack_entries (uint32_t pEnclave_ip);

int delete_conntrack_entries(uint32_t enclave_ip) {
        int result;
        uid_t old_euid = geteuid();
        gid_t old_egid = getegid();

        // TODO: use CAP_NET_ADMIN instead of root privs.
        // elevate to root
        if(change_privs(0,0,false) != 0) return -1;
        assert(geteuid() == 0 && getegid() == 0);

        // actual conntrack code
        result = _delete_conntrack_entries(enclave_ip);

        // revert privs
        if(change_privs(old_euid,old_egid,true) != 0) {
            fprintf(stderr, "Failed to revert SENG Server privileges to %d, %d!\n", old_euid, old_egid);
        }

        return result;
    }

static int _delete_conntrack_entries (uint32_t pEnclave_ip)
{
    int ret;
    u_int32_t family = AF_INET;
    struct nfct_handle *h;

    struct cb_data d;
    d.enclave_ip = pEnclave_ip;
    d.removed = 0;

    h = nfct_open(CONNTRACK, 0);
    if (!h) {
        perror("nfct_open");
        return -1;
    }

    nfct_callback_register(h, NFCT_T_ALL, cb, &d);
    ret = nfct_query(h, NFCT_Q_DUMP, &family);

    if (ret == -1)
        printf("SENG: error during receive of conntrack entries for %d : (%d)(%s)\n", d.enclave_ip, ret, (char *) strerror(errno));

    nfct_close(h);

    return ret == -1 ? ret : d.removed;
}