#include <errno.h> //ENOMEM
#include <assert.h>
#include <netlink/genl/ctrl.h> //genl
#include <netlink/genl/genl.h> //genl

#include "seng_netfilter.h"
#include "xt_seng_genl.h"

struct nl_sock* nlsock;

struct nla_policy genl_seng_policy[XT_SENG_ATTR_MAX+1] = {

        [XT_SENG_ATTR_APP] = {
                .type = NLA_BINARY,
                .maxlen = SGX_HASH_SIZE
        },

        [XT_SENG_ATTR_HOST] = {
                .type = NLA_U32,
                .maxlen = sizeof(uint32_t)
        },

        [XT_SENG_ATTR_CAT] = {
                .type = NLA_STRING,
                .maxlen = MAX_CAT_NAME_LENGTH
        },

        [XT_SENG_ATTR_ENC] = {
                .type = NLA_U32,
                .maxlen = sizeof(uint32_t)
        },
};

int prep_nl_sock (void) {
    int family_id, grp_id;

    nlsock = nl_socket_alloc();
    if(!nlsock) {
        fprintf(stderr, "SENG: Unable to alloc nl socket!\n");
        return -ENOMEM;
    }

    /* connect to genl */
    if (genl_connect(nlsock)) {
        fprintf(stderr, "SENG: Unable to connect to genl!\n");
        goto exit_err;
    }

    /* resolve the generic nl family id*/
    family_id = genl_ctrl_resolve(nlsock, GENL_SENG_FAMILY_NAME);
    if(family_id < 0){
        fprintf(stderr, "SENG: Unable to resolve family name!\n");
        goto exit_err;
    }

    grp_id = genl_ctrl_resolve_grp(nlsock, GENL_SENG_FAMILY_NAME, GENL_SENG_MCGRP_NAME);

    if (nl_socket_add_membership(nlsock, grp_id)) {
        fprintf(stderr, "Unable to join group %u!\n", grp_id);
        goto exit_err;
    }

    return EXIT_SUCCESS;

    exit_err:
    nl_socket_free(nlsock); // this call closes the socket as well
    return EXIT_FAILURE;
}

int cleanup_nl_sock(void) {
    if(!nlsock) return EXIT_FAILURE;
    nl_socket_free(nlsock);
    return EXIT_SUCCESS;
}

int add_enclave (uint32_t enclave, const uint8_t* app_hash, uint32_t host, const char* cat_name) {
    struct nl_msg* msg;
    int family_id;
    int err = 0;

    family_id = genl_ctrl_resolve(nlsock, GENL_SENG_FAMILY_NAME);
    if(family_id < 0){
        fprintf(stderr, "SENG: Unable to resolve family name!\n");
        return -1;
    }

    msg = nlmsg_alloc();
    if (!msg) {
        fprintf(stderr, "SENG: Failed to allocate netlink message\n");
        return -ENOMEM;
    }

    if(!genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, family_id, 0, NLM_F_REQUEST, GENL_XT_SENG_MSG, 0)) {
        fprintf(stderr, "SENG: Failed to put nl_hdr!\n");
        err = -ENOMEM;
        goto out;
    }

    err = nla_put_u32(msg, XT_SENG_ATTR_HOST, host);
    if (err) {
        fprintf(stderr, "SENG: Failed to put host!\n");
        goto out;
    }

    err = nla_put(msg, XT_SENG_ATTR_APP, SGX_HASH_SIZE, app_hash);
    if (err) {
        fprintf(stderr, "SENG: Failed to put app name!\n");
        goto out;
    }

    if (cat_name) {
        err = nla_put_string(msg, XT_SENG_ATTR_CAT, cat_name);
        if (err) {
            fprintf(stderr, "SENG: Failed to put cat name!\n");
            goto out;
        }
    }

    err = nla_put_flag(msg, XT_SENG_ATTR_ADD);
    if (err) {
        fprintf(stderr, "SENG: Failed to set add flag!\n");
        goto out;
    }

    //enclave stuff
    err = nla_put_u32(msg, XT_SENG_ATTR_ENC, enclave);
    if (err) {
        fprintf(stderr, "SENG: Failed to put enclave!\n");
        goto out;
    }

    err = nl_send_sync(nlsock, msg);
    if (err < 0) fprintf(stderr, "SENG: Failed to send nl message!\n");

    return err;

    out:
        nlmsg_free(msg);
        return err;
}

int add_enclave_ack (uint32_t enclave, const uint8_t* app_hash, uint32_t host, const char* cat_name) {
    int ret;
    int i = 0;

    repeat_msg:

        if (i > 4) {
            printf("SENG: failed sending message %i times - aborting...\n", i);
            return -1;
        }

        //send message
        ret = add_enclave (enclave, app_hash, host, cat_name);

        if (ret < 0) {
            printf("SENG: Did not send message! - %i\n", i);
            i += 1;
            goto repeat_msg;
        }

    return 0;
}

int cat_to_app (const uint8_t* app_hash, const char* cat_name) {
    struct nl_msg* msg;
    int family_id;
    int err = 0;

    family_id = genl_ctrl_resolve(nlsock, GENL_SENG_FAMILY_NAME);
    if(family_id < 0){
        fprintf(stderr, "SENG: Unable to resolve family name!\n");
        return -1;
    }

    msg = nlmsg_alloc();
    if (!msg) {
        fprintf(stderr, "SENG: Failed to allocate netlink message\n");
        return -ENOMEM;
    }

    if(!genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, family_id, 0, NLM_F_REQUEST, GENL_XT_SENG_MSG, 0)) {
        fprintf(stderr, "SENG: Failed to put nl_hdr!\n");
        err = -ENOMEM;
        goto out;
    }

    err = nla_put(msg, XT_SENG_ATTR_APP, SGX_HASH_SIZE, app_hash);
    if (err) {
        fprintf(stderr, "SENG: Failed to put app name!\n");
        goto out;
    }

    if (cat_name) {
        err = nla_put_string(msg, XT_SENG_ATTR_CAT, cat_name);
        if (err) {
            fprintf(stderr, "SENG: Failed to put cat name!\n");
            goto out;
        }
    }

    err = nla_put_flag(msg, XT_SENG_ATTR_ADD);
    if (err) {
        fprintf(stderr, "SENG: Failed to set operation flag!\n");
        goto out;
    }

    err = nl_send_sync(nlsock, msg);
    if (err < 0) fprintf(stderr, "SENG: Failed to send nl message!\n");

    return err;

    out:
        nlmsg_free(msg);
        return err;
}

int remove_cat_from_app (const uint8_t* app_hash, const char* cat_name) {
    struct nl_msg* msg;
    int family_id;
    int err = 0;

    family_id = genl_ctrl_resolve(nlsock, GENL_SENG_FAMILY_NAME);
    if(family_id < 0){
        fprintf(stderr, "SENG: Unable to resolve family name!\n");
        return -1;
    }

    msg = nlmsg_alloc();
    if (!msg) {
        fprintf(stderr, "SENG: Failed to allocate netlink message\n");
        return -ENOMEM;
    }

    if(!genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, family_id, 0, NLM_F_REQUEST, GENL_XT_SENG_MSG, 0)) {
        fprintf(stderr, "SENG: Failed to put nl_hdr!\n");
        err = -ENOMEM;
        goto out;
    }

    err = nla_put(msg, XT_SENG_ATTR_APP, SGX_HASH_SIZE, app_hash);
    if (err) {
        fprintf(stderr, "SENG: Failed to put app name!\n");
        goto out;
    }

    if (cat_name) {
        err = nla_put_string(msg, XT_SENG_ATTR_CAT, cat_name);
        if (err) {
            fprintf(stderr, "SENG: Failed to put cat name!\n");
            goto out;
        }
    }

    err = nla_put_flag(msg, XT_SENG_ATTR_RMV);
    if (err) {
        fprintf(stderr, "SENG: Failed to set operation flag!\n");
        goto out;
    }

    err = nl_send_sync(nlsock, msg);
    if (err < 0) fprintf(stderr, "SENG: Failed to send nl message!\n");

    return err;

    out:
    nlmsg_free(msg);
    return err;
}

int cat_to_app_ack (const uint8_t* app_hash, const char* cat_name) {
    int ret;
    int i = 0;

    repeat_msg:

    if (i > 4) {
        printf("SENG: failed sending message %i times - aborting...\n", i);
        return -1;
    }

    //send message
    ret = cat_to_app (app_hash, cat_name);

    if (ret < 0) {
        printf("SENG: Did not send message! - %i\n", i);
        i += 1;
        goto repeat_msg;
    }

    return 0;
}

int remove_cat_from_app_ack (const uint8_t* app_hash, const char* cat_name) {
    int ret;
    int i = 0;

    repeat_msg:

    if (i > 4) {
        printf("SENG: failed sending message %i times - aborting...\n", i);
        return -1;
    }

    //send message
    ret = remove_cat_from_app (app_hash, cat_name);

    if (ret < 0) {
        printf("SENG: Did not send message! - %i\n", i);
        i += 1;
        goto repeat_msg;
    }

    return 0;
}

int remove_enclave (uint32_t enclave) {
    struct nl_msg* msg;
    int family_id;
    int err = 0;

    family_id = genl_ctrl_resolve(nlsock, GENL_SENG_FAMILY_NAME);
    if(family_id < 0){
        fprintf(stderr, "SENG: Unable to resolve family name!\n");
        return -1;
    }

    msg = nlmsg_alloc();
    if (!msg) {
        fprintf(stderr, "SENG: Failed to allocate netlink message\n");
        return -ENOMEM;
    }

    if(!genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, family_id, 0, NLM_F_REQUEST, GENL_XT_SENG_MSG, 0)) {
        fprintf(stderr, "SENG: Failed to put nl_hdr!\n");
        err = -ENOMEM;
        goto out;
    }

    err = nla_put_u32(msg, XT_SENG_ATTR_ENC, enclave);
    if (err) {
        fprintf(stderr, "SENG: Failed to put enclave!\n");
        goto out;
    }

    err = nla_put_flag(msg, XT_SENG_ATTR_RMV);
    if (err) {
        fprintf(stderr, "SENG: Failed to set operation flag!\n");
        goto out;
    }

    err = nl_send_sync(nlsock, msg);
    if (err < 0) fprintf(stderr, "SENG: Failed to send nl message!\n");

    return err;

    out:
        nlmsg_free(msg);
        return err;
}

int remove_enclave_ack (uint32_t enclave) {
    int ret;
    int i = 0;

    repeat_msg:

    if (i > 4) {
        printf("SENG: failed sending message %i times - aborting...\n", i);
        return -1;
    }

    //send message
    ret = remove_enclave (enclave);

    if (ret < 0) {
        printf("SENG: Did not send message! - %i\n", i);
        i += 1;
        goto repeat_msg;
    }

    ret = delete_conntrack_entries(enclave);

    if (ret == -1) {
        printf("SENG: failed deleting conntrack entries associated with %d\n", enclave);
    } else {
        printf("SENG: deleted %d conntrack entries\n", ret);
    }

    return 0;
}

/// Simply sends a signal to the kernel module.
/**
* @param[in] signal   The signal to be sent.
* \return EXIT_SUCCESS or error codes
*/
int send_signal (int signal) {
    struct nl_msg *msg;
    int family_id;
    int err = 0;

    family_id = genl_ctrl_resolve(nlsock, GENL_SENG_FAMILY_NAME);
    if (family_id < 0) {
        fprintf(stderr, "SENG: Unable to resolve family name in send_signal! - %i\n", signal);
        return EXIT_FAILURE;
    }

    msg = nlmsg_alloc();
    if (!msg) {
        fprintf(stderr, "SENG: Failed to allocate netlink message\n");
        return -ENOMEM;
    }

    if (!genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, family_id, 0, NLM_F_REQUEST, GENL_XT_SENG_MSG, 0)) {
        fprintf(stderr, "SENG: Failed to put nl_hdr!\n");
        err = -ENOMEM;
        goto out;
    }

    err = nla_put_flag(msg, signal);
    if (err) {
        fprintf(stderr, "SENG: Failed to set signal flag!\n");
        goto out;
    }

    err = nl_send_sync(nlsock, msg);
    if (err < 0) fprintf(stderr, "SENG: Failed to send nl message!\n");

    return err;

    out:
        nlmsg_free(msg);
        return err;
}

int send_signal_ack (int signal) {
    int ret;
    int i = 0;

    repeat_signal:

        if (i > 4) {
            printf("SENG: failed sending signal %i times - aborting...\n", i);
            return EXIT_FAILURE;
        }

        ret = send_signal(signal);

        if (ret < 0) {
            printf("SENG: Did not send signal! - %i\n", i);
            i += 1;
            goto repeat_signal;
        }

    return EXIT_SUCCESS;
}

int flush_module(void) {

    int ret = 0;

    ret = send_signal_ack(XT_SENG_ATTR_FLUSH);

    if (ret == EXIT_SUCCESS) {
        printf("SENG: module flushed successfully!\n");
        return EXIT_SUCCESS;
    } else {
        printf("SENG: Error sending flush signal!\n");
        return EXIT_FAILURE;
    }
}
