#ifndef SENG_NETFILTER_H
#define SENG_NETFILTER_H

#include "seng_netfilter_api.h"

#include <netlink/netlink.h> //nl_msg for callback
#include <xt_seng_genl.h>


/**
 * @brief netlink socket global variable
 *
 * Used to store the current netlink socket, used for communicating via netlink.
 * Will be initialized by prep_nl_sock()
 * */
extern struct nl_sock* nlsock;

/**
 * @brief Sends a signal to the kernel module with retrial mechanism.
 *
 * Will send the signal up to 4 times, until it was successful.
 *
 * @param[in] signal   The signal to be sent.
 *
 * @return EXIT_SUCCESS or error codes
*/
int send_signal_ack (int signal);

/**
 * @brief Deletes all conntrack entries associated with the given enclave.
 *
 * Dumps all conntrack entries and deletes those matching the source or destination ipv4.
 *
 * @param[in] pEnclave_ip   The enclave, whose entries are to be deleted. (network byte order)
 *
 * @return amount of deleted entries or -1 on error
*/
int delete_conntrack_entries (uint32_t pEnclave_ip);

#endif
