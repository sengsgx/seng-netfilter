#ifndef SENG_NETFILTER_API_H
#define SENG_NETFILTER_API_H

#include <xt_seng_genl.h>
#include <stdint.h>

/**
 * @brief Prepares the netlink socket.
 *
 * Prepares the netlink socket nlsock and sets the callback functions cb to process_msg() and seq_check().
 * 
 * @return EXIT_SUCCESS or error codes
*/
int prep_nl_sock (void);

/**
 * @brief Cleanup the netlink socket.
 *
 * Cleans the netlink socket nlsock and its callback functions up.
 * 
 * @return EXIT_SUCCESS or error codes
*/
int cleanup_nl_sock (void);

/**
 * @brief  Sends the flush signal to the kernel module.
 *
 * Calling this method first attempts to send the unready signal to the kernel module.
 * Right after, the flush signal is attempted to be sent.
 *
 * @return EXIT_SUCCESS or EXIT_FAILURE
*/
int flush_module (void);

/**
 * @brief tries to add an enclave in the kernel module
 *
 * Will send the message up to 4 times, until it was successful.
 *
 * @param[in] enclave_ip    The enclave to be added.
 * @param[in] app_hash      The app hash associated with the enclave.
 * @param[in] host          The host ip associated with the enclave.
 * @param[in] cat_name      A category associated with the app. (optional)
 *
 * @return EXIT_SUCCESS or error codes
 * */
int add_enclave_ack (uint32_t enclave_ip, const uint8_t* app_hash, uint32_t host, const char* cat_name);

/**
 * @brief tries to add a category in the given app
 *
 * Will send the message up to 4 times, until it was successful.
 *
 * @param[in] app_hash        The app hash to be added to.
 * @param[in] cat_name        The category to be added.
 *
 * @return EXIT_SUCCESS or error codes
*/
int cat_to_app_ack (const uint8_t* app_hash, const char* cat_name);

/**
 * @brief tries to remove a category in the given app
 *
 * Will send the message up to 4 times, until it was successful.
 *
 * @param[in] app_hash        The app hash to be removed from.
 * @param[in] cat_name        The category to be removed.
 *
 * @return EXIT_SUCCESS or error codes
*/
int remove_cat_from_app_ack (const uint8_t* app_hash, const char* cat_name);

/**
 * @brief removes an enclave
 *
 * Will send the message up to 4 times, until it was successful.
 *
 * @param[in] enclave_ip     The enclave to be removed.
 *
 * @return EXIT_SUCCESS or error codes
 * */
int remove_enclave_ack (uint32_t enclave_ip);

#endif
